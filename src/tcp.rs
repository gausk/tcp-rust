use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use rand::{Rng, rng};
use std::collections::VecDeque;
use std::io::{ErrorKind, Result};
use std::task::Waker;
use tun_rs::AsyncDevice;

pub const TCP_WINDOW_LEN: u16 = 1500;
pub const TTL: u8 = 64;

/// State of Send Sequence Space (RFC 793 S3.2 F4)
/// ```text
///     1         2          3          4
///     ----------|----------|----------|----------
///     SND.UNA    SND.NXT    SND.UNA
///                          +SND.WND
///
///  1 - old sequence numbers which have been acknowledged
///  2 - sequence numbers of unacknowledged data
///  3 - sequence numbers allowed for new data transmission
///  4 - future sequence numbers which are not yet allowed
/// ```
#[derive(Debug, Clone, Default)]
pub struct SendSequenceSpace {
    /// send unacknowledged
    una: u32,
    /// send next
    nxt: u32,
    /// send window
    wnd: u16,
    /// send urgent pointer
    up: bool,
    /// segment sequence number used for last window update
    wl1: u32,
    /// segment acknowledgment number used for last window update
    wl2: u32,
    /// initial send sequence number
    iss: u32,
}

impl SendSequenceSpace {
    /// `SND.UNA < SEG.ACK =< SND.NXT`
    fn is_ack_in_between(&self, ack_no: u32) -> bool {
        let max_diff = self.nxt.wrapping_sub(self.una);
        let current_diff = ack_no.wrapping_sub(self.una);
        //current_diff != 0 && current_diff <= max_diff
        // From testing I have found that ACK already acknowledged is
        // send again with data, hence removed current_diff != 0 check
        current_diff <= max_diff
    }
}

/// State of Receive Sequence Space (RFC 793 S3.2 F5)
/// ```text
///    1          2          3
///    ----------|----------|----------
///    RCV.NXT    RCV.NXT
///               +RCV.WND
///
///    1 - old sequence numbers which have been acknowledged
///    2 - sequence numbers allowed for new reception
///    3 - future sequence numbers which are not yet allowed
///```
#[derive(Debug, Clone, Default)]
pub struct RecvSequenceSpace {
    /// receive next
    nxt: u32,
    /// receive window
    wnd: u16,
    /// receive urgent pointer
    up: bool,
    /// initial receive sequence number
    irs: u32,
}

impl RecvSequenceSpace {
    /// start or end bytes of the segment is within range
    /// ```text
    /// RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
    ///              OR
    /// RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
    /// ```
    /// In case window is zero, ack is only allowed
    fn is_seq_in_between(&self, seq_no: u32, seq_len: usize) -> bool {
        let wnd = self.wnd as u32;

        if wnd == 0 {
            // Special case: window is zero
            return seq_len == 0 && seq_no == self.nxt;
        }

        let start_diff = seq_no.wrapping_sub(self.nxt);
        let end_diff = seq_no
            .wrapping_add(seq_len as u32)
            .wrapping_sub(1)
            .wrapping_sub(self.nxt);

        start_diff < wnd || end_diff < wnd
    }
}

#[derive(Debug, Clone)]
pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: Ipv4Header,
    tcp: TcpHeader,
    pub(crate) incoming: VecDeque<u8>,
    pub(crate) unacked: VecDeque<u8>,
    pub(crate) read_waker: Option<Waker>,
    pub(crate) write_waker: Option<Waker>,
}

impl Connection {
    pub(crate) fn is_recv_closed(&self) -> bool {
        self.state == State::TimeWait
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum State {
    Closed,
    Listen,
    SynRcvd,
    Estab,
    FinWait1,
    FinWait2,
    TimeWait,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match self {
            State::Estab | State::FinWait1 | State::FinWait2 | State::TimeWait => true,
            State::SynRcvd | State::Closed | State::Listen => false,
        }
    }
}

impl Connection {
    pub async fn accept<'a>(
        nic: &AsyncDevice,
        iph: Ipv4HeaderSlice<'a>,
        tcph: TcpHeaderSlice<'a>,
        _data: &'a [u8],
    ) -> Result<Option<Self>> {
        if !tcph.syn() {
            return Ok(None);
        }
        let send_iss = rng().random();
        let mut conn = Self {
            state: State::SynRcvd,
            recv: RecvSequenceSpace {
                irs: tcph.sequence_number(),
                wnd: tcph.window_size(),
                nxt: tcph.sequence_number().wrapping_add(1),
                up: false,
            },
            send: SendSequenceSpace {
                una: send_iss,
                nxt: send_iss,
                iss: send_iss,
                wnd: tcph.window_size(),
                up: false,
                wl1: 0,
                wl2: 0,
            },
            ip: Ipv4Header::new(0, TTL, IpNumber::TCP, iph.destination(), iph.source()).unwrap(),
            tcp: TcpHeader::new(
                tcph.destination_port(),
                tcph.source_port(),
                send_iss,
                TCP_WINDOW_LEN,
            ),
            incoming: VecDeque::new(),
            unacked: VecDeque::new(),
            read_waker: None,
            write_waker: None,
        };

        conn.tcp.ack = true;
        conn.tcp.syn = true;
        conn.write(nic, send_iss, &[]).await?;
        conn.tcp.ack = false;
        conn.tcp.syn = false;
        Ok(Some(conn))
    }

    pub async fn on_packet<'a>(
        &mut self,
        nic: &AsyncDevice,
        _iph: Ipv4HeaderSlice<'a>,
        tcph: TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> Result<()> {
        //// 1. Check Sequence number
        let seq_no = tcph.sequence_number();
        let slen = data.len() + tcph.syn() as usize + tcph.fin() as usize;
        if !self.recv.is_seq_in_between(seq_no, slen) {
            // If an incoming segment is not acceptable, an acknowledgment
            // should be sent in reply (unless the RST bit is set, if so drop
            // the segment and return):
            //
            // `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`
            if !tcph.rst() {
                self.tcp.ack = true;
                // passing seq number here and ack get set in write function
                self.write(nic, self.send.nxt, &[]).await?;
                self.tcp.ack = false;
                return Ok(());
            }
        }
        self.recv.nxt = seq_no.wrapping_add(slen as u32);

        //// 2. Check reset bit is set
        // If SYN-RECEIVED STATE, move state to Listen
        // else if state is ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2 or
        // CLOSE-WAIT, close the connection.
        if tcph.rst() {
            self.state = State::Closed;
            // TODO: maybe send reset in some case only
            self.send_reset(nic).await?;
            return Ok(());
        }

        //// 3. Ignore security checks
        //// 4. Check the SYN bit.
        if tcph.syn() {
            self.send_reset(nic).await?;
            self.state = State::Closed;
            return Ok(());
        }

        //// 5. Check the ack bit
        if tcph.ack() {
            let ack_no = tcph.acknowledgment_number();
            if !self.send.is_ack_in_between(ack_no) {
                // If the connection is in a synchronized state (ESTABLISHED,
                // FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT),
                // any unacceptable segment (out of window sequence number or
                // unacceptable acknowledgment number) must elicit only an empty
                // acknowledgment segment containing the current send-sequence number
                // and an acknowledgment indicating the next sequence number expected
                // to be received, and the connection remains in the same state.

                // So we don't send RST in synchronized state instead just ACK.

                // If the connection is in any non-synchronized state (LISTEN,
                // SYN-SENT, SYN-RECEIVED), If the incoming segment has an ACK field,
                // the reset takes its sequence number from the ACK field of the segment,
                // otherwise the reset has sequence number zero and the ACK field is set to the sum
                // of the sequence number and segment length of the incoming segment.
                // The connection remains in the same state.
                if !self.state.is_synchronized() {
                    // <SEQ=SEG.ACK><CTL=RST>
                    // TODO: we should send ack number in sequence number here
                    self.send_reset(nic).await?
                } else {
                    // TODO: send ack here.
                }
                return Ok(());
            }
            self.send.una = ack_no;
        }
        //// 6. Check the urg bit
        if tcph.urg() {
            // TODO: Handle it correctly.
            // State: ESTABLISHED, FIN-WAIT-1 and FIN-WAIT-2
            // If the URG bit is set, RCV.UP <- max(RCV.UP,SEG.UP), and signal
            // the user that the remote side has urgent data if the urgent
            // pointer (RCV.UP) is in advance of the data consumed.  If the
            // user has already been signaled (or is still in the "urgent
            // mode") for this continuous sequence of urgent data, do not
            // signal the user again.
            // For other state ignore.
        }
        //// 7. Process the segment bit.
        //// 8. Check the fin bit.
        match self.state {
            State::SynRcvd => {
                if tcph.ack() && tcph.acknowledgment_number() == self.send.iss.wrapping_add(1) {
                    self.state = State::Estab;
                } else {
                    return Err(ErrorKind::InvalidInput.into());
                }
            }
            State::Estab => {
                // For now let's terminate the connection!
                self.tcp.fin = true;
                self.tcp.ack = true;
                self.write(nic, self.send.nxt, &[]).await?;
                self.state = State::FinWait1;
                self.tcp.fin = false;
                self.tcp.ack = true;
            }
            State::Closed | State::Listen | State::TimeWait => {
                println!("unexpected state {:?}", self.state);
            }
            State::FinWait1 => {
                if tcph.ack() {
                    self.state = State::FinWait2;
                }
            }
            State::FinWait2 => {
                if tcph.fin() {
                    self.tcp.ack = true;
                    self.write(nic, self.send.nxt, &[]).await?;
                    self.tcp.ack = false;
                    self.state = State::TimeWait;
                    if let Some(waker) = self.read_waker.take() {
                        waker.wake();
                    }
                }
            }
        }
        Ok(())
    }

    async fn send_reset(&mut self, nic: &AsyncDevice) -> Result<()> {
        self.tcp.rst = true;
        self.write(nic, 0, &[]).await?;
        self.tcp.rst = false;
        Ok(())
    }

    async fn write(&mut self, nic: &AsyncDevice, seq_no: u32, data: &[u8]) -> Result<()> {
        self.ip
            .set_payload_len(self.tcp.header_len() + data.len())
            .unwrap();
        self.ip.header_checksum = self.ip.calc_header_checksum();

        self.tcp.sequence_number = seq_no;
        self.tcp.acknowledgment_number = self.recv.nxt;
        self.tcp.checksum = self.tcp.calc_checksum_ipv4(&self.ip, data).unwrap();
        nic.send(&[&self.ip.to_bytes(), &self.tcp.to_bytes(), data].concat())
            .await?;
        self.send.nxt = seq_no.wrapping_add(segment_length(data, self.tcp.syn, self.tcp.fin));
        Ok(())
    }
}

fn segment_length(data: &[u8], is_syn: bool, is_fin: bool) -> u32 {
    // SEG.LEN = the number of octets occupied by the data in the segment (counting SYN and FIN)
    data.len() as u32 + is_syn as u32 + is_fin as u32
}
