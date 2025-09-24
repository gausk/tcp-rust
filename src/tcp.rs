use anyhow::Result;
use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use rand::{Rng, rng};
use tun_rs::AsyncDevice;

pub const TCP_WINDOW_LEN: u16 = 1500;
pub const TTL: u8 = 64;

/// State of Send Sequence Space (RFC 793 S3.2 F4)
/// ```
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

/// State of Receive Sequence Space (RFC 793 S3.2 F5)
/// ```
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

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
}

pub enum State {
    Closed,
    Listen,
    SynRcvd,
    Estab,
}

impl Default for Connection {
    fn default() -> Self {
        Self {
            state: State::Listen,
            send: SendSequenceSpace::default(),
            recv: RecvSequenceSpace::default(),
        }
    }
}
impl Connection {
    pub async fn on_packets<'a>(
        &mut self,
        nic: &AsyncDevice,
        iph: Ipv4HeaderSlice<'a>,
        tcph: TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> Result<()> {
        match self.state {
            State::Closed => {}
            State::Listen => {
                if tcph.syn() {
                    // keep track of sender info
                    self.recv.irs = tcph.sequence_number();
                    self.recv.wnd = tcph.window_size();
                    self.recv.nxt = tcph.sequence_number().wrapping_add(1);
                    self.state = State::SynRcvd;

                    // stuff we are sending them
                    self.send.iss = rng().random();
                    self.send.nxt = self.send.iss.wrapping_add(1);
                    self.send.una = self.send.iss;
                    self.send.wnd = TCP_WINDOW_LEN;

                    let mut syn_ack = TcpHeader::new(
                        tcph.destination_port(),
                        tcph.source_port(),
                        self.send.iss,
                        TCP_WINDOW_LEN,
                    );
                    syn_ack.ack = true;
                    syn_ack.ack = true;
                    syn_ack.acknowledgment_number = self.recv.nxt;

                    let diph = Ipv4Header::new(
                        syn_ack.header_len() as u16,
                        TTL,
                        IpNumber::TCP,
                        iph.destination(),
                        iph.source(),
                    )?;

                    nic.send(&[diph.to_bytes(), syn_ack.to_bytes()].concat())
                        .await?;
                }
            }
            State::SynRcvd => {}
            State::Estab => {}
        }
        println!(
            "{}:{} -> {}:{} {}b of tcp data",
            iph.source_addr(),
            tcph.source_port(),
            iph.destination_addr(),
            tcph.destination_port(),
            data.len()
        );
        Ok(())
    }
}
