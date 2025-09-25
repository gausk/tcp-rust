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

#[derive(Debug, Clone)]
pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
}

#[derive(Debug, Clone)]
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
    pub async fn accept<'a>(
        nic: &AsyncDevice,
        iph: Ipv4HeaderSlice<'a>,
        tcph: TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> Result<Option<Self>> {
        if !tcph.syn() {
            return Ok(None);
        }
        let send_iss = rng().random();
        println!("sending iss {}", send_iss);
        let conn = Self {
            state: State::SynRcvd,
            recv: RecvSequenceSpace {
                irs: tcph.sequence_number(),
                wnd: tcph.window_size(),
                nxt: tcph.sequence_number().wrapping_add(1),
                up: false,
            },
            send: SendSequenceSpace {
                una: send_iss,
                nxt: send_iss.wrapping_add(1),
                iss: send_iss,
                wnd: TCP_WINDOW_LEN,
                up: false,
                wl1: 0,
                wl2: 0,
            },
        };
        let mut syn_ack = TcpHeader::new(
            tcph.destination_port(),
            tcph.source_port(),
            conn.send.iss,
            TCP_WINDOW_LEN,
        );
        syn_ack.ack = true;
        syn_ack.syn = true;
        syn_ack.acknowledgment_number = conn.recv.nxt;

        let diph = Ipv4Header::new(
            syn_ack.header_len() as u16,
            TTL,
            IpNumber::TCP,
            iph.destination(),
            iph.source(),
        )?;

        nic.send(&[diph.to_bytes(), syn_ack.to_bytes()].concat())
            .await?;
        Ok(Some(conn))
    }

    pub fn on_packet<'a>(
        &mut self,
        nic: &AsyncDevice,
        iph: Ipv4HeaderSlice<'a>,
        tcph: TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> Result<()> {
        println!("Existing Connection received!");
        Ok(())
    }
}
