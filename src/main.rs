#![allow(unused)]
mod tcp;

use anyhow::{Result, bail};
use etherparse::icmpv4::DestUnreachableHeader::Protocol;
use etherparse::ip_number::TCP;
use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::Ipv4Addr;
use tcp::Connection;
use tun_rs::DeviceBuilder;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut connections: HashMap<Quad, Connection> = Default::default();
    let dev = DeviceBuilder::new()
        .name("utun7")
        .ipv4("192.68.0.1", 24, None)
        .build_async()
        .unwrap();
    let mut buf = [0; 65535];
    loop {
        let len = dev.recv(&mut buf).await.unwrap();
        match Ipv4HeaderSlice::from_slice(&buf[..len]) {
            Ok(iph) => {
                if iph.protocol() != TCP {
                    continue;
                }
                match TcpHeaderSlice::from_slice(&buf[iph.slice().len()..]) {
                    Ok(tcph) => {
                        let datai = iph.slice().len() + tcph.slice().len();
                        match connections.entry(Quad {
                            src: (iph.source_addr(), tcph.source_port()),
                            dst: (iph.destination_addr(), tcph.destination_port()),
                        }) {
                            Entry::Occupied(mut entry) => {
                                entry
                                    .get_mut()
                                    .on_packet(&dev, iph, tcph, &buf[datai..len])
                                    .await?;
                            }
                            Entry::Vacant(entry) => {
                                if let Some(conn) =
                                    Connection::accept(&dev, iph, tcph, &buf[datai..len]).await?
                                {
                                    entry.insert(conn);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        bail!("Error parsing tcp header {e}");
                    }
                }
            }
            Err(e) => {
                bail!("Error parsing ipv4 header {e}");
            }
        }
    }
}
