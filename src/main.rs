mod tcp;

use anyhow::Result;
use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};
use std::collections::HashMap;
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
        .ipv4("192.168.0.1", 24, None)
        .build_async()
        .unwrap();
    let mut buf = [0; 65535];
    loop {
        let len = dev.recv(&mut buf).await.unwrap();
        match Ipv4HeaderSlice::from_slice(&buf[..len]) {
            Ok(iph) => {
                if iph.protocol().0 != 6 {
                    continue;
                }
                match TcpHeaderSlice::from_slice(&buf[iph.slice().len()..]) {
                    Ok(tcph) => {
                        let datai = iph.slice().len() + tcph.slice().len();
                        connections
                            .entry(Quad {
                                src: (iph.source_addr(), tcph.source_port()),
                                dst: (iph.destination_addr(), tcph.destination_port()),
                            })
                            .or_default()
                            .on_packets(&dev, iph, tcph, &buf[datai..len])
                            .await?;
                    }
                    Err(e) => {
                        eprintln!("Error parsing tcp header {e}");
                    }
                }
            }
            Err(e) => {
                eprintln!("Error parsing ipv4 header {e}");
            }
        }
    }
}
