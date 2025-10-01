#![allow(unused)]
pub mod tcp;

use crate::tcp::Connection;
use etherparse::ip_number::TCP;
use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::io::{Error, ErrorKind, Result};
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tun_rs::{AsyncDevice, DeviceBuilder};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

impl Quad {
    pub fn new(src: (Ipv4Addr, u16), dst: (Ipv4Addr, u16)) -> Self {
        Self { src, dst }
    }
}

#[derive(Default)]
pub struct ConnectionManager {
    connections: HashMap<Quad, Connection>,
    pending: HashMap<u16, VecDeque<Quad>>,
}

type CmInterface = Arc<Mutex<ConnectionManager>>;
pub struct Interface {
    cmh: CmInterface,
    jh: JoinHandle<()>,
}

impl Interface {
    pub async fn new() -> Result<Self> {
        let dev = DeviceBuilder::new()
            .name("utun7")
            .ipv4("192.68.0.1", 24, None)
            .build_async()?;
        let cmh: CmInterface = Arc::default();
        let jh = {
            let cmh = cmh.clone();
            tokio::task::spawn(async move {
                packet_loop(&dev, cmh).await;
            })
        };
        Ok(Interface { cmh, jh })
    }

    pub async fn bind(&mut self, port: u16) -> Result<TcpListener> {
        let mut cm = self.cmh.lock().await;
        match cm.pending.entry(port) {
            Entry::Vacant(v) => {
                v.insert(VecDeque::new());
            }
            Entry::Occupied(_) => {
                return Err(Error::new(ErrorKind::AddrInUse, "port already bound"));
            }
        }
        drop(cm);
        Ok(TcpListener {
            port,
            cmh: self.cmh.clone(),
        })
    }
}

/// A TCP socket server, listening for connections.
///
/// After creating a `TcpListener` by [`bind`]ing it to a socket address, it listens
/// for incoming TCP connections. These can be accepted by calling [`accept`] or by
/// iterating over the [`Incoming`] iterator returned by [`incoming`][`TcpListener::incoming`].
///
/// The socket will be closed when the value is dropped.
pub struct TcpListener {
    port: u16,
    cmh: CmInterface,
}

impl TcpListener {
    pub async fn accept(&self) -> Result<TcpStream> {
        let mut cmh = self.cmh.lock().await;
        if let Some(quad) = cmh
            .pending
            .get_mut(&self.port)
            .expect("port closed while listener still active")
            .pop_front()
        {
            Ok(TcpStream {
                cmh: self.cmh.clone(),
                quad,
            })
        } else {
            Err(Error::new(ErrorKind::WouldBlock, "no connection to accept"))
        }
    }
}

/// A TCP stream between a local and a remote socket.
///
/// After creating a `TcpStream` by either [`connect`]ing to a remote host or
/// [`accept`]ing a connection on a [`TcpListener`], data can be transmitted
/// by [reading] and [writing] to it.
///
/// The connection will be closed when the value is dropped. The reading and writing
/// portions of the connection can also be shut down individually with the [`shutdown`]
/// method.
pub struct TcpStream {
    quad: Quad,
    cmh: CmInterface,
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        let mut cmh = match self.cmh.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                // If the lock is held by another task, we register the current task
                // for wake-up and return Pending.
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };
        let conn = match cmh.connections.get_mut(&self.quad) {
            Some(conn) => conn,
            None => {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::ConnectionAborted,
                    "tcp stream aborted unexpectedly",
                )));
            }
        };

        if conn.incoming.is_empty() {
            conn.read_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        let rlen = buf.remaining().min(conn.incoming.len());
        let (front, back) = conn.incoming.as_slices();

        let mut copied = 0;
        if !front.is_empty() {
            let n = front.len().min(rlen);
            buf.put_slice(&front[..n]);
            copied += n;
        }

        if copied < rlen {
            let m = back.len().min(rlen - copied);
            buf.put_slice(&back[..m]);
            copied += m;
        }

        conn.incoming.drain(..copied);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        let mut cmh = match self.cmh.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                // If the lock is held by another task, we register the current task
                // for wake-up and return Pending.
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };
        let conn = match cmh.connections.get_mut(&self.quad) {
            Some(conn) => conn,
            None => {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::ConnectionAborted,
                    "tcp stream aborted unexpectedly",
                )));
            }
        };

        const SEND_QUEUE_SIZE: usize = 1024;
        if conn.unacked.len() >= SEND_QUEUE_SIZE {
            // If the queue is full, register the current task's waker
            conn.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        let wlen = buf.len().min(SEND_QUEUE_SIZE - conn.unacked.len());
        conn.unacked.extend(&buf[..wlen]);
        Poll::Ready(Ok(wlen))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let mut cmh = match self.cmh.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                // If the lock is held by another task, we register the current task
                // for wake-up and return Pending.
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };
        let conn = match cmh.connections.get_mut(&self.quad) {
            Some(conn) => conn,
            None => {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::ConnectionAborted,
                    "tcp stream aborted unexpectedly",
                )));
            }
        };
        if conn.unacked.is_empty() {
            Poll::Ready(Ok(()))
        } else {
            conn.write_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let mut cmh = match self.cmh.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                // If the lock is held by another task, we register the current task
                // for wake-up and return Pending.
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };
        let conn = match cmh.connections.get_mut(&self.quad) {
            Some(conn) => conn,
            None => {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::ConnectionAborted,
                    "tcp stream aborted unexpectedly",
                )));
            }
        };
        // TODO: Close connection
        // conn.close().await
        Poll::Ready(Ok(()))
    }
}

async fn packet_loop(dev: &AsyncDevice, cmh: CmInterface) -> Result<()> {
    let mut buf = [0; 1500];
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
                        let quad = Quad::new(
                            (iph.source_addr(), tcph.source_port()),
                            (iph.destination_addr(), tcph.destination_port()),
                        );
                        let mut cmg = cmh.lock().await;
                        let mut cm = &mut *cmg;
                        match cm.connections.entry(quad.clone()) {
                            Entry::Occupied(mut conn) => {
                                conn.get_mut()
                                    .on_packet(&dev, iph, tcph, &buf[datai..len])
                                    .await
                                    .unwrap();
                                drop(cmg);
                            }
                            Entry::Vacant(e) => {
                                if let Some(pending) = cm.pending.get_mut(&tcph.destination_port())
                                {
                                    println!(
                                        "listening on port {}, hence accepting connection",
                                        tcph.destination_port()
                                    );
                                    if let Some(conn) =
                                        Connection::accept(&dev, iph, tcph, &buf[datai..len])
                                            .await
                                            .unwrap()
                                    {
                                        e.insert(conn);
                                        pending.push_back(quad);
                                    }
                                }
                            }
                        }
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

/*
sync version implementation

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut cmh = self.cmh.lock().unwrap();
        let conn = cmh.connections.get_mut(&self.quad).ok_or_else(|| {
            Error::new(
                ErrorKind::ConnectionAborted,
                "tcp stream aborted unexpectedly",
            )
        })?;

        const SEND_QUEUE_SIZE: usize = 1024;
        if conn.unacked.len() >= SEND_QUEUE_SIZE {
            return Err(ErrorKind::WouldBlock.into());
        }

        let wlen = buf.len().min(SEND_QUEUE_SIZE - conn.unacked.len());
        conn.unacked.extend(&buf[..wlen]);
        Ok(wlen)
    }

    fn flush(&mut self) -> Result<()> {
        let mut cmh = self.cmh.lock().unwrap();
        let conn = cmh.connections.get_mut(&self.quad).ok_or_else(|| {
            Error::new(
                ErrorKind::ConnectionAborted,
                "tcp stream aborted unexpectedly",
            )
        })?;
        if conn.unacked.is_empty() {
            Ok(())
        } else {
            // TODO: block
            Err(Error::new(ErrorKind::WouldBlock, "too many bytes buffered"))
        }
    }
}

impl TcpStream {
    pub fn shutdown(&self, how: Shutdown) -> Result<()> {
        let mut cmh = self.cmh.lock().unwrap();
        let conn = cmh.connections.get_mut(&self.quad).ok_or_else(|| {
            Error::new(
                ErrorKind::ConnectionAborted,
                "tcp stream aborted unexpectedly",
            )
        })?;
        // TODO: Close Connection by sending FIN
        Ok(())
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut cmh = self.cmh.lock().unwrap();
        let conn = cmh.connections.get_mut(&self.quad).ok_or_else(|| {
            Error::new(
                ErrorKind::ConnectionAborted,
                "tcp stream aborted unexpectedly",
            )
        })?;

        if conn.incoming.is_empty() {
            return Err(ErrorKind::WouldBlock.into());
        }

        let rlen = buf.len().min(conn.incoming.len());
        let (front, back) = conn.incoming.as_slices();

        let mut copied = 0;
        if !front.is_empty() {
            let n = front.len().min(rlen);
            buf[..n].copy_from_slice(&front[..n]);
            copied += n;
        }

        if copied < rlen {
            let m = back.len().min(rlen - copied);
            buf[copied..copied + m].copy_from_slice(&back[..m]);
            copied += m;
        }

        conn.incoming.drain(..copied);
        Ok(copied)
    }
}

*/
