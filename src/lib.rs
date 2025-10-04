#![allow(dead_code)]
mod tcp;
mod timer;

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
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;
use tokio::time::timeout;
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
pub struct ConnectionsInfo {
    connections: HashMap<Quad, Connection>,
    pending: HashMap<u16, VecDeque<Quad>>,
}

#[derive(Default)]
pub struct ConnectionManager {
    info: Mutex<ConnectionsInfo>,
    pending_var: Notify,
}

type CmInterface = Arc<ConnectionManager>;
pub struct Interface {
    cmh: CmInterface,
    jh: JoinHandle<()>,
}

impl Drop for Interface {
    fn drop(&mut self) {
        // TODO: make sure all listeners are closed
        self.jh.abort();
    }
}

impl Interface {
    pub async fn new() -> Result<Self> {
        let dev = DeviceBuilder::new()
            .name("utun7")
            .ipv4("192.168.0.1", 24, None)
            .build_async()?;
        let cmh: CmInterface = Arc::default();
        let jh = {
            let cmh = cmh.clone();
            tokio::task::spawn(async move {
                packet_loop(&dev, cmh).await.unwrap();
            })
        };
        Ok(Interface { cmh, jh })
    }

    pub async fn bind(&mut self, port: u16) -> Result<TcpListener> {
        let mut cm = self.cmh.info.lock().await;
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
/// After creating a `TcpListener` by binding it to a socket address, it listens
/// for incoming TCP connections. These can be accepted by calling accept.
pub struct TcpListener {
    port: u16,
    cmh: CmInterface,
}

impl TcpListener {
    pub async fn accept(&self) -> Result<TcpStream> {
        loop {
            let mut cmh = self.cmh.info.lock().await;
            if let Some(quad) = cmh
                .pending
                .get_mut(&self.port)
                .expect("port closed while listener still active")
                .pop_front()
            {
                return Ok(TcpStream {
                    cmh: self.cmh.clone(),
                    quad,
                });
            }
            let notified = self.cmh.pending_var.notified();
            drop(cmh);
            notified.await;
        }
    }

    pub async fn close(&mut self) -> Result<()> {
        let mut cm = self.cmh.info.lock().await;
        let pending = cm
            .pending
            .remove(&self.port)
            .expect("port closed while listener still active");
        for quad in pending {
            // TODO: send Fin and terminate connection
            cm.connections.remove(&quad);
        }
        Ok(())
    }
}

/// A TCP stream between a local and a remote socket.
///
/// After creating a `TcpStream` by accepting a connection on a TcpListener,
/// data can be transmitted by reading and writing to it.
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
        let mut cmh = match self.cmh.info.try_lock() {
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

        if conn.is_recv_closed() && conn.incoming.is_empty() {
            return Poll::Ready(Ok(()));
        }

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
        let mut cmh = match self.cmh.info.try_lock() {
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
        let mut cmh = match self.cmh.info.try_lock() {
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
        let mut cmh = match self.cmh.info.try_lock() {
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
        // TODO: _eventually_ remove self.quad from cm.info.connections
        Poll::Ready(conn.close())
    }
}

async fn packet_loop(dev: &AsyncDevice, cmh: CmInterface) -> Result<()> {
    let mut buf = [0; 1500];
    loop {
        let len = match timeout(Duration::from_secs(2), dev.recv(&mut buf)).await {
            Ok(Ok(len)) => len,
            Ok(Err(e)) => return Err(e),
            Err(_) => 0,
        };
        if len == 0 {
            let mut cmg = cmh.info.lock().await;
            for conn in cmg.connections.values_mut() {
                // XXX: Better handling of error?
                conn.on_tick(dev).await?;
            }
            continue;
        }
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
                        let mut cmg = cmh.info.lock().await;
                        let cm = &mut *cmg;
                        match cm.connections.entry(quad.clone()) {
                            Entry::Occupied(mut conn) => {
                                conn.get_mut()
                                    .on_packet(dev, tcph, &buf[datai..len])
                                    .await?;
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
                                        Connection::accept(dev, iph, tcph, &buf[datai..len]).await?
                                    {
                                        e.insert(conn);
                                        pending.push_back(quad);
                                        drop(cmg);
                                        cmh.pending_var.notify_waiters();
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
        let conn = cmh.info.connections.get_mut(&self.quad).ok_or_else(|| {
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
        let conn = cmh.info.connections.get_mut(&self.quad).ok_or_else(|| {
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
        let conn = cmh.info.connections.get_mut(&self.quad).ok_or_else(|| {
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
        let conn = cmh.info.connections.get_mut(&self.quad).ok_or_else(|| {
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
