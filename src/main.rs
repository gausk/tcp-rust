use std::io::Result;
use std::time::Duration;
use tcp_rust::Interface;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

#[tokio::main]
async fn main() -> Result<()> {
    let mut inf = Interface::new().await?;
    println!("Interface created successfully!");
    let mut listener = inf.bind(80).await?;
    println!("Listener bound on port 80");
    while let Ok(Ok(mut stream)) = timeout(Duration::from_secs(60), listener.accept()).await {
        println!("Accepted a new connection!");
        tokio::spawn(async move {
            stream.write_all(b"Hi GK!\n").await.unwrap();
            stream
                .write_all(b"We have built an amazing rust-tcp crate!\n")
                .await
                .unwrap();
            // shutdown write
            stream.shutdown().await.unwrap();
            loop {
                let mut buf = [0; 1024];
                let n = stream.read(&mut buf[..]).await.unwrap();
                if n == 0 {
                    println!("no more data!");
                    break;
                } else {
                    println!("Received data: {}", String::from_utf8_lossy(&buf[..n]));
                }
            }
        });
    }
    println!("Closing the connection!");
    listener.close().await?;
    println!("All connection closed");
    Ok(())
}
