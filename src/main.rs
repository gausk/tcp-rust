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
    let mut listener = inf.bind(443).await?;
    println!("Listener bound on port 443");
    while let Ok(Ok(mut stream)) = timeout(Duration::from_secs(60), listener.accept()).await {
        println!("Accepted a new connection!");
        tokio::spawn(async move {
            stream
                .write_all(b"Hi GK. Testing the tcp-rust")
                .await
                .unwrap();
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
            stream.shutdown().await.unwrap();
        });
    }
    println!("Closing the connection!");
    listener.close().await?;
    println!("All connection closed");
    Ok(())
}
