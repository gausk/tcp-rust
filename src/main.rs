use std::io::Result;
use tcp_rust::Interface;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

#[tokio::main]
async fn main() -> Result<()> {
    let mut inf = Interface::new().await?;
    println!("Interface created successfully!");
    let listener = inf.bind(443).await?;
    while let Ok(mut stream) = listener.accept().await {
        println!("Accepted a new connection!");
        tokio::spawn(async move {
            stream.write(b"Hi GK. Testing the tcp-rust").await.unwrap();
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
    Ok(())
}
