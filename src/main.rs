use tokio::net::TcpListener;
use tracing::{debug, info};
use tracing_subscriber::filter::LevelFilter;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

async fn setup_listener() -> Result<()> {
    let listener = TcpListener::bind("0.0.0.0:7007").await?;

    loop {
        match listener.accept().await {
            Ok((socket, addr)) => {
                tokio::spawn(handle_client(socket, addr));
            }
            Err(e) => info!("Couldn't get client: {:?}", e),
        }
    }
}

async fn handle_client(socket: tokio::net::TcpStream, addr: std::net::SocketAddr) -> Result<()> {
    // Handle the client here
    info!("New connection from: {:?}", addr);

    loop {
        // Wait for the socket to be readable
        socket.readable().await?;
        let mut buf = [0; 4096];

        match socket.try_read(&mut buf) {
            Ok(0) => break,
            Ok(bytes_read) => {
                let request = String::from_utf8_lossy(&buf[0..bytes_read]);
                info!("Request: {:?}", request);
                debug!("read {} bytes", bytes_read);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::DEBUG)
        .init();

    setup_listener().await?;

    Ok(())
}
