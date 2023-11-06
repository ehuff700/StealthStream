use std::{
	net::{SocketAddr, ToSocketAddrs},
	sync::{
		atomic::{AtomicBool, Ordering},
		Arc,
	},
};

use tokio::{net::TcpStream, signal};
use tracing::error;

use crate::{errors::ClientErrors, StealthStreamResult};

use super::{stream::StealthStream, StealthStreamMessage};

pub type ClientResult<T> = std::result::Result<T, ClientErrors>;

#[derive(Debug, Clone)]
pub struct Client {
	raw_socket: StealthStream,
	connection_state: Arc<AtomicBool>,
	address: SocketAddr,
}

impl Client {
	/// Connects to a stealth stream server at the given address
	pub async fn connect<A>(addr: A) -> ClientResult<Self>
	where
		A: ToSocketAddrs,
	{
		let address = addr.to_socket_addrs()?.next().unwrap(); // TODO: fix this
		let raw_socket = StealthStream::from_tcp_stream(TcpStream::connect(address).await?); // TODO: Make Error Type
		let connection_state = Arc::new(AtomicBool::new(true));

		let client = Self {
			raw_socket,
			connection_state,
			address,
		};

		tokio::task::spawn({
			let cloned = client.clone();
			async move {
				signal::ctrl_c().await.unwrap();
				if let Err(e) = cloned.disconnect().await {
					error!("Error shutting down client: {:?}", e);
				};
			}
		});

		Ok(client)
	}

	/// This is used by the server to create a new client. Should not be used in client side code.
	pub fn from_stream(socket: TcpStream, address: SocketAddr) -> Self {
		let connection_state = Arc::new(AtomicBool::new(true));
		let raw_socket = StealthStream::from_tcp_stream(socket);

		Self {
			raw_socket,
			address,
			connection_state,
		}
	}

	/// Sends a message to/from the client to the stream.
	pub async fn send(&self, message: StealthStreamMessage) -> ClientResult<()> {
		let raw_message = message.to_message();
		self.raw_socket.write(&raw_message).await.map_err(ClientErrors::from)
	}

	/// Recieves a message to/from the client
	pub async fn recieve(&self) -> StealthStreamResult<StealthStreamMessage> {
		match self.raw_socket.read().await {
			Ok(message) => Ok(message),
			Err(e) => Err(e),
		}
	}

	/// Disconnects the client from the server by sending a disconnect message, as well as updating the connection state.
	pub async fn disconnect(&self) -> ClientResult<()> {
		self.send(StealthStreamMessage::Goodbye(Some("gracefully shutdown".to_string())))
			.await?;
		self.connection_state.store(false, Ordering::SeqCst);
		Ok(())
	}

	/* Getters */
	pub fn socket(&self) -> &StealthStream {
		&self.raw_socket
	}

	pub fn address(&self) -> SocketAddr {
		self.address
	}

	pub fn is_connected(&self) -> bool {
		self.connection_state.load(Ordering::SeqCst)
	}

	/* Setters */
	pub fn set_connection_state(&self, is_connected: bool) {
		self.connection_state.store(is_connected, Ordering::SeqCst);
	}
}
