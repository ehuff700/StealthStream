use std::{
	net::{SocketAddr, ToSocketAddrs},
	sync::{
		atomic::{AtomicBool, Ordering},
		Arc,
	},
};

use anyhow::anyhow;
use tokio::{net::TcpStream, signal};
use tracing::error;

use crate::{errors::ClientErrors, GoodbyeCodes, StealthStreamResult};

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
		if self.is_connected() {
			let raw_message = message.to_message();
			self.raw_socket.write(&raw_message).await.map_err(ClientErrors::from)
		} else {
			Err(ClientErrors::ConnectionError(
				anyhow!("Client is currently not connected").into(),
			))
		}
	}

	/// Recieves a message to/from the client
	pub async fn recieve(&self) -> StealthStreamResult<StealthStreamMessage> {
		match self.raw_socket.read().await {
			Ok(message) => Ok(message),
			Err(e) => Err(e),
		}
	}

	/// Disconnects the client from the server by sending a [StealthStreamMessage::Goodbye] message as well as updating the connection state.
	///
	/// This method will additionally close the underlying socket, preventing any messages from being sent.
	pub async fn disconnect(&self) -> ClientResult<()> {
		self.send(StealthStreamMessage::Goodbye(GoodbyeCodes::Graceful)).await?;
		self.raw_socket.close().await;
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

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use rand::Rng;

	use crate::{Server, ServerBuilder, StealthStreamMessage};

	async fn setup_server() -> Arc<Server> {
		let mut rng = rand::thread_rng();
		let random_number: u16 = rng.gen_range(1000..10000);
		let server = ServerBuilder::default().port(random_number).build().await.unwrap();

		let server = Arc::new(server);

		tokio::task::spawn({
			let task_server = server.clone();
			async move {
				task_server.listen().await.unwrap();
			}
		});

		server
	}

	#[tokio::test]
	async fn test_disconnect() {
		let server = setup_server().await;
		let client = super::Client::connect(server.address()).await.unwrap();

		assert!(client.is_connected());
		client.disconnect().await.unwrap();
		assert!(!client.is_connected());

		// Assert that messages can no longer be sent after disconnect.
		let result = client.send(StealthStreamMessage::Poke).await;
		assert!(result.is_err());

		drop(server);
	}

	// TODO: refactor this test to server
	#[tokio::test]
	async fn test_basic_send_recv() {
		let server = setup_server().await;

		let client = super::Client::connect(server.address()).await.unwrap();

		let message = super::StealthStreamMessage::Message("Test".to_string());
		client.send(message).await.unwrap();

		drop(server)
	}
}
