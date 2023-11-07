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

use crate::{
	errors::ClientErrors,
	protocol::{StealthStream, StealthStreamMessage, GRACEFUL},
	StealthStreamResult,
};

pub type ClientResult<T> = std::result::Result<T, ClientErrors>;

#[derive(Debug, Clone)]
/// Used to store the address context of a [SocketAddr]
pub enum AddressContext {
	/// Represents an address of the server when used on the client side.
	ServerAddress(SocketAddr),
	/// Represents the address of the client as seen from the server side.
	ClientAddress(SocketAddr),
}

#[derive(Debug, Clone)]
/// Client object used to connect to a StealthStream server.
pub struct Client {
	/// A handle to the underlying socket, wrapped in a [StealthStream] struct.
	raw_socket: StealthStream,
	/// An atomic boolean used to track the client's connection state.
	connection_state: Arc<AtomicBool>,
	/// The address context of the remote peer.
	///
	/// This value will be [AddressContext::ClientAddress] when viewed server side and [AddressContext::ServerAddress] when viewed client side.
	peer_address: AddressContext,
}

impl Client {
	/// Connects to a StealthStream server at the given address
	pub async fn connect<A>(addr: A) -> ClientResult<Self>
	where
		A: ToSocketAddrs,
	{
		let address = addr.to_socket_addrs()?.next().unwrap(); // TODO: fix this
		let raw_socket = StealthStream::from_tcp_stream(TcpStream::connect(address).await?);
		let connection_state = Arc::new(AtomicBool::new(true));

		let client = Self {
			raw_socket,
			connection_state,
			peer_address: AddressContext::ServerAddress(address),
		};

		// Setup a ctrl + c listener to gracefully close the connection.
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
		self.send(StealthStreamMessage::create_goodbye(GRACEFUL)).await?;
		self.raw_socket.close().await;
		self.connection_state.store(false, Ordering::SeqCst);
		Ok(())
	}

	/// This is used by the server to create a new client. Should not be used in client side code.
	pub(crate) fn from_stream(socket: TcpStream, address: SocketAddr) -> Self {
		let connection_state = Arc::new(AtomicBool::new(true));
		let raw_socket = StealthStream::from_tcp_stream(socket);

		Self {
			raw_socket,
			peer_address: AddressContext::ClientAddress(address),
			connection_state,
		}
	}

	/* Getters */
	pub fn socket(&self) -> &StealthStream {
		&self.raw_socket
	}

	pub fn peer_address(&self) -> &AddressContext {
		&self.peer_address
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

	use crate::{
		protocol::StealthStreamMessage,
		server::{Server, ServerBuilder},
	};

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

	#[tokio::test]
	async fn test_basic_send() {
		let server = setup_server().await;

		let client = super::Client::connect(server.address()).await.unwrap();

		let message = super::StealthStreamMessage::Message("Test".to_string());
		let result = client.send(message).await;
		assert!(result.is_ok());

		drop(server)
	}
}
