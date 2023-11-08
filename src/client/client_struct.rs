use std::{
	net::{SocketAddr, ToSocketAddrs},
	sync::{
		atomic::{AtomicBool, Ordering},
		Arc,
	},
	time::Duration,
};

use anyhow::anyhow;
use tokio::{net::TcpStream, signal};
use tracing::error;
use uuid::Uuid;

use crate::{
	errors::ClientErrors,
	protocol::{GoodbyeCodes, Handshake, StealthStream, StealthStreamMessage, GRACEFUL},
	server::MessageCallback,
	StealthStreamResult,
};

use super::ClientBuilder;

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
pub struct RawClient {
	/// A handle to the underlying socket, wrapped in a [StealthStream] struct.
	raw_socket: StealthStream,
	/// An atomic boolean used to track the client's connection state.
	connection_state: Arc<AtomicBool>,
	/// The address context of the remote peer.
	///
	/// This value will be [AddressContext::ClientAddress] when viewed server side and [AddressContext::ServerAddress] when viewed client side.
	peer_address: AddressContext,
}

impl RawClient {
	/// Used by builder functions to create a new [RawClient]
	pub(crate) async fn new(address: SocketAddr, peer_address: AddressContext) -> ClientResult<Self> {
		let raw_socket = TcpStream::connect(address).await?.into();
		let connection_state = Arc::new(AtomicBool::new(true));

		Ok(Self {
			raw_socket,
			connection_state,
			peer_address,
		})
	}

	/// Creates a new [RawClient] from a [tokio::net::TcpStream] and [SocketAddr].
	pub(crate) fn from_stream(socket: TcpStream, address: SocketAddr) -> Self {
		let connection_state = Arc::new(AtomicBool::new(true));
		let raw_socket = socket.into();

		Self {
			raw_socket,
			peer_address: AddressContext::ClientAddress(address),
			connection_state,
		}
	}

	/// Sends a message to/from the client to the stream.
	pub async fn send(&self, message: StealthStreamMessage) -> ClientResult<()> {
		let raw_message = message.to_message();
		self.raw_socket.write(&raw_message).await.map_err(ClientErrors::from)
	}

	/// Gracefully disconnects the client from the server by sending a [StealthStreamMessage::Goodbye] message as well as updating the connection state.
	///
	/// This method will additionally close the underlying socket, preventing any messages from being sent.
	pub async fn disconnect(&self) -> ClientResult<()> {
		self.send(StealthStreamMessage::create_goodbye(GRACEFUL)).await?;
		self.raw_socket.close().await;
		self.connection_state.store(false, Ordering::SeqCst);
		Ok(())
	}

	/// Functionally the same as `disconnect`, but with a reason.
	pub async fn disconnect_with_reason(&self, code: impl Into<GoodbyeCodes>, reason: &str) -> ClientResult<()> {
		self.send(StealthStreamMessage::create_goodbye_with_reason(code, reason))
			.await?;
		self.raw_socket.close().await;
		self.connection_state.store(false, Ordering::SeqCst);
		Ok(())
	}

	/// Reads a single message from the stream.
	pub(crate) async fn recieve(&self) -> StealthStreamResult<StealthStreamMessage> {
		self.raw_socket.read().await
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
}

#[derive(Clone)]
#[allow(dead_code)] // TODO: implement reconnect
/// Client object used to connect to a StealthStream server.
pub struct Client {
	inner: Option<Arc<RawClient>>,
	/// Whether or not the client should attempt to reconnect when disconnected.
	should_reconnect: bool,
	/// The interval of time between reconnect attempts. If this parameter is not specified, an exponential backoff will be attempted.
	reconnect_interval: Option<Duration>,
	/// The maximum number of reconnect attempts. If this parameter is not specified, a maximum of 10 attempts will be attempted.
	reconnect_attempts: Option<u32>,
	/// The unique identifier of the session, provided by the server after a successful handshake.
	/// This will be None if this is the client's first connection.
	pub(crate) session_id: Option<Uuid>,
	/// Custom event handler defined by the client for use in recieving messages from the server.
	event_handler: Arc<dyn MessageCallback>,
}

impl Client {
	/// Connects to a StealthStream server at the given address
	pub async fn connect<A>(&mut self, addr: A) -> ClientResult<()>
	where
		A: ToSocketAddrs,
	{
		let address = addr.to_socket_addrs()?.next().unwrap(); // TODO: fix this
		let peer_address = AddressContext::ServerAddress(address);
		let inner = RawClient::new(address, peer_address).await?;
		self.inner = Some(Arc::new(inner));

		Handshake::start_client_handshake(self).await?;

		// Setup a ctrl + c listener to gracefully close the connection.
		tokio::task::spawn({
			let cloned = self.clone();
			async move {
				signal::ctrl_c().await.unwrap();
				if let Err(e) = cloned.disconnect().await {
					error!("Error shutting down client: {:?}", e);
				};
			}
		});

		Ok(())
	}

	/// Sends a message to/from the client to the stream.
	pub async fn send(&self, message: StealthStreamMessage) -> ClientResult<()> {
		self.inner()?.send(message).await
	}

	/// Begins a listening loop for incoming messages.
	///
	/// This function will block until an error occurrs or the client is disconnected.
	pub async fn listen(&self) -> StealthStreamResult<()> {
		let inner = self.inner()?;

		while self.is_connected() {
			match inner.recieve().await {
				Ok(message) => {
					let callback = &self.event_handler;
					callback(message, inner.clone()).await;
				},
				Err(e) => return Err(e),
			}
		}
		Ok(())
	}

	/// Gracefully disconnects the client from the server by sending a [StealthStreamMessage::Goodbye] message as well as updating the connection state.
	///
	/// This method will additionally close the underlying socket, preventing any messages from being sent.
	pub async fn disconnect(&self) -> ClientResult<()> {
		self.inner()?.disconnect().await
	}

	/// Functionally the same as `disconnect`, but with a reason.
	pub async fn disconnect_with_reason(&self, code: impl Into<GoodbyeCodes>, reason: &str) -> ClientResult<()> {
		self.inner()?.disconnect_with_reason(code, reason).await
	}

	/* Getters */
	pub fn is_connected(&self) -> bool {
		if let Some(inner) = &self.inner {
			inner.is_connected()
		} else {
			false
		}
	}

	// Convenience method used internally by the client to return the inner when we know it's valid.
	fn inner(&self) -> ClientResult<&Arc<RawClient>> {
		if let Some(inner) = self.inner.as_ref() {
			Ok(inner)
		} else {
			Err(ClientErrors::ConnectionError(
				anyhow!("Client is currently not connected").into(),
			))
		}
	}
}

impl From<ClientBuilder> for Client {
	fn from(value: ClientBuilder) -> Self {
		Self {
			inner: None,
			session_id: None,
			should_reconnect: value.should_reconnect,
			reconnect_interval: value.reconnect_interval,
			reconnect_attempts: value.reconnect_attempts,
			event_handler: value.event_handler,
		}
	}
}
#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use rand::Rng;

	use crate::{
		client::ClientBuilder,
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
		let mut client = ClientBuilder::default().build();
		client.connect(server.address()).await.unwrap();

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
		let mut client = ClientBuilder::default().build();
		client.connect(server.address()).await.unwrap();

		let message = super::StealthStreamMessage::Message("Test".to_string());
		let result = client.send(message).await;
		assert!(result.is_ok());

		drop(server)
	}
}
