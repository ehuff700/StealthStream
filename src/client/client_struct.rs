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

use super::ClientBuilder;
use crate::{
	errors::ClientErrors,
	protocol::{
		constants::GRACEFUL, GoodbyeCodes, Handshake, StealthStream, StealthStreamMessage, StealthStreamPacketErrors,
	},
	server::MessageCallback,
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
/// The raw client used both in server and client mode.
pub struct RawClient {
	/// A handle to the underlying socket, wrapped in a [StealthStream] struct.
	raw_socket: Arc<StealthStream>,
	/// An atomic boolean used to track the client's connection state.
	connection_state: Arc<AtomicBool>,
	/// The address context of the remote peer.
	///
	/// This value will be [AddressContext::ClientAddress] when viewed server
	/// side and [AddressContext::ServerAddress] when viewed client side.
	peer_address: AddressContext,
}

impl RawClient {
	/// Used by builder functions to create a new [RawClient]
	pub(crate) async fn new(address: SocketAddr, peer_address: AddressContext) -> ClientResult<Self> {
		let raw_socket = Arc::new(TcpStream::connect(address).await?.into());
		let connection_state = Arc::new(AtomicBool::new(true));

		Ok(Self {
			raw_socket,
			connection_state,
			peer_address,
		})
	}

	/// Creates a new [RawClient] from a [TcpStream] and
	/// [SocketAddr].
	pub(crate) fn from_stream(socket: TcpStream, address: SocketAddr) -> Self {
		let connection_state = Arc::new(AtomicBool::new(true));
		let raw_socket = Arc::new(socket.into());

		Self {
			raw_socket,
			peer_address: AddressContext::ClientAddress(address),
			connection_state,
		}
	}

	/// Sends a message to/from the client to the stream.
	pub async fn send(&self, message: StealthStreamMessage) -> ClientResult<()> {
		if self.is_connected() {
			self.raw_socket.write(message.into()).await.map_err(ClientErrors::from)
		} else {
			Err(StealthStreamPacketErrors::StreamClosed)?
		}
	}

	/// Gracefully disconnects the client from the server by sending a
	/// [StealthStreamMessage::Goodbye] message as well as updating the
	/// connection state.
	///
	/// This method will additionally close the underlying socket, preventing
	/// any messages from being sent.
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

	/// Receives a message from the stream.
	///
	/// This method will return `None` if the underlying socket is closed.
	pub async fn receive(&self) -> Option<Result<StealthStreamMessage, StealthStreamPacketErrors>> {
		self.raw_socket.read().await
	}

	/* Getters */
	pub fn socket(&self) -> &StealthStream { &self.raw_socket }

	pub fn peer_address(&self) -> &AddressContext { &self.peer_address }

	pub fn is_connected(&self) -> bool { self.connection_state.load(Ordering::SeqCst) }
}

#[derive(Clone)]
#[allow(dead_code)] // TODO: implement reconnect
/// Client object wrapping a RawClient, typically used in client side code.
pub struct Client {
	inner: Option<Arc<RawClient>>,
	/// Whether or not the client should attempt to reconnect when disconnected.
	should_reconnect: bool,
	/// The interval of time between reconnect attempts. If this parameter is
	/// not specified, an exponential backoff will be attempted.
	reconnect_interval: Option<Duration>,
	/// The maximum number of reconnect attempts. If this parameter is not
	/// specified, a maximum of 10 attempts will be attempted.
	reconnect_attempts: u32,
	/// The unique identifier of the session, provided by the server after a
	/// successful handshake. This will be None if this is the client's first
	/// connection.
	pub(crate) session_id: Option<Uuid>,
	/// Custom event handler defined by the client for use in recieving messages
	/// from the server.
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
		#[cfg(feature = "signals")]
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
	pub async fn send(&self, message: StealthStreamMessage) -> ClientResult<()> { self.inner()?.send(message).await }

	/// Spawns a new tokio task which listens for incoming messages.
	///
	/// While the client is connected, it will recieve messagees from the server
	/// and call the event handler of this client with the message.
	pub async fn listen(&self) -> StealthStreamResult<()> {
		let inner = self.inner()?;
		tokio::task::spawn({
			let cloned = inner.clone();
			let callback = self.event_handler.clone();
			async move {
				while cloned.is_connected() {
					while let Some(packet) = cloned.receive().await {
						match packet {
							Ok(message) => {
								callback(message, cloned.clone()).await;
							},
							Err(e) => return Err(e), // TODO: handle errors on the client side
						}
					}
				}
				Ok(())
			}
		});

		Ok(())
	}

	/// Gracefully disconnects the client from the server by sending a
	/// [StealthStreamMessage::Goodbye] message as well as updating the
	/// connection state.
	///
	/// This method will additionally close the underlying socket, preventing
	/// any messages from being sent.
	pub async fn disconnect(&self) -> ClientResult<()> { self.inner()?.disconnect().await }

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

	/// Convenience method used internally by the crate to return the inner
	/// when we know it's valid.
	pub fn inner(&self) -> ClientResult<&Arc<RawClient>> {
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
	use std::{sync::Arc, time::Duration};

	use futures_util::SinkExt;
	use pretty_assertions::assert_eq;
	use rand::Rng;
	use tokio::time::timeout;
	use tracing::info;
	use tracing_subscriber::filter::LevelFilter;

	use crate::{
		client::ClientBuilder,
		errors::ClientErrors,
		pin_callback,
		protocol::{constants::HANDSHAKE_OPCODE, StealthStreamMessage, StealthStreamPacket, StealthStreamPacketErrors},
		server::{MessageCallback, Server, ServerBuilder},
	};
	macro_rules! server_client_setup1 {
		() => {{
			let server = basic_server_setup(|_, _| pin_callback!({})).await;
			let mut client = ClientBuilder::default().build();
			client
				.connect(server.address())
				.await
				.expect("Failed to connect to server");
			(server, client)
		}};
		($callback:block) => {{
			let server = basic_server_setup($callback).await;
			let mut client = ClientBuilder::default().build();
			client
				.connect(server.address())
				.await
				.expect("Failed to connect to server");
			(server, client)
		}};
		($server_callback:block, $client_callback:block) => {{
			let server = basic_server_setup($server_callback).await;
			let mut client = ClientBuilder::default().with_event_handler($client_callback).build();
			client
				.connect(server.address())
				.await
				.expect("Failed to connect to server");
			(server, client)
		}};
	}

	async fn basic_server_setup<T>(callback: T) -> Arc<Server>
	where
		T: MessageCallback,
	{
		let mut rng = rand::thread_rng();
		let random_number: u16 = rng.gen_range(1000..10000);
		let server = ServerBuilder::default()
			.port(random_number)
			.with_event_handler(callback);
		let server = server.build().await.expect("Couldn't build server");

		let server = Arc::new(server);

		tokio::task::spawn({
			let task_server = server.clone();
			async move {
				task_server.listen().await.unwrap();
			}
		});

		server
	}
	use test_log::test;

	#[test(tokio::test)]
	async fn test_disconnect() {
		let (server, client) = server_client_setup1!();

		assert!(client.is_connected());
		client.disconnect().await.unwrap();
		assert!(!client.is_connected());

		// Assert that messages can no longer be sent after disconnect.
		let result = client.send(StealthStreamMessage::Heartbeat).await;
		assert!(
			result.is_err_and(|e| matches!(e, ClientErrors::InvalidPacket(StealthStreamPacketErrors::StreamClosed)))
		);

		drop(server);
	}

	#[test(tokio::test)]
	async fn test_basic_send() {
		let (server, client) = server_client_setup1!();

		let message = super::StealthStreamMessage::Message("Test Message!".to_string());
		assert!(client.send(message).await.is_ok());
		drop(server)
	}

	#[tokio::test]
	async fn test_basic_recieve() {
		let (tx, mut rx) = tokio::sync::mpsc::channel(1);
		let test_txt = "Test Message!";
		tracing_subscriber::fmt().with_max_level(LevelFilter::DEBUG).init();

		let (_, client) = server_client_setup1!({
			move |recieved_message, _| {
				let tx = tx.clone();
				pin_callback!({
					tx.send(recieved_message).await.unwrap();
				})
			}
		});
		tokio::time::sleep(Duration::from_millis(1000)).await;

		/* Test Successful Recieve */
		let expected = StealthStreamMessage::Message(test_txt.to_string());
		client.send(expected).await.expect("error sending message");

		let received = rx.recv().await.expect("didn't receive valid stealthstream message");
		let expected = StealthStreamMessage::Message(test_txt.to_string());

		assert_eq!(received, expected, "the received message did not match the expected one");
	}

	#[tokio::test]
	async fn test_bad_send() {
		let (tx, mut rx) = tokio::sync::mpsc::channel(10);

		let (_, client) = server_client_setup1!({
			move |recieved_message, _| {
				let tx = tx.clone();
				info!("Recieved message: {:?}", recieved_message);
				pin_callback!({
					tx.send(recieved_message).await.unwrap();
				})
			}
		});

		let raw = client.inner().unwrap();

		tokio::time::sleep(Duration::from_millis(1000)).await;

		let mut guard = raw.raw_socket.write_half().lock().await;
		// TODO: if handshakes will be persistent, do we terminate the TCP connection?
		// test shorter content, longer prefix
		let bad_handshake: Vec<u8> = StealthStreamPacket::new(HANDSHAKE_OPCODE, 12, b"hellox".to_vec()).into();
		let buf = guard.write_buffer_mut();
		buf.extend_from_slice(&bad_handshake);

		guard.write_buffer_mut().extend_from_slice(&bad_handshake);
		guard.flush().await.expect("couldn't flush stream");
		drop(guard);

		let received = timeout(Duration::from_millis(300), rx.recv()).await;
		assert!(received.is_err());
		let expected = StealthStreamMessage::Message("hey".to_string());
		client.send(expected).await.unwrap();
		let received = timeout(Duration::from_millis(300), rx.recv()).await;
		assert!(received.is_ok_and(|v| v.is_some()));
	}
}
