use std::{
	collections::HashMap,
	fmt::Display,
	net::{SocketAddr, ToSocketAddrs},
	sync::{
		atomic::{AtomicBool, Ordering},
		Arc,
	},
	time::Duration,
};

use anyhow::anyhow;
#[cfg(feature = "tls")]
use rustls::ClientConfig;
#[cfg(feature = "tls")]
use rustls::{RootCertStore, ServerName};
use serde::Deserialize;
use serde_json::Value;
use tokio::{net::TcpStream, signal};
#[cfg(feature = "tls")]
use tokio_rustls::{TlsConnector, TlsStream};
use tracing::{debug, error};
use uuid::Uuid;

use super::{ClientBuilder, ClientMessageCallback};
#[cfg(feature = "tls")]
use crate::protocol::tls::{CertVerifier, ServerTlsStream};
use crate::{
	errors::ClientErrors,
	protocol::{
		constants::GRACEFUL,
		control::{AuthData, HandshakeData},
		data::{AcknowledgeData, MessageData},
		GoodbyeCodes, StealthStream, StealthStreamMessage, StealthStreamPacketError,
	},
	server::InnerState,
	StealthStreamResult,
};

pub type ClientResult<T> = Result<T, ClientErrors>;

#[derive(Debug, Clone)]
/// Used to store the address context of a [SocketAddr]
pub enum AddressContext {
	/// Represents an address of the server when used on the client side.
	ServerAddress(SocketAddr),
	/// Represents the address of the client as seen from the server side.
	ClientAddress(SocketAddr),
}

impl Display for AddressContext {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::ServerAddress(addr) => write!(f, "{}", addr),
			Self::ClientAddress(addr) => write!(f, "{}", addr),
		}
	}
}

#[derive(Debug, Clone)]
/// The raw client used both in server and client mode.
pub struct RawClient {
	/// A handle to the underlying socket, wrapped in a [StealthStream] struct.
	raw_socket: Arc<StealthStream>,
	/// An atomic boolean used to track the client's connection state.
	connection_state: Arc<AtomicBool>,
	/// An optional state object that can be used by the server to track the
	/// state of the client.
	state: Arc<InnerState>,
	/// The address context of the remote peer.
	///
	/// This value will be [AddressContext::ClientAddress] when viewed server
	/// side and [AddressContext::ServerAddress] when viewed client side.
	peer_address: AddressContext,
}

impl RawClient {
	/// Used by builder functions to create a new [RawClient]
	pub(crate) async fn new(
		address: SocketAddr, peer_address: AddressContext,
		#[cfg(feature = "tls")] _skip_certificate_validation: Option<bool>,
	) -> ClientResult<Self> {
		#[cfg(feature = "tls")]
		{
			// TODO: implement domain resolution and skip certificate validation
			let stream = TcpStream::connect(address).await?;

			let mut config = ClientConfig::builder()
				.with_safe_defaults()
				.with_root_certificates(RootCertStore::empty())
				.with_no_client_auth();

			if matches!(_skip_certificate_validation, Some(true) | None) {
				config.dangerous().set_certificate_verifier(Arc::new(CertVerifier));
			} else {
				// TODO: setup proper root certificates
			}

			let connector = TlsConnector::from(Arc::new(config));

			let tls_stream = connector
				.connect(ServerName::try_from("example.com").expect("invalid DNS name"), stream)
				.await?;

			let abstracted = TlsStream::from(tls_stream);
			let raw_socket: Arc<StealthStream> = Arc::new(abstracted.into());
			let connection_state = Arc::new(AtomicBool::new(true));
			let state = Arc::new(InnerState::default());

			Ok(Self {
				raw_socket,
				connection_state,
				state,
				peer_address,
			})
		}

		#[cfg(not(feature = "tls"))]
		{
			let raw_socket = Arc::new(TcpStream::connect(address).await?.into());
			let connection_state = Arc::new(AtomicBool::new(true));
			let state = Arc::new(InnerState::default());

			Ok(Self {
				raw_socket,
				connection_state,
				state,
				peer_address,
			})
		}
	}

	#[cfg(not(feature = "tls"))]
	/// Creates a new [RawClient] from a [TcpStream] and
	/// [SocketAddr]. This method is typically used to create a raw client on
	/// the server side.
	pub(crate) fn from_stream(socket: TcpStream, address: SocketAddr, state: Arc<InnerState>) -> Self {
		let connection_state = Arc::new(AtomicBool::new(true));
		let raw_socket = Arc::new(socket.into());

		Self {
			raw_socket,
			peer_address: AddressContext::ClientAddress(address),
			state,
			connection_state,
		}
	}

	#[cfg(feature = "tls")]
	/// Creates a new [RawClient] from a [ServerTlsStream<TcpStream>] and
	/// [SocketAddr]. This method is typically used to create a raw client on
	/// the server side.
	pub(crate) fn from_tls_stream(
		socket: ServerTlsStream<TcpStream>, address: SocketAddr, state: Arc<InnerState>,
	) -> Self {
		use crate::protocol::tls::TlsStreamEnum;

		let connection_state = Arc::new(AtomicBool::new(true));
		let raw_socket = Arc::new(TlsStreamEnum::from(socket).into());

		Self {
			raw_socket,
			peer_address: AddressContext::ClientAddress(address),
			connection_state,
			state,
		}
	}

	/// Sends a message to/from the client to the stream.
	pub async fn send(&self, message: StealthStreamMessage) -> ClientResult<()> {
		if self.is_connected() {
			self.raw_socket
				.write_all(message.to_packet()?)
				.await
				.map_err(ClientErrors::from)
		} else {
			Err(StealthStreamPacketError::StreamClosed)?
		}
	}

	/// Sends a message to the socket, resolving when the appropriate
	/// acknowledgement is received.
	pub async fn send_with_ack(&self, message: MessageData) -> ClientResult<Option<AcknowledgeData>> {
		let ack_id = message.ack_id().unwrap(); // TODO: change this?
		let message = StealthStreamMessage::Message(message);

		if self.is_connected() {
			self.raw_socket
				.write_all(message.to_packet()?)
				.await
				.map_err(ClientErrors::from)?;
			Ok(self.raw_socket.wait_for_ack(ack_id).await.map_err(ClientErrors::from)?)
		} else {
			Err(StealthStreamPacketError::StreamClosed)?
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
		self.raw_socket.close().await?;
		self.connection_state.store(false, Ordering::SeqCst);
		Ok(())
	}

	/// Functionally the same as `disconnect`, but with a reason.
	pub async fn disconnect_with_reason(&self, code: impl Into<GoodbyeCodes>, reason: &str) -> ClientResult<()> {
		self.send(StealthStreamMessage::create_goodbye_with_reason(code, reason))
			.await?;
		self.raw_socket.close().await?;
		self.connection_state.store(false, Ordering::SeqCst);
		Ok(())
	}

	/// Receives a message from the stream.
	///
	/// This method will return `None` if the underlying socket is closed.
	pub async fn receive(&self) -> Option<Result<StealthStreamMessage, StealthStreamPacketError>> {
		self.raw_socket.read().await
	}

	/* Getters */
	pub fn socket(&self) -> &StealthStream { &self.raw_socket }

	pub fn peer_address(&self) -> &AddressContext { &self.peer_address }

	pub fn is_connected(&self) -> bool { self.connection_state.load(Ordering::SeqCst) }

	/// Retrieves the state for the client.
	///
	/// The state can be used particularly in server-side code to track the
	/// state of the client.
	pub fn state(&self) -> &Arc<InnerState> { &self.state }
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
	/// Custom event handler defined by the client for use in receiving messages
	/// from the server.
	event_handler: Arc<dyn ClientMessageCallback>,
	/// Headers sent during the initial handshake.
	headers: Option<HashMap<String, Value>>,
	/// Whether or not the client should compress the stream using LZ4.
	should_compress: bool,
	/// Whether or not the client should skip certificate validation.
	#[cfg(feature = "tls")]
	skip_certificate_validation: bool,
}

impl Client {
	/// Internal function which handles the actual connection.
	async fn _connect<A>(&mut self, addr: A, namespace: &str, auth: Option<AuthData>) -> ClientResult<()>
	where
		A: ToSocketAddrs,
	{
		let address = addr.to_socket_addrs()?.next().unwrap(); //FIXME
		let peer_address = AddressContext::ServerAddress(address);

		#[cfg(feature = "tls")]
		let inner = RawClient::new(address, peer_address, Some(self.skip_certificate_validation)).await?;

		#[cfg(not(feature = "tls"))]
		let inner = RawClient::new(address, peer_address).await?;

		self.inner = Some(Arc::new(inner));

		HandshakeData::start_client_handshake(self, self.should_compress, self.headers.clone(), namespace, auth)
			.await?;
		/* TODO: fix this
		if let Some(Ok(_value)) = self.inner()?.receive().await {
		} else {

		};*/

		// Setup a ctrl + c listener to gracefully close the connection.
		#[cfg(feature = "signals")] // TODO: make sure this only runs once.
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

	/// Connects to a StealthStream server at the given address
	///
	/// This function will connect to the root namespace with no authentication.
	pub async fn connect<A>(&mut self, addr: A) -> ClientResult<()>
	where
		A: ToSocketAddrs,
	{
		self._connect(addr, "/", None).await
	}

	/// Connects to the namespace on the StealthStream server at the given
	/// address.
	///
	/// This function will connect to the provided namespace, with the optional
	/// authentication data.
	pub async fn connect_to_namespace<A>(
		&mut self, addr: A, namespace: &str, auth: Option<AuthData>,
	) -> ClientResult<()>
	where
		A: ToSocketAddrs,
	{
		self._connect(addr, namespace, auth).await
	}

	/// Sends a message to/from the client to the stream.
	pub async fn send(&self, message: StealthStreamMessage) -> ClientResult<()> { self.inner()?.send(message).await }

	/// Sends a message from the client while waiting for an acknowledgement.
	pub async fn send_with_ack<T>(&self, message: MessageData) -> ClientResult<T>
	where
		T: for<'a> Deserialize<'a> + Send + Sync + 'static,
	{
		debug!("was this triggered");
		let ack = self.inner()?.send_with_ack(message).await?;
		if let Some(ack) = ack {
			let content = ack.deserialize::<T>()?;
			Ok(content)
		} else {
			Err(StealthStreamPacketError::StreamClosed)?
		}
	}

	/// Spawns a blocking loop which listens for incoming messages from the
	/// server.
	///
	/// While the client is connected, it will receive messages from the server
	/// and call the event handler of this client with the message.
	pub async fn listen(&self) -> StealthStreamResult<()> {
		let inner = self.inner()?;
		let callback = &self.event_handler;
		while inner.is_connected() {
			while let Some(packet) = inner.receive().await {
				match packet {
					Ok(message) => {
						callback(message, inner.clone()).await;
					},
					Err(e) => return Err(e)?, // TODO: handle errors on the client side
				}
			}
		}
		Ok(())
	}

	/// Receives a message from the stream.
	///
	/// This method will return `None` if the underlying socket is closed.
	pub async fn receive(&self) -> Option<Result<StealthStreamMessage, StealthStreamPacketError>> {
		self.inner().unwrap().receive().await
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

	/// Returns the remote address of the peer this client is connected to, if
	/// any.
	pub fn peer_address(&self) -> Option<AddressContext> {
		let inner = self.inner().ok();
		inner.map(|inner| inner.peer_address.clone())
	}

	/// Convenience method used internally by the crate to return the inner
	/// when we know it's valid.
	pub fn inner(&self) -> ClientResult<Arc<RawClient>> {
		if let Some(inner) = self.inner.as_ref() {
			Ok(inner.clone())
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
			should_compress: value.should_compress,
			headers: value.headers,
			event_handler: value
				.event_handler
				.unwrap_or_else(|| ClientBuilder::default_event_handler()),
			#[cfg(feature = "tls")]
			skip_certificate_validation: value.skip_certificate_validation,
		}
	}
}
#[cfg(test)] // TODO: write namespace tests
mod tests {
	use std::{sync::Arc, time::Duration};

	use futures_util::SinkExt;
	use pretty_assertions::assert_eq;
	use rand::Rng;
	use tokio::time::timeout;
	#[allow(unused_imports)]
	use tracing::{debug, info, level_filters::LevelFilter};

	use crate::{
		client::ClientBuilder,
		errors::ClientErrors,
		pin_callback,
		protocol::{data::MessageData, StealthStreamMessage, StealthStreamPacket, StealthStreamPacketError},
		server::{Namespace, Server, ServerBuilder, ServerMessageCallback},
	};

	macro_rules! server_client_setup1 {
		() => {{
			let server = basic_server_setup(|_, _, _| pin_callback!({})).await;
			#[cfg(not(feature = "tls"))]
			let mut client = ClientBuilder::default().build();

			#[cfg(feature = "tls")]
			let mut client = ClientBuilder::default().skip_certificate_validation(true).build();
			client
				.connect(server.address())
				.await
				.expect("Failed to connect to server");
			(server, client)
		}};
		($callback:block) => {{
			let server = basic_server_setup($callback).await;
			#[cfg(not(feature = "tls"))]
			let mut client = ClientBuilder::default().build();

			#[cfg(feature = "tls")]
			let mut client = ClientBuilder::default().skip_certificate_validation(true).build();
			client
				.connect(server.address())
				.await
				.expect("Failed to connect to server");
			(server, client)
		}};
		($server_callback:block, $client_callback:block) => {{
			let server = basic_server_setup($server_callback).await;
			#[cfg(not(feature = "tls"))]
			let mut client = ClientBuilder::default().with_event_handler($client_callback).build();

			#[cfg(feature = "tls")]
			let mut client = ClientBuilder::default()
				.skip_certificate_validation(true)
				.with_event_handler($client_callback)
				.build();

			client
				.connect(server.address())
				.await
				.expect("Failed to connect to server");
			(server, client)
		}};
	}

	async fn basic_server_setup<T>(callback: T) -> Arc<Server>
	where
		T: ServerMessageCallback,
	{
		let mut rng = rand::thread_rng();
		let random_number: u16 = rng.gen_range(1000..10000);
		let client_namespace = Namespace::new("/client", false);
		let admin_namespace = Namespace::new("/admin", true);

		#[cfg(not(feature = "tls"))]
		let server = ServerBuilder::default()
			.with_namespace(admin_namespace)
			.with_namespace(client_namespace)
			.port(random_number)
			.onmessage(callback);
		#[cfg(feature = "tls")]
		let server = ServerBuilder::default()
			.cert_file_path("src/test_cert.pem")
			.key_file_path("src/test_key.pem")
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

	#[tokio::test]
	async fn test_disconnect() {
		let (server, mut client) = server_client_setup1!();

		assert!(client.is_connected());
		client.disconnect().await.unwrap();
		assert!(!client.is_connected());

		// Assert that messages can no longer be sent after disconnect.
		let result = client.send(StealthStreamMessage::Heartbeat).await;
		assert!(result.is_err_and(|e| matches!(e, ClientErrors::InvalidPacket(StealthStreamPacketError::StreamClosed))));

		client
			.connect_to_namespace(server.address(), "/client", None)
			.await
			.unwrap();

		assert!(client.is_connected());
		client.disconnect().await.unwrap();
		assert!(!client.is_connected());

		drop(server);
	}

	#[tokio::test]
	async fn test_namespaces() {
		//tracing_subscriber::fmt().with_max_level(LevelFilter::DEBUG).init();
		let (tx, mut rx) = tokio::sync::mpsc::channel(1);

		let (server, mut client) = server_client_setup1!(
			{
				let cloned = tx.clone();
				move |recieved_message, _, _| {
					let tx = cloned.clone();
					pin_callback!({
						tx.send(recieved_message).await.unwrap();
					})
				}
			},
			{
				move |recieved_message, _| {
					let tx = tx.clone();
					pin_callback!({
						tx.send(recieved_message).await.unwrap();
					})
				}
			}
		);

		client
			.connect_to_namespace(server.address(), "/admin", None)
			.await
			.unwrap();
		tokio::task::spawn({
			let cloned = client.clone();
			async move { cloned.listen().await }
		});

		let r = rx.recv().await;
		// Test that server sends a goodbye message to the client, because an attempt to
		// access a privileged namespace. TODO: enhance this to assert_eq
		assert!(r.is_some_and(|a| matches!(a, StealthStreamMessage::Goodbye(_))));
	}

	#[tokio::test]
	async fn test_basic_send() {
		let (server, client) = server_client_setup1!();

		let message = StealthStreamMessage::Message(MessageData::new(b"Test Message!", false, false));
		assert!(client.send(message).await.is_ok());
		drop(server)
	}

	#[tokio::test]
	async fn test_basic_receive() {
		//tracing_subscriber::fmt().with_max_level(LevelFilter::DEBUG).init();

		let (tx, mut rx) = tokio::sync::mpsc::channel(1);
		let test_txt = "Test Message!";

		let (_, client) = server_client_setup1!({
			move |recieved_message, _, _| {
				let tx = tx.clone();
				pin_callback!({
					tx.send(recieved_message).await.unwrap();
				})
			}
		});

		/* Test Successful Receive */
		let expected = StealthStreamMessage::Message(MessageData::new(test_txt.as_bytes(), true, false));
		client.send(expected).await.expect("error sending message");

		let received = rx.recv().await.expect("didn't receive valid stealthstream message");
		let expected = StealthStreamMessage::Message(MessageData::new(test_txt.as_bytes(), true, false));

		assert_eq!(received, expected, "the received message did not match the expected one");
	}

	#[tokio::test]
	async fn test_bad_send() {
		//tracing_subscriber::fmt().with_max_level(LevelFilter::DEBUG).init();
		let (tx, mut rx) = tokio::sync::mpsc::channel(10);

		let (_, client) = server_client_setup1!({
			move |recieved_message, _, _| {
				let tx = tx.clone();
				info!("Received message: {}", recieved_message);
				pin_callback!({
					tx.send(recieved_message).await.unwrap();
				})
			}
		});

		let raw = client.inner().unwrap();

		/* Send a Bad Packet */
		let mut guard = raw.raw_socket.writer().lock().await;
		let packet = StealthStreamPacket::new(0, 2, vec![1, 2]);
		let bytes: Vec<u8> = packet.into();
		guard.write_buffer_mut().extend_from_slice(&bytes);
		guard.flush().await.expect("couldn't flush raw write stream");
		drop(guard);

		let received = timeout(Duration::from_millis(300), rx.recv()).await;
		assert!(received.is_err());

		/* Assert that normal packets can be sent after bad ones */
		let expected = StealthStreamMessage::Message(MessageData::new(b"hey", true, false));
		client.send(expected).await.unwrap();
		let received = timeout(Duration::from_millis(300), rx.recv()).await;
		assert!(received.is_ok_and(|v| v.is_some()));
	}

	#[tokio::test]
	async fn test_message_fragmentation() {
		//tracing_subscriber::fmt().with_max_level(LevelFilter::DEBUG).init();
		let (tx, mut rx) = tokio::sync::mpsc::channel(10);

		let (_, client) = server_client_setup1!({
			move |recieved_message, _, _| {
				let tx = tx.clone();
				info!("Received message: {}", recieved_message);
				pin_callback!({
					tx.send(recieved_message).await.unwrap();
				})
			}
		});

		tokio::time::sleep(Duration::from_millis(500)).await;

		/* Test Message Fragmentation */
		let gen = generate_long_string(3);
		let result = client.send(StealthStreamMessage::create_utf8_message(&gen)).await;
		assert!(result.is_ok());
		let test = rx.recv().await;
		assert!(test.is_some_and(|v| v.to_string().contains("aaa")));

		/* Test content overflow */
		let gen = generate_long_string(1024 * 16);
		let result = client.send(StealthStreamMessage::create_utf8_message(&gen)).await;
		assert!(result.is_err_and(|e| matches!(
			e,
			ClientErrors::InvalidPacket(StealthStreamPacketError::MessageContentsOverflowed(_))
		)));

		/* Test Successful Send */
		let result = client.send(StealthStreamMessage::create_utf8_message("hi")).await;
		assert!(result.is_ok());

		let test = rx.recv().await;
		assert_eq!(Some(StealthStreamMessage::create_utf8_message("hi")), test);
	}

	fn generate_long_string(length_kb: usize) -> String {
		let length = 1024 * length_kb; // Convert KB to bytes (characters)
		let repeated_char = "a"; // You can choose any character
		repeated_char.to_string().repeat(length)
	}
}
