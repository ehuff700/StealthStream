use std::{
	net::{SocketAddr, ToSocketAddrs},
	sync::{
		atomic::{AtomicBool, Ordering},
		Arc,
	},
	time::Duration,
};

use anyhow::anyhow;
use rustls::{
	client::{ServerCertVerified, ServerCertVerifier},
	RootCertStore, ServerName,
};
use tokio::{net::TcpStream, signal};
use tokio_rustls::{TlsConnector, TlsStream};
use tracing::error;
use uuid::Uuid;

use super::ClientBuilder;
use crate::ServerTlsStream;
use crate::{
	errors::ClientErrors,
	protocol::{
		constants::GRACEFUL, GoodbyeCodes, Handshake, StealthStream, StealthStreamMessage, StealthStreamPacketError,
	},
	server::MessageCallback,
	StealthStreamResult,
};
pub type ClientResult<T> = std::result::Result<T, ClientErrors>;

/// TODO: fix this override / refactor?
struct CertVerifier;
impl ServerCertVerifier for CertVerifier {
	fn verify_server_cert(
		&self, _end_entity: &rustls::Certificate, _intermediates: &[rustls::Certificate], _server_name: &ServerName,
		_scts: &mut dyn Iterator<Item = &[u8]>, _ocsp_response: &[u8], _now: std::time::SystemTime,
	) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
		Ok(ServerCertVerified::assertion())
	}
}

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
	pub(crate) async fn new(
		address: SocketAddr, peer_address: AddressContext, _skip_certificate_validation: Option<bool>,
	) -> ClientResult<Self> {
		#[cfg(feature = "tls")]
		{
			let _domain = "example.com"; // TODO: implement domain resolution and skip certificate validation
			let stream = TcpStream::connect(address).await?;
			let mut config = rustls::ClientConfig::builder()
				.with_safe_defaults()
				.with_root_certificates(RootCertStore::empty())
				.with_no_client_auth(); // i guess this was previously the default?
			config.dangerous().set_certificate_verifier(Arc::new(CertVerifier));

			let connector = TlsConnector::from(Arc::new(config));

			let tls_stream = connector
				.connect(ServerName::try_from("example.com").expect("invalid DNS name"), stream)
				.await?;
			let abstracted = TlsStream::from(tls_stream);

			let raw_socket: Arc<StealthStream> = Arc::new(abstracted.into());
			let connection_state = Arc::new(AtomicBool::new(true));

			Ok(Self {
				raw_socket,
				connection_state,
				peer_address,
			})
		}

		#[cfg(not(feature = "tls"))]
		{
			let raw_socket = Arc::new(TcpStream::connect(address).await?.into());
			let connection_state = Arc::new(AtomicBool::new(true));

			Ok(Self {
				raw_socket,
				connection_state,
				peer_address,
			})
		}
	}

	#[cfg(not(feature = "tls"))]
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

	#[cfg(feature = "tls")]
	/// Creates a new [RawClient] from a [TlsStream] and
	/// [SocketAddr].
	pub(crate) fn from_tls_stream(socket: ServerTlsStream<TcpStream>, address: SocketAddr) -> Self {
		use crate::TlsStreamEnum;

		let connection_state = Arc::new(AtomicBool::new(true));
		let raw_socket = Arc::new(TlsStreamEnum::from(socket).into());

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
	/// Whether or not the client should skip certificate validation.
	#[cfg(feature = "tls")]
	skip_certificate_validation: bool,
}

impl Client {
	/// Connects to a StealthStream server at the given address
	pub async fn connect<A>(&mut self, addr: A) -> ClientResult<()>
	where
		A: ToSocketAddrs,
	{
		let address = addr.to_socket_addrs()?.next().unwrap(); // TODO: fix this
		let peer_address = AddressContext::ServerAddress(address);

		let inner = if cfg!(feature = "tls") {
			RawClient::new(address, peer_address, Some(self.skip_certificate_validation)).await?
		} else {
			RawClient::new(address, peer_address, None).await?
		};

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
	pub async fn send(&self, message: StealthStreamMessage) -> ClientResult<()> {
		self.inner()?.send(message).await
	}

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
			event_handler: value
				.event_handler
				.unwrap_or_else(|| ClientBuilder::default_event_handler()),
			#[cfg(feature = "tls")]
			skip_certificate_validation: value.skip_certificate_validation,
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

	use crate::{
		client::ClientBuilder,
		errors::ClientErrors,
		pin_callback,
		protocol::{StealthStreamMessage, StealthStreamPacket, StealthStreamPacketError},
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

	#[tokio::test]
	async fn test_disconnect() {
		let (server, client) = server_client_setup1!();

		assert!(client.is_connected());
		client.disconnect().await.unwrap();
		assert!(!client.is_connected());

		// Assert that messages can no longer be sent after disconnect.
		let result = client.send(StealthStreamMessage::Heartbeat).await;
		assert!(result.is_err_and(|e| matches!(e, ClientErrors::InvalidPacket(StealthStreamPacketError::StreamClosed))));

		drop(server);
	}

	#[tokio::test]
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

		let (_, client) = server_client_setup1!({
			move |recieved_message, _| {
				let tx = tx.clone();
				pin_callback!({
					tx.send(recieved_message).await.unwrap();
				})
			}
		});
		tokio::time::sleep(Duration::from_millis(1)).await;

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

		tokio::time::sleep(Duration::from_millis(1)).await;

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
		let expected = StealthStreamMessage::Message("hey".to_string());
		client.send(expected).await.unwrap();
		let received = timeout(Duration::from_millis(300), rx.recv()).await;
		assert!(received.is_ok_and(|v| v.is_some()));
	}
}
