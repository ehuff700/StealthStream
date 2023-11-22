#[cfg(feature = "tls")]
use std::{
	fs::File,
	io::BufReader,
	path::{Path, PathBuf},
};
use std::{
	net::{IpAddr, Ipv4Addr, SocketAddr},
	sync::Arc,
};

#[cfg(feature = "tls")]
use rustls::Certificate;
#[cfg(feature = "tls")]
use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio::net::TcpListener;
#[cfg(feature = "tls")]
use tokio_rustls::rustls::ServerConfig;
use tracing::debug;

use super::{server_struct::Server, CloseCallback, MessageCallback, OpenCallback, ServerResult};
#[cfg(feature = "tls")]
use crate::errors::Error;
use crate::{
	client::RawClient,
	pin_callback,
	protocol::{
		control_messages::{GoodbyeData, HandshakeData},
		StealthStreamMessage,
	},
};

/// Utility Struct to build a [Server] as needed
pub struct ServerBuilder {
	/// The Ip Address to bind the server to.
	address: IpAddr,
	/// The port number to bind to
	port: u16,
	/// The delay between each [StealthStreamMessage::Poke] message in ms.
	poke_delay: u64,
	/// The accepted delay (in ms) in which a client must negotiate a successful
	/// handshake.
	handshake_timeout: u64,
	/// The event handler that will be invoked when a [StealthStreamMessage] is
	/// received
	on_message: Option<Arc<dyn MessageCallback>>,
	/// The event handler that will be invoked when a connection is opened.
	on_open: Option<Arc<dyn OpenCallback>>,
	// The event handler that will be invoked when a connection is closed.
	on_close: Option<Arc<dyn CloseCallback>>,
	#[cfg(feature = "tls")]
	/// The path to the TLS certificate.
	cert_file_path: Option<PathBuf>,
	#[cfg(feature = "tls")]
	/// The path of the private key file
	key_file_path: Option<PathBuf>,
}

impl ServerBuilder {
	fn new() -> Self {
		Self {
			address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
			port: 7007,
			poke_delay: 5000,
			handshake_timeout: 2000,
			on_message: None,
			on_close: None,
			on_open: None,
			#[cfg(feature = "tls")]
			cert_file_path: None,
			#[cfg(feature = "tls")]
			key_file_path: None,
		}
	}

	/// Sets the ip address to bind the server to (localhost loopback by
	/// default).
	pub fn address(mut self, address: impl Into<IpAddr>) -> Self {
		self.address = address.into();
		self
	}

	/// Sets the port number to bind to (7007 by default).
	pub fn port(mut self, port: u16) -> Self {
		self.port = port;
		self
	}

	/// Determines the delay between each iteration of the
	/// [StealthStreamMessage::Poke] task, in ms.
	///
	/// 5000 ms by default.
	pub fn set_poke_delay(mut self, poke_delay: u64) -> Self {
		self.poke_delay = poke_delay;
		self
	}

	/// Sets the accepted delay (in ms) in which a client must negotiate a
	/// successful handshake before the server closes the connection.
	pub fn set_handshake_timeout(mut self, handshake_timeout: u64) -> Self {
		self.handshake_timeout = handshake_timeout;
		self
	}

	/// Sets the event handler for all incoming [StealthStreamMessage]s, with
	/// the exception of handshakes (those go to open) and goodbyes (those go to
	/// close)
	pub fn onmessage(mut self, event_handler: impl MessageCallback) -> Self {
		self.on_message = Some(Arc::new(event_handler));
		self
	}

	/// Sets the event handler for all goodbye messages.
	pub fn onclose(mut self, event_handler: impl CloseCallback) -> Self {
		self.on_close = Some(Arc::new(event_handler));
		self
	}

	/// Sets the event handler for all incoming handshakes (e.g new
	/// connections.)
	pub fn onopen(mut self, event_handler: impl OpenCallback) -> Self {
		self.on_open = Some(Arc::new(event_handler));
		self
	}

	/// Sets the file path location to the TLS certificate
	#[cfg(feature = "tls")]
	#[must_use]
	pub fn cert_file_path(mut self, cert_file_path: impl AsRef<Path>) -> Self {
		self.cert_file_path = Some(cert_file_path.as_ref().to_path_buf());
		self
	}

	/// Sets the file path location to the private key file
	#[cfg(feature = "tls")]
	#[must_use]
	pub fn key_file_path(mut self, key_file_path: impl AsRef<Path>) -> Self {
		self.key_file_path = Some(key_file_path.as_ref().to_path_buf());
		self
	}

	pub async fn build(self) -> ServerResult<Server> {
		let address = SocketAddr::new(self.address, self.port);
		let listener = TcpListener::bind(address).await?;
		let on_message = self.on_message.unwrap_or_else(|| Self::default_message_handler());
		let on_close = self.on_close.unwrap_or_else(|| Self::default_close_handler());
		let on_open = self.on_open.unwrap_or_else(|| Self::default_open_handler());

		#[cfg(feature = "tls")]
		{
			let cert_file_path = self
				.cert_file_path
				.expect("Please provide a valid certificate file path or disable TLS.");
			let key_file_path = self
				.key_file_path
				.expect("Please provide a valid private key file path or disable TLS.");

			let cert_file = &mut BufReader::new(File::open(cert_file_path).expect("Couldn't open cert file"));
			let key_file = &mut BufReader::new(File::open(key_file_path).expect("Couldn't open private key file"));

			let cert_chain: Vec<Certificate> = certs(cert_file)?.into_iter().map(Certificate).collect();
			let mut keys = pkcs8_private_keys(key_file)?;
			if keys.is_empty() {
				return Err(Error::InvalidPrivateKey);
			}

			let config = ServerConfig::builder()
				.with_safe_defaults()
				.with_no_client_auth()
				.with_single_cert(cert_chain, tokio_rustls::rustls::PrivateKey(keys.remove(0)))
				.unwrap();

			Ok(Server::new(
				listener,
				SocketAddr::new(self.address, self.port),
				self.poke_delay,
				self.handshake_timeout,
				on_open,
				on_message,
				on_close,
				Some(config),
			))
		}
		#[cfg(not(feature = "tls"))]
		{
			Ok(Server::new(
				listener,
				SocketAddr::new(self.address, self.port),
				self.poke_delay,
				self.handshake_timeout,
				on_open,
				on_message,
				on_close,
			))
		}
	}

	fn default_message_handler() -> Arc<dyn MessageCallback> {
		let handler = |message: StealthStreamMessage, _: Arc<RawClient>| {
			pin_callback!({
				debug!(target: "default_message_handler", "Received message: {:?}", message);
			})
		};
		Arc::new(handler)
	}

	fn default_close_handler() -> Arc<dyn CloseCallback> {
		let handler = |data: GoodbyeData, _: Arc<RawClient>| {
			pin_callback!({
				debug!(target: "default_close_handler", "Client closed connection: {:?}", data);
			})
		};
		Arc::new(handler)
	}

	fn default_open_handler() -> Arc<dyn OpenCallback> {
		let handler = |_: HandshakeData, client: Arc<RawClient>| {
			pin_callback!({
				debug!(target: "default_open_handler", "Client connected from {:?}", client.peer_address());
			})
		};

		Arc::new(handler)
	}
}

impl Default for ServerBuilder {
	fn default() -> Self { Self::new() }
}
