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

use super::{server_struct::Server, MessageCallback, ServerResult};
#[cfg(feature = "tls")]
use crate::errors::Error;
use crate::{client::RawClient, pin_callback, protocol::StealthStreamMessage};

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
	event_handler: Option<Arc<dyn MessageCallback>>,
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
			event_handler: None,
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

	pub fn set_handshake_timeout(mut self, handshake_timeout: u64) -> Self {
		self.handshake_timeout = handshake_timeout;
		self
	}

	/// Uses the provided event handler to handle [StealthStreamMessage]s.
	pub fn with_event_handler(mut self, event_handler: impl MessageCallback) -> Self {
		self.event_handler = Some(Arc::new(event_handler));
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
		let event_handler = self.event_handler.unwrap_or_else(|| Self::default_event_handler());

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
				event_handler,
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
				event_handler,
			))
		}
	}

	fn default_event_handler() -> Arc<dyn MessageCallback> {
		let handler = |message: StealthStreamMessage, _: Arc<RawClient>| {
			pin_callback!({
				debug!("Received message: {:?}", message);
			})
		};
		Arc::new(handler)
	}
}

impl Default for ServerBuilder {
	fn default() -> Self { Self::new() }
}
