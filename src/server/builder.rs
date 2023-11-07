use std::{
	net::{IpAddr, Ipv4Addr, SocketAddr},
	sync::Arc,
};

use tokio::net::TcpListener;
use tracing::{debug, info};

use crate::{client::Client, protocol::StealthStreamMessage, server::BoxedCallbackFuture};

use super::{server_struct::Server, MessageCallback, ServerResult};

/// Utility Struct to build a [Server] as needed
pub struct ServerBuilder {
	/// The Ip Address to bind the server to.
	address: IpAddr,
	/// The port number to bind to
	port: u16,
	/// The delay between each [StealthStreamMessage::Poke] message in ms.
	poke_delay: u64,
	/// The event handler that will be invoked when a [StealthStreamMessage] is received
	event_handler: Option<Arc<dyn MessageCallback>>,
}

impl ServerBuilder {
	fn new() -> Self {
		Self {
			address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
			port: 7007,
			poke_delay: 5000,
			event_handler: None,
		}
	}

	/// Sets the ip address to bind the server to (localhost loopback by default).
	pub fn address(mut self, address: impl Into<IpAddr>) -> Self {
		self.address = address.into();
		self
	}

	/// Sets the port number to bind to (7007 by default).
	pub fn port(mut self, port: u16) -> Self {
		self.port = port;
		self
	}

	/// Determines the delay between each iteration of the [StealthStreamMessage::Poke] task, in ms.
	///
	/// 5000 ms by default.
	pub fn set_poke_delay(mut self, poke_delay: u64) -> Self {
		self.poke_delay = poke_delay;
		self
	}

	/// Uses the provided event handler to handle [StealthStreamMessage]s.
	pub fn with_event_handler(mut self, event_handler: impl MessageCallback) -> Self {
		self.event_handler = Some(Arc::new(event_handler));
		self
	}

	pub async fn build(self) -> ServerResult<Server> {
		let address = SocketAddr::new(self.address, self.port);
		let listener = TcpListener::bind(address).await?;
		let event_handler = self.event_handler.unwrap_or_else(|| Self::default_event_handler());

		info!("StealthStream server listening on {}", address);
		Ok(Server::new(
			listener,
			SocketAddr::new(self.address, self.port),
			self.poke_delay,
			event_handler,
		))
	}

	fn default_event_handler() -> Arc<dyn MessageCallback> {
		let handler = |message: StealthStreamMessage, _: Arc<Client>| {
			debug!("Received message: {:?}", message);
			Box::pin(async move {}) as BoxedCallbackFuture
		};
		Arc::new(handler)
	}
}

impl Default for ServerBuilder {
	fn default() -> Self {
		Self::new()
	}
}
