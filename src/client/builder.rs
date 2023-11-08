use std::{sync::Arc, time::Duration};

use tracing::debug;

use crate::{protocol::StealthStreamMessage, server::MessageCallback};

use super::{Client, RawClient};

pub struct ClientBuilder {
	/// Whether or not the client should attempt to reconnect when disconnected.
	///
	/// False by default.
	pub(crate) should_reconnect: bool,
	/// The interval of time between reconnect attempts. If this parameter is not specified, an exponential backoff will be attempted.
	///
	/// None by default.
	pub(crate) reconnect_interval: Option<Duration>,
	/// The maximum number of reconnect attempts. If this parameter is not specified, a maximum of 10 attempts will be attempted.
	///
	/// None by default.
	pub(crate) reconnect_attempts: Option<u32>,

	/// Event handler for when a message is received from the server. If this parameter is not specified,
	/// A default event handler which simply logs the message will be used.
	pub(crate) event_handler: Arc<dyn MessageCallback>,
}

impl ClientBuilder {
	pub(crate) fn new() -> Self {
		Self {
			should_reconnect: false,
			reconnect_interval: None, // TODO: implement exponential backoff
			reconnect_attempts: Some(10),
			event_handler: Self::default_event_handler(),
		}
	}

	/// Determines whether or not a client should attempt to reconnect to the server on disconnect.
	pub fn should_reconnect(&mut self, should_reconnect: bool) -> &mut Self {
		self.should_reconnect = should_reconnect;
		self
	}

	/// Sets the amount of time to wait between reconnection attempts.
	pub fn reconnect_interval(&mut self, interval: Duration) -> &mut Self {
		self.reconnect_interval = Some(interval);
		self
	}

	/// Sets the maximum number of reconnection attempts.
	pub fn reconnect_attempts(&mut self, attempts: u32) -> &mut Self {
		self.reconnect_attempts = Some(attempts);
		self
	}

	/// Adds an event handler for incoming messages from the server.
	pub fn with_event_handler(&mut self, event_handler: Arc<dyn MessageCallback>) -> &mut Self {
		self.event_handler = event_handler;
		self
	}

	pub fn build(self) -> Client {
		let client: Client = self.into();
		client
	}

	fn default_event_handler() -> Arc<dyn MessageCallback> {
		Arc::new(|message: StealthStreamMessage, _: Arc<RawClient>| {
			Box::pin(async move {
				debug!("Received message from server: {:?}", message);
			})
		})
	}
}

impl Default for ClientBuilder {
	fn default() -> Self {
		Self::new()
	}
}
