use std::{sync::Arc, time::Duration};

use tracing::debug;

use super::{Client, RawClient};
use crate::{pin_callback, protocol::StealthStreamMessage, server::MessageCallback};

pub struct ClientBuilder {
	/// Whether or not the client should attempt to reconnect when disconnected.
	///
	/// False by default.
	pub(crate) should_reconnect: bool,
	/// The interval of time between reconnect attempts. If this parameter is
	/// not specified, an exponential backoff will be attempted.
	///
	/// None by default.
	pub(crate) reconnect_interval: Option<Duration>,
	/// The maximum number of reconnect attempts. If this parameter is not
	/// specified, a maximum of 10 attempts will be attempted.
	///
	/// None by default.
	pub(crate) reconnect_attempts: u32,

	/// Event handler for when a message is received from the server. If this
	/// parameter is not specified, A default event handler which simply logs
	/// the message will be used.
	pub(crate) event_handler: Option<Arc<dyn MessageCallback>>,

	/// Simple boolean to indicate whether or not the client should skip certificate validation.
	/// This should only be used for testing purposes **AND IS NOT SAFE** for production use.
	#[cfg(feature = "tls")]
	pub(crate) skip_certificate_validation: bool,
}

impl ClientBuilder {
	pub(crate) fn new() -> Self {
		Self {
			should_reconnect: false,
			reconnect_interval: None, // TODO: implement exponential backoff
			reconnect_attempts: 10,
			event_handler: None,
			#[cfg(feature = "tls")]
			skip_certificate_validation: false,
		}
	}

	/// Determines whether or not a client should attempt to reconnect to the
	/// server on disconnect.
	pub fn should_reconnect(mut self, should_reconnect: bool) -> Self {
		self.should_reconnect = should_reconnect;
		self
	}

	/// Sets the amount of time to wait between reconnection attempts.
	pub fn reconnect_interval(mut self, interval: Duration) -> Self {
		self.reconnect_interval = Some(interval);
		self
	}

	/// Sets the maximum number of reconnection attempts.
	pub fn reconnect_attempts(mut self, attempts: u32) -> Self {
		self.reconnect_attempts = attempts;
		self
	}

	/// Adds an event handler for incoming messages from the server.
	pub fn with_event_handler(mut self, event_handler: impl MessageCallback) -> Self {
		self.event_handler = Some(Arc::new(event_handler));
		self
	}

	/// Determines whether or not the client should skip certificate validation.
	///
	/// Skipping certificate validation should only be used for testing purposes **AND IS NOT SAFE** for production use.
	#[cfg(feature = "tls")]
	pub fn skip_certificate_validation(mut self, value: bool) -> Self {
		self.skip_certificate_validation = value;
		self
	}

	// TODO: implement on close/error? Or leave that up to the implementation?
	pub fn build(self) -> Client {
		self.into()
	}

	/// Default event handler which simply logs the message.
	pub(crate) fn default_event_handler() -> Arc<dyn MessageCallback> {
		let handler = |message: StealthStreamMessage, _: Arc<RawClient>| {
			pin_callback!({
				debug!(target: "default_event_handler", "Received message: {}", message);
			})
		};
		Arc::new(handler)
	}
}

impl Default for ClientBuilder {
	fn default() -> Self {
		Self::new()
	}
}
