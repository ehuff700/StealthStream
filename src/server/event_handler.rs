use std::sync::Arc;

use tracing::debug;

use super::{CloseCallback, MessageCallback, OpenCallback};
use crate::{
	client::RawClient,
	pin_callback,
	protocol::{
		control::{GoodbyeData, HandshakeData},
		StealthStreamMessage,
	},
};

pub struct Namespace {
	pub(crate) identifier: String,
	pub(crate) is_privileged: bool,
	pub(crate) handlers: EventHandler,
}

impl Namespace {
	/// Creates a new [Namespace] with the given identifier. The identifier must
	/// start with a "/", and cannot be "/" itself, as that designates the root
	/// namespace.
	///
	/// This method will assign default event handlers for onopen, onmessage,
	/// and onclose which simply log the events.
	///
	/// To have more granularity over the behaviors, define your own event
	/// handlers with the respective functions.
	pub fn new(identifier: impl Into<String>, is_privileged: bool) -> Self {
		let identifier = identifier.into();
		// TODO: prevent collision with the root namespace
		Self {
			is_privileged,
			identifier,
			handlers: EventHandler::default(),
		}
	}

	/// Defines an event handler which will be invoked when a new connection is
	/// opened.
	pub fn onopen(mut self, open_callback: impl OpenCallback) -> Self {
		self.handlers.on_open = Arc::new(open_callback);
		self
	}

	/// Defines an event handler which will be invoked when a message is
	/// received.
	pub fn onmessage(mut self, message_callback: impl MessageCallback) -> Self {
		self.handlers.on_message = Arc::new(message_callback);
		self
	}

	/// Defines an event handler which will be invoked when a connection is
	/// closed.
	pub fn onclose(mut self, close_callback: impl CloseCallback) -> Self {
		self.handlers.on_close = Arc::new(close_callback);
		self
	}
}

/// Used to create Event Handlers for a [Namespace] or a [Server] (assuming
/// default "/" namespace).
pub(crate) struct EventHandler {
	pub on_open: Arc<dyn OpenCallback>,
	pub on_message: Arc<dyn MessageCallback>,
	pub on_close: Arc<dyn CloseCallback>,
}

impl EventHandler {
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

impl Default for EventHandler {
	fn default() -> Self {
		Self {
			on_open: Self::default_open_handler(),
			on_message: Self::default_message_handler(),
			on_close: Self::default_close_handler(),
		}
	}
}
