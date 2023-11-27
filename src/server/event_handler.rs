use std::sync::Arc;

use tracing::debug;

use super::{CloseCallback, OpenCallback, ServerMessageCallback, AuthCallback};

use crate::{
	client::RawClient,
	pin_auth_callback, pin_callback,
	protocol::{
		control::{AuthData, GoodbyeData, HandshakeData},
		StealthStreamMessage,
	},
	server::state::InnerState,
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
	pub fn onopen(&mut self, open_callback: impl OpenCallback) { self.handlers.on_open = Arc::new(open_callback); }

	/// Defines an event handler which will be invoked when a message is
	/// received.
	pub fn onmessage(&mut self, message_callback: impl ServerMessageCallback) -> Self {
		self.handlers.on_message = Arc::new(message_callback);
	}

	/// Defines an event handler which will be invoked when a connection is
	/// closed.
	pub fn onclose(&mut self, close_callback: impl CloseCallback) { self.handlers.on_close = Arc::new(close_callback); }

	/// Defines an event handler which will be invoked when an attempt is made
	/// to authenticate to a namespace.
	pub fn onauth(&mut self, auth_callback: impl AuthCallback) { self.handlers.on_auth = Arc::new(auth_callback); }
}

/// Used to create Event Handlers for a [Namespace] or a [Server] (assuming
/// default "/" namespace).
pub(crate) struct EventHandler {
	pub on_auth: Arc<dyn AuthCallback>,
	pub on_open: Arc<dyn OpenCallback>,
	pub on_message: Arc<dyn ServerMessageCallback>,
	pub on_close: Arc<dyn CloseCallback>,
}

impl EventHandler {
	fn default_message_handler() -> Arc<dyn ServerMessageCallback> {
		let handler = |message: StealthStreamMessage, _: Arc<RawClient>, _: Arc<InnerState>| {
            pin_callback!({
				debug!(target: "default_message_handler", "Received message: {:?}", message);
			})
        };
            Arc::new(handler)
        }

	fn default_auth_handler() -> Arc<dyn AuthCallback> {
		let handler = |_: AuthData, _: Arc<RawClient>| pin_auth_callback!({ Ok(true) });
		Arc::new(handler)
	}

	fn default_close_handler() -> Arc<dyn CloseCallback> {
		let handler = |data: GoodbyeData, _: Arc<RawClient>, _: Arc<InnerState>| {
			pin_callback!({
				debug!(target: "default_close_handler", "Client closed connection: {:?}", data);
			})
		};
		Arc::new(handler)
	}

	fn default_open_handler() -> Arc<dyn OpenCallback> {
		let handler = |_: HandshakeData, client: Arc<RawClient>, _: Arc<InnerState>| {
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
			on_auth: Self::default_auth_handler(),
			on_open: Self::default_open_handler(),
			on_message: Self::default_message_handler(),
			on_close: Self::default_close_handler(),
		}
	}
}
