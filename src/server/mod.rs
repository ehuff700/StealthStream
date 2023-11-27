mod builder;
mod event_handler;
mod server_struct;
mod state;

use std::{future::Future, pin::Pin, sync::Arc};

pub use builder::*;
pub use event_handler::*;
pub use server_struct::*;
pub use state::*;

use crate::{
	client::RawClient,
	errors::Error as LibraryError,
	protocol::{
		control::{AuthData, GoodbyeData, HandshakeData},
		StealthStreamMessage,
	},
};

pub type ServerResult<T> = Result<T, LibraryError>;

/// Type alias used to indicate a pinned and boxed future.
pub type BoxedCallbackFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
pub type BoxedBoolFuture =
	Pin<Box<dyn Future<Output = Result<bool, Box<dyn std::error::Error + Send + 'static>>> + Send + 'static>>;

/// This trait is used by the [Server] and [Client] to handle incoming messages.
pub trait ServerMessageCallback: // TODO: move this somewhere else
	Fn(StealthStreamMessage, Arc<RawClient>, Arc<InnerState>) -> BoxedCallbackFuture + Sync + Send + 'static
{
}

impl<F> ServerMessageCallback for F where
	F: Fn(StealthStreamMessage, Arc<RawClient>, Arc<InnerState>) -> BoxedCallbackFuture + Sync + Send + 'static
{
}

pub trait ClientMessageCallback: // TODO: move this somewhere else
Fn(StealthStreamMessage, Arc<RawClient>) -> BoxedCallbackFuture + Sync + Send + 'static
{
}

impl<F> ClientMessageCallback for F where
	F: Fn(StealthStreamMessage, Arc<RawClient>) -> BoxedCallbackFuture + Sync + Send + 'static
{
}

/// This trait is used by the server whenever a new connection is established.
pub trait OpenCallback:
	Fn(HandshakeData, Arc<RawClient>, Arc<InnerState>) -> BoxedCallbackFuture + Sync + Send + 'static
{
}
impl<F> OpenCallback for F where
	F: Fn(HandshakeData, Arc<RawClient>, Arc<InnerState>) -> BoxedCallbackFuture + Sync + Send + 'static
{
}

/// This is used by the server whenever a new connection is closed.
pub trait CloseCallback:
	Fn(GoodbyeData, Arc<RawClient>, Arc<InnerState>) -> BoxedCallbackFuture + Sync + Send + 'static
{
}
impl<F> CloseCallback for F where
	F: Fn(GoodbyeData, Arc<RawClient>, Arc<InnerState>) -> BoxedCallbackFuture + Sync + Send + 'static
{
}

/// This trait is used by the server whenever a new connection is authenticated.
pub trait AuthCallback:
	Fn(AuthData, Arc<RawClient>, Arc<InnerState>) -> BoxedBoolFuture + Sync + Send + 'static
{
}

impl<F> AuthCallback for F where
	F: Fn(AuthData, Arc<RawClient>, Arc<InnerState>) -> BoxedBoolFuture + Sync + Send + 'static
{
}
