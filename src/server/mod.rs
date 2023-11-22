mod builder;
mod server_struct;
use std::{future::Future, pin::Pin, sync::Arc};

pub use builder::*;
pub use server_struct::*;

use crate::{
	client::RawClient,
	errors::Error as LibraryError,
	protocol::{
		control_messages::{GoodbyeData, HandshakeData},
		StealthStreamMessage,
	},
};

pub type ServerResult<T> = std::result::Result<T, LibraryError>;

/// Type alias used to indicate a pinned and boxed future.
pub type BoxedCallbackFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// This trait is used by the [Server] and [Client] to handle incoming messages.
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub trait MessageCallback: // TODO: move this somewhere else
	Fn(StealthStreamMessage, Arc<RawClient>) -> BoxedCallbackFuture + Sync + Send + 'static
{
}

impl<F> MessageCallback for F where
	F: Fn(StealthStreamMessage, Arc<RawClient>) -> BoxedCallbackFuture + Sync + Send + 'static
{
}

pub trait OpenCallback: Fn(HandshakeData, Arc<RawClient>) -> BoxedCallbackFuture + Sync + Send + 'static {}
impl<F> OpenCallback for F where F: Fn(HandshakeData, Arc<RawClient>) -> BoxedCallbackFuture + Sync + Send + 'static {}

pub trait CloseCallback: Fn(GoodbyeData, Arc<RawClient>) -> BoxedCallbackFuture + Sync + Send + 'static {}
impl<F> CloseCallback for F where F: Fn(GoodbyeData, Arc<RawClient>) -> BoxedCallbackFuture + Sync + Send + 'static {}
