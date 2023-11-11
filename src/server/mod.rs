mod builder;
mod server_struct;
use std::{future::Future, pin::Pin, sync::Arc};

pub use builder::*;
pub use server_struct::*;

use crate::{client::RawClient, errors::Error as LibraryError, protocol::StealthStreamMessage};

pub type ServerResult<T> = std::result::Result<T, LibraryError>;

/// Type alias used to indicate a pinned and boxed future.
pub type BoxedCallbackFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// This trait is used by the [Server] and [Client] to handle incoming messages.
pub trait MessageCallback: // TODO: move this somewhere else
	Fn(StealthStreamMessage, Arc<RawClient>) -> BoxedCallbackFuture + Sync + Send + 'static
{
}

impl<F> MessageCallback for F where
	F: Fn(StealthStreamMessage, Arc<RawClient>) -> BoxedCallbackFuture + Sync + Send + 'static
{
}
