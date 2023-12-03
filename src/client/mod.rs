mod builder;
mod client_struct;

pub use builder::*;
pub use client_struct::*;

use crate::{protocol::StealthStreamMessage, server::BoxedCallbackFuture};

pub trait ClientMessageCallback: // TODO: move this somewhere else
Fn(StealthStreamMessage, Client) -> BoxedCallbackFuture + Sync + Send + 'static
{
}

impl<F> ClientMessageCallback for F where
	F: Fn(StealthStreamMessage, Client) -> BoxedCallbackFuture + Sync + Send + 'static
{
}
