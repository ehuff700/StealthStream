mod builder;
mod client_struct;

use std::sync::Arc;

pub use builder::*;
pub use client_struct::*;

use crate::{protocol::StealthStreamMessage, server::BoxedCallbackFuture};

pub trait ClientMessageCallback: // TODO: move this somewhere else
Fn(StealthStreamMessage, Arc<RawClient>) -> BoxedCallbackFuture + Sync + Send + 'static
{
}

impl<F> ClientMessageCallback for F where
	F: Fn(StealthStreamMessage, Arc<RawClient>) -> BoxedCallbackFuture + Sync + Send + 'static
{
}
