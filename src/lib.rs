extern crate core;

pub mod client;
pub mod errors;
pub mod protocol;
pub mod server;

use errors::Error;

pub type StealthStreamResult<T> = Result<T, Error>;

#[macro_export]
macro_rules! pin_callback {
	($callback:block) => {
		Box::pin(async move { $callback }) as $crate::server::BoxedCallbackFuture
	};
}

#[macro_export]
macro_rules! pin_auth_callback {
	($callback:block) => {
		Box::pin(async move { $callback }) as $crate::server::BoxedBoolFuture
	};
}
