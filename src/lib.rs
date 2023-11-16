pub mod client;
pub mod errors;
pub mod protocol;
pub mod server;

use errors::Error;

pub type StealthStreamResult<T> = std::result::Result<T, Error>;

#[macro_export]
macro_rules! pin_callback {
	($callback:block) => {
		Box::pin(async move { $callback }) as $crate::server::BoxedCallbackFuture
	};
}
