pub mod client;
pub mod errors;
pub mod protocol;
pub mod server;

use errors::Error;

pub type StealthStreamResult<T> = std::result::Result<T, Error>;

#[cfg(feature = "tls")]
pub type ClientTlsStream<T> = tokio_rustls::client::TlsStream<T>;
#[cfg(feature = "tls")]
pub type ServerTlsStream<T> = tokio_rustls::server::TlsStream<T>;
#[cfg(feature = "tls")]
pub type TlsStreamEnum<T> = tokio_rustls::TlsStream<T>;

#[macro_export]
macro_rules! pin_callback {
	($callback:block) => {
		Box::pin(async move { $callback }) as $crate::server::BoxedCallbackFuture
	};
}
