mod client;
pub mod protocol;
pub mod errors;
mod server;

use errors::Error;

pub use self::client::*;
pub use self::protocol::*;
pub use self::server::*;

// TODO: Make a better error type
pub type StealthStreamResult<T> = std::result::Result<T, Error>;
