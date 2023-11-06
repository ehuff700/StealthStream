pub mod connection;
pub mod errors;
use errors::Error;

pub use self::connection::*;

// TODO: Make a better error type
pub type StealthStreamResult<T> = std::result::Result<T, Error>;
