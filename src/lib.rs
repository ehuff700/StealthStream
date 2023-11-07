pub mod client;
pub mod errors;
pub mod protocol;
pub mod server;

use errors::Error;

pub type StealthStreamResult<T> = std::result::Result<T, Error>;
