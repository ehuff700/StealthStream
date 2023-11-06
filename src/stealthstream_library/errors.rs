use std::string::FromUtf8Error;

use thiserror::Error;

/// Error type for the StealthStream library.
#[derive(Debug, Error)]
pub enum Error {
	#[error(transparent)]
	Io(#[from] std::io::Error),
	#[error("Invalid opcode provided: {0}")]
	InvalidOpcode(u8),
	#[error("Invalid UTF-8: {0:?}")]
	Utf8Error(#[from] FromUtf8Error),
	#[error(transparent)]
	ServerError(#[from] ServerErrors),
	#[error(transparent)]
	ClientError(#[from] ClientErrors),
}

#[derive(Debug, Error)]
pub enum ClientErrors {
	#[error(transparent)]
	Io(#[from] std::io::Error),
	#[error("Client Error Occurred: {0}")]
	ClientError(#[from] anyhow::Error),
}

#[derive(Debug, Error)]
pub enum ServerErrors {
	#[error(transparent)]
	Io(#[from] std::io::Error),
	#[error("Server Error Occurred: {0}")]
	ServerError(#[from] anyhow::Error),
}