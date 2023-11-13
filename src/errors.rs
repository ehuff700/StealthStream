use std::string::FromUtf8Error;

use thiserror::Error;

use crate::protocol::{HandshakeErrors, StealthStreamPacketErrors};

/// Error type for the StealthStream library.
#[derive(Debug, Error)]
pub enum Error {
	#[error(transparent)]
	Io(#[from] std::io::Error),
	#[error(transparent)]
	InvalidPacket(#[from] StealthStreamPacketErrors),
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
	#[error("{0}")]
	ConnectionError(Box<dyn std::error::Error + Send + Sync + 'static>),
	#[error(transparent)]
	InvalidPacket(#[from] StealthStreamPacketErrors),
	#[error("Client Error Occurred: {0}")]
	MiscError(#[from] anyhow::Error),
}

#[derive(Debug, Error)]
pub enum ServerErrors {
	#[error(transparent)]
	Io(#[from] std::io::Error),
	#[error("Invalid Handshake: {0}")]
	InvalidHandshake(#[from] HandshakeErrors),
	#[error("Server Error Occurred: {0}")]
	ServerError(#[from] anyhow::Error),
}
