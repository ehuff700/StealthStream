use std::string::FromUtf8Error;

use thiserror::Error;

use crate::protocol::{constants::MAX_MESSAGE_LENGTH, HandshakeErrors, StealthStreamPacketError};

/// Error type for the StealthStream library.
#[derive(Debug, Error)]
pub enum Error {
	#[error(transparent)]
	Io(#[from] std::io::Error),
	#[error(transparent)]
	InvalidPacket(#[from] StealthStreamPacketError),
	#[error("Invalid UTF-8: {0:?}")]
	Utf8Error(#[from] FromUtf8Error),
	#[error{"message contents overflowed {MAX_MESSAGE_LENGTH} bytes: {0}"}]
	MessageContentOverflowed(usize),
	#[error(transparent)]
	ServerError(#[from] ServerErrors),
	#[error(transparent)]
	ClientError(#[from] ClientErrors),

	#[cfg(feature = "tls")]
	#[error("Couldn't extract private key from file.")]
	InvalidPrivateKey,
}

#[derive(Debug, Error)]
pub enum ClientErrors {
	#[error(transparent)]
	Io(#[from] std::io::Error),
	#[error("{0}")]
	ConnectionError(Box<dyn std::error::Error + Send + Sync + 'static>),
	#[error(transparent)]
	InvalidPacket(#[from] StealthStreamPacketError),
	#[error("Client Error Occurred: {0}")]
	MiscError(#[from] anyhow::Error),
	#[error("error deserializing from bytes: {0:?}")]
	DeserializeError(#[from] rmp_serde::decode::Error),
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
