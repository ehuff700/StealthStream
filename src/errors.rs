use std::{fmt::Display, string::FromUtf8Error};
use uuid::Uuid;

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
	#[error("{0}")]
	ConnectionError(Box<dyn std::error::Error + Send + Sync + 'static>),
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

#[derive(Debug, Error)]
pub enum HandshakeErrors {
	InvalidSessionId(Uuid),
	UnsupportedVersion(u8),
	SkippedHandshake,
}

impl Display for HandshakeErrors {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			HandshakeErrors::InvalidSessionId(uuid) => write!(f, "Invalid Session ID: {}", uuid),
			HandshakeErrors::UnsupportedVersion(version) => write!(f, "Unsupported Version: {}", version),
			HandshakeErrors::SkippedHandshake => write!(f, "Client attempted to skip handshake"),
		}
	}
}
