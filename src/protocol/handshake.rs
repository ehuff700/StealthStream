use std::{fmt::Display, io::Read, sync::Arc, time::Duration};

use thiserror::Error;
use tracing::{debug, info};
use uuid::Uuid;

use super::{
	constants::{DEFAULT_HANDSHAKE_LENGTH, HANDSHAKE_LENGTH_WITH_SESSION_ID, SUPPORTED_VERSIONS},
	StealthStreamMessage, StealthStreamPacketError,
};
use crate::{
	client::{Client, ClientResult, RawClient},
	errors::{Error, ServerErrors},
	server::ServerResult,
};

pub struct Handshake {
	version: u8,
	session_id: Option<Uuid>,
}

impl Handshake {
	pub async fn start_server_handshake(client: &Arc<RawClient>) -> ServerResult<()> {
		let result = tokio::time::timeout(Duration::from_millis(200), client.receive())
			.await
			.map_err(|_| ServerErrors::from(HandshakeErrors::HandshakeTimeout))?;

		match result {
			Some(message) => {
				match message {
					Ok(StealthStreamMessage::Handshake { version, .. }) => {
						debug!("Received version {} handshake from {:?}", version, client.peer_address());

						// TODO: do something with session_id
						info!("Upgraded connection to StealthStream for client {:?}", client.peer_address());
						Ok(())
					},
					Err(e) => Err(e)?,
					Ok(_) => Err(ServerErrors::from(HandshakeErrors::SkippedHandshake))?,
				}
			},
			None => Err(Error::from(StealthStreamPacketError::StreamClosed)),
		}
	}

	/// Sends the client handshake message to the server.
	pub async fn start_client_handshake(client: &Client) -> ClientResult<()> {
		client
			.send(StealthStreamMessage::Handshake {
				version: 1,
				session_id: client.session_id,
			})
			.await
	}

	/// Utility function that validates a [StealthStreamMessage::Handshake]
	/// message.
	pub fn parse_handshake(mut message_buffer: &[u8]) -> Result<Self, HandshakeErrors> {
		let mut session_id: Option<Uuid> = None;
		let version;

		if message_buffer.len() == DEFAULT_HANDSHAKE_LENGTH || message_buffer.len() == HANDSHAKE_LENGTH_WITH_SESSION_ID
		{
			let mut version_buffer = [0u8; 1];
			message_buffer.read_exact(&mut version_buffer)?;
			version = version_buffer[0];

			if message_buffer.len() == HANDSHAKE_LENGTH_WITH_SESSION_ID {
				let mut session_id_buffer = [0u8; 16];
				message_buffer.read_exact(&mut session_id_buffer)?;
				session_id = Some(Uuid::from_bytes(session_id_buffer));
			}
		} else {
			return Err(HandshakeErrors::ArbitraryBytes);
		}

		if !SUPPORTED_VERSIONS.contains(&version) {
			return Err(HandshakeErrors::UnsupportedVersion(version));
		}

		if let Some(session_id) = session_id {
			if session_id.is_nil() || session_id.get_version_num() != 4 {
				return Err(HandshakeErrors::InvalidSessionId(session_id));
			}
		}

		Ok(Self { version, session_id })
	}
}

impl From<Handshake> for StealthStreamMessage {
	fn from(value: Handshake) -> StealthStreamMessage {
		StealthStreamMessage::Handshake {
			version: value.version,
			session_id: value.session_id,
		}
	}
}

#[derive(Debug, Error)]
pub enum HandshakeErrors {
	ArbitraryBytes,
	HandshakeTimeout,
	BufferReadError(#[from] tokio::io::Error),
	InvalidSessionId(Uuid),
	UnsupportedVersion(u8),
	SkippedHandshake,
}

impl Display for HandshakeErrors {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			HandshakeErrors::HandshakeTimeout => write!(f, "Handshake not received within the configured timeout"),
			HandshakeErrors::ArbitraryBytes => write!(f, "Arbitrary Bytes detected"),
			HandshakeErrors::InvalidSessionId(uuid) => write!(f, "Invalid Session ID: {}", uuid),
			HandshakeErrors::UnsupportedVersion(version) => write!(f, "Unsupported Version: {}", version),
			HandshakeErrors::SkippedHandshake => write!(f, "Client attempted to skip handshake"),
			HandshakeErrors::BufferReadError(e) => write!(f, "Error reading from buffer: {}", e),
		}
	}
}
