use std::{io::Cursor, sync::Arc, time::Duration};

use thiserror::Error;
use tokio::io::AsyncReadExt;
use tracing::{debug, info};
use uuid::Uuid;

use super::{
	constants::{DEFAULT_HANDSHAKE_LENGTH, HANDSHAKE_LENGTH_WITH_SESSION_ID, SUPPORTED_VERSIONS},
	control_messages::HandshakeData,
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
	pub async fn start_server_handshake(client: &Arc<RawClient>, handshake_timeout: u64) -> ServerResult<()> {
		let configured_timeout = Duration::from_millis(handshake_timeout);

		let handshake_result = tokio::time::timeout(configured_timeout, client.receive())
			.await
			.map_err(|_| ServerErrors::from(HandshakeErrors::HandshakeTimeout(configured_timeout)))?;

		match handshake_result {
			Some(message) => {
				match message {
					Ok(StealthStreamMessage::Handshake(data)) => {
						debug!("Received version {} handshake from {:?}", data.version(), client.peer_address());

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
			.send(StealthStreamMessage::Handshake(HandshakeData::new(1, client.session_id)))
			.await
	}

	/// Utility function that validates a [StealthStreamMessage::Handshake]
	/// message.
	pub async fn parse_handshake(message_buffer: &[u8]) -> Result<Self, HandshakeErrors> {
		let mut reader = Cursor::new(message_buffer);

		if ![DEFAULT_HANDSHAKE_LENGTH, HANDSHAKE_LENGTH_WITH_SESSION_ID].contains(&message_buffer.len()) {
			return Err(HandshakeErrors::ArbitraryBytes);
		}

		let version = reader.read_u8().await?;

		if !SUPPORTED_VERSIONS.contains(&version) {
			return Err(HandshakeErrors::UnsupportedVersion(version));
		}

		let session_id = if message_buffer.len() == HANDSHAKE_LENGTH_WITH_SESSION_ID {
			Self::parse_session_id(&mut reader).await?
		} else {
			None
		};

		Ok(Self { version, session_id })
	}

	async fn parse_session_id(message_buffer: &mut Cursor<&[u8]>) -> Result<Option<Uuid>, HandshakeErrors> {
		let slice = message_buffer.read_i128().await?.to_be_bytes();

		let session_id = Uuid::from_slice(&slice).map_err(HandshakeErrors::from)?;

		if session_id.is_nil() || session_id.get_version_num() != 4 {
			return Err(HandshakeErrors::InvalidSessionId(session_id));
		}

		Ok(Some(session_id))
	}
}

impl From<Handshake> for HandshakeData {
	fn from(value: Handshake) -> Self { HandshakeData::new(value.version, value.session_id) }
}

#[derive(Debug, Error)]
pub enum HandshakeErrors {
	#[error("Arbitrary bytes detected")]
	ArbitraryBytes,
	#[error("Handshake not received within the configured timeout: {0:?}")]
	HandshakeTimeout(Duration),
	#[error("Error reading from buffer: {0}")]
	BufferReadError(#[from] tokio::io::Error),
	#[error("Invalid Session ID: {0}")]
	InvalidSessionId(Uuid),
	#[error("error parsing session id: {0}")]
	SessionIdParseError(#[from] uuid::Error),
	#[error("Unsupported version: {0}")]
	UnsupportedVersion(u8),
	#[error("Client attempted to skip handshake")]
	SkippedHandshake,
}
