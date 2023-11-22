use std::{sync::Arc, time::Duration};

use thiserror::Error;
use tracing::{debug, info};
use uuid::Uuid;

use super::{control_messages::HandshakeData, StealthStreamMessage, StealthStreamPacketError};
use crate::{
	client::{Client, ClientResult, RawClient},
	errors::{Error, ServerErrors},
	server::ServerResult,
};

impl HandshakeData {
	pub async fn start_server_handshake(
		client: &Arc<RawClient>, handshake_timeout: u64,
	) -> ServerResult<HandshakeData> {
		let configured_timeout = Duration::from_millis(handshake_timeout);

		let handshake_result = tokio::time::timeout(configured_timeout, client.receive())
			.await
			.map_err(|_| ServerErrors::from(HandshakeErrors::HandshakeTimeout(configured_timeout)))?;

		match handshake_result {
			Some(message) => {
				match message {
					Ok(StealthStreamMessage::Handshake(data)) => {
						debug!("Received version {} handshake from {:?}", data.version(), client.peer_address());
						if data.should_compress {
							debug!("Compressing stream....");
							client.socket().set_compression(true).await;
						}

						// TODO: do something with session_id
						info!("Upgraded connection to StealthStream for client {:?}", client.peer_address());
						Ok(data)
					},
					Err(e) => Err(e)?,
					Ok(_) => Err(ServerErrors::from(HandshakeErrors::SkippedHandshake))?,
				}
			},
			None => Err(Error::from(StealthStreamPacketError::StreamClosed)),
		}
	}

	/// Sends the client handshake message to the server.
	pub async fn start_client_handshake(client: &Client, should_compress: bool) -> ClientResult<()> {
		client
			.send(StealthStreamMessage::Handshake(HandshakeData::new(
				1,
				should_compress,
				client.session_id,
			)))
			.await
	}
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
