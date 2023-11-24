use std::{collections::HashMap, sync::Arc, time::Duration};

use thiserror::Error;
use tracing::{debug, info};

use super::{
	constants::PROTOCOL_VERSION,
	control::{AuthData, HandshakeData},
	StealthStreamMessage, StealthStreamPacketError,
};
use crate::{
	client::{Client, ClientResult, RawClient},
	errors::{Error, ServerErrors},
	server::{Namespace, ServerResult},
};

impl HandshakeData {
	pub async fn start_server_handshake(
		client: &Arc<RawClient>, namespace_handlers: &HashMap<String, Namespace>, handshake_timeout: u64,
	) -> ServerResult<HandshakeData> {
		let configured_timeout = Duration::from_millis(handshake_timeout);

		let handshake_result = tokio::time::timeout(configured_timeout, client.receive())
			.await
			.map_err(|_| ServerErrors::from(HandshakeErrors::HandshakeTimeout(configured_timeout)))?;

		match handshake_result {
			Some(message) => match message {
				Ok(StealthStreamMessage::Handshake(data)) => {
					debug!("Received version {} handshake from {:?}", data.version(), client.peer_address());
					let requested = &data.namespace;

					let namespace = namespace_handlers
						.get(requested)
						.ok_or_else(|| ServerErrors::from(HandshakeErrors::NamespaceNotFound(requested.to_string())))?;

					if namespace.is_privileged {
						let auth_handler = &namespace.handlers.on_auth;
						match data.auth.as_ref() {
							Some(auth) => {
								match auth_handler(auth, client.clone()).await {
									Ok(true) => {
										debug!("Successfully authenticated client {:?}", client.peer_address());
									},
									Ok(false) => {
										return Err(ServerErrors::from(HandshakeErrors::NamespaceAuthFailed))?;
									},
									Err(_) => {
										todo!();
									},
								};
							},
							None => return Err(ServerErrors::from(HandshakeErrors::NamespaceAuthMissing))?,
						}
					}

					if data.should_compress {
						debug!("Compressing stream....");
						client.socket().set_compression(true).await;
					}

					info!("Upgraded connection to StealthStream for client {:?}", client.peer_address());
					Ok(data)
				},
				Err(e) => Err(e)?,
				Ok(_) => Err(ServerErrors::from(HandshakeErrors::SkippedHandshake))?,
			},
			None => Err(Error::from(StealthStreamPacketError::StreamClosed)),
		}
	}

	/// Sends the client handshake message to the server.
	pub async fn start_client_handshake(
		client: &Client, should_compress: bool, namespace: &str, auth: Option<AuthData>,
	) -> ClientResult<()> {
		client
			.send(StealthStreamMessage::Handshake(HandshakeData::new(
				PROTOCOL_VERSION,
				should_compress,
				namespace,
				auth,
			)))
			.await
	}
}

#[derive(Debug, Error)]
pub enum HandshakeErrors {
	#[error("Arbitrary bytes detected")]
	ArbitraryBytes,
	#[error("Namespace not found: {0}")]
	NamespaceNotFound(String),
	#[error("Auth missing for privileged namespace")]
	NamespaceAuthMissing,
	#[error("Authentication failed for privileged namespace")]
	NamespaceAuthFailed,
	#[error("Handshake not received within the configured timeout: {0:?}")]
	HandshakeTimeout(Duration),
	#[error("Error reading from buffer: {0}")]
	BufferReadError(#[from] tokio::io::Error),
	#[error("error parsing session id: {0}")]
	SessionIdParseError(#[from] uuid::Error),
	#[error("Unsupported version: {0}")]
	UnsupportedVersion(u8),
	#[error("Client attempted to skip handshake")]
	SkippedHandshake,
}
