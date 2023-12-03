use std::{collections::HashMap, sync::Arc, time::Duration};

use anyhow::anyhow;
use log::warn;
use serde_json::Value;
use thiserror::Error;
use tracing::{debug, trace};

use super::{
	constants::PROTOCOL_VERSION,
	control::{AuthData, HandshakeData},
	StealthStreamMessage, StealthStreamPacketError,
};
use crate::{
	client::{Client, ClientResult, RawClient},
	errors::{ClientErrors, Error, ServerErrors},
	server::{InnerState, Namespace, ServerResult},
};

impl HandshakeData {
	pub async fn start_server_handshake(
		client: &Arc<RawClient>, namespace_handlers: &HashMap<String, Namespace>, state: &Arc<InnerState>,
		handshake_timeout: u64,
	) -> ServerResult<HandshakeData> {
		let configured_timeout = Duration::from_millis(handshake_timeout);

		let handshake_result = tokio::time::timeout(configured_timeout, client.socket().read())
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
								match auth_handler(auth.clone(), client.clone(), state.clone()).await {
									Ok(true) => {
										trace!("Successfully authenticated client {:?}", client.peer_address());
									},
									Ok(false) => {
										return Err(ServerErrors::from(HandshakeErrors::NamespaceAuthFailed))?;
									},
									Err(_) => {
										todo!(); //TODO: handle auth errors
									},
								};
							},
							None => return Err(ServerErrors::from(HandshakeErrors::NamespaceAuthMissing))?,
						}
					}

					if data.should_compress {
						trace!("Compressing stream....");
						client.socket().set_compression(true).await;
					}

					// Send acknowledgement heartbeat, indicating that the handshake was successful
					client.send(StealthStreamMessage::Heartbeat).await?;
					trace!("Upgraded connection to StealthStream for client {:?}", client.peer_address());
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
		client: &Client, should_compress: bool, headers: Option<HashMap<String, Value>>, namespace: &str,
		auth: Option<AuthData>,
	) -> ClientResult<()> {
		client
			.send(StealthStreamMessage::Handshake(HandshakeData::new(
				PROTOCOL_VERSION,
				should_compress,
				headers,
				namespace,
				auth,
			)))
			.await?;

		return match client.inner()?.socket().read().await {
			Some(Ok(StealthStreamMessage::Goodbye(data))) => {
				warn!("failed handshake: {:?}", data);
				Err(ClientErrors::ConnectionError(anyhow!(data.to_string()).into()))
			},
			Some(Ok(StealthStreamMessage::Heartbeat)) => {
				trace!("received initial heartbeat, handshake success");
				Ok(())
			},
			Some(Err(e)) => Err(e)?,
			None => Err(ClientErrors::ConnectionError(
				anyhow!("couldn't receive any messages from the server").into(),
			)),
			_ => Ok(()),
		};
	}
}

#[derive(Debug, Error)]
pub enum HandshakeErrors {
	#[error("arbitrary bytes detected")]
	ArbitraryBytes,
	#[error("namespace not found: {0}")]
	NamespaceNotFound(String),
	#[error("auth missing for privileged namespace")]
	NamespaceAuthMissing,
	#[error("authentication failed for privileged namespace")]
	NamespaceAuthFailed,
	#[error("handshake not received within the configured timeout: {0:?}")]
	HandshakeTimeout(Duration),
	#[error("error reading from buffer: {0}")]
	BufferReadError(#[from] tokio::io::Error),
	#[error("error parsing session id: {0}")]
	SessionIdParseError(#[from] uuid::Error),
	#[error("unsupported version: {0}")]
	UnsupportedVersion(u8),
	#[error("client attempted to skip handshake")]
	SkippedHandshake,
}
