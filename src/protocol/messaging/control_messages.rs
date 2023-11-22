use std::{fmt::Display, io::Cursor};

use async_trait::async_trait;
use derive_getters::Getters;
use tokio::io::AsyncReadExt;
use uuid::Uuid;

use super::{GoodbyeCodes, StealthStreamPacketParser};
use crate::protocol::{
	constants::{ERROR_OPCODE, GOODBYE_OPCODE, HANDSHAKE_OPCODE, SUPPORTED_VERSIONS},
	framing::FrameOpcodes,
	HandshakeErrors, StealthStreamPacket, StealthStreamPacketError,
};

#[derive(Debug, PartialEq, Getters)]
pub struct HandshakeData {
	pub(crate) version: u8,
	pub(crate) should_compress: bool,
	pub(crate) session_id: Option<Uuid>,
}

#[async_trait]
impl StealthStreamPacketParser for HandshakeData {
	fn metadata(&self) -> (FrameOpcodes, Vec<u8>) {
		let opcode = FrameOpcodes::try_from(HANDSHAKE_OPCODE).unwrap();
		let mut handshake = vec![self.version, self.should_compress as u8];
		if let Some(session_id) = self.session_id.as_ref() {
			handshake.extend_from_slice(session_id.as_bytes());
		}

		(opcode, handshake)
	}

	async fn from_packet(packet: &StealthStreamPacket) -> Result<Self, StealthStreamPacketError> {
		let mut message_buffer = packet.content();
		let mut reader = Cursor::new(message_buffer);
		let version = reader.read_u8().await?;

		if !SUPPORTED_VERSIONS.contains(&version) {
			return Err(HandshakeErrors::UnsupportedVersion(version))?;
		}

		let should_compress = {
			let u8 = reader.read_u8().await?;
			if u8 > 1 {
				return Err(HandshakeErrors::ArbitraryBytes)?;
			}
			u8 != 0
		};

		let session_id = if message_buffer.len() > 2 {
			let slice = message_buffer.read_i128().await?.to_be_bytes();

			let session_id = Uuid::from_slice(&slice).map_err(HandshakeErrors::from)?;

			if session_id.is_nil() || session_id.get_version_num() != 4 {
				return Err(HandshakeErrors::InvalidSessionId(session_id))?;
			}
			Some(session_id)
		} else {
			None
		};

		Ok(Self {
			version,
			should_compress,
			session_id,
		})
	}
}

#[derive(Debug, PartialEq, Getters)]
pub struct GoodbyeData {
	code: GoodbyeCodes,
	reason: Option<String>,
}

#[async_trait]
impl StealthStreamPacketParser for GoodbyeData {
	fn metadata(&self) -> (FrameOpcodes, Vec<u8>) {
		let opcode = FrameOpcodes::try_from(GOODBYE_OPCODE).unwrap();
		let mut code_bytes = vec![self.code as u8];
		if let Some(reason) = &self.reason {
			code_bytes.extend_from_slice(reason.as_bytes());
		}

		(opcode, code_bytes)
	}

	async fn from_packet(packet: &StealthStreamPacket) -> Result<Self, StealthStreamPacketError>
	where
		Self: Sized,
	{
		let mut message_buffer = packet.content();
		let mut goodbye_code = [0u8; 1];
		message_buffer.read_exact(&mut goodbye_code).await?;
		let code = GoodbyeCodes::from(goodbye_code[0]);

		let mut reason = String::with_capacity(message_buffer.len());
		message_buffer.read_to_string(&mut reason).await?;

		let message = if reason.is_empty() {
			GoodbyeData { code, reason: None }
		} else {
			GoodbyeData {
				code,
				reason: Some(reason),
			}
		};

		Ok(message)
	}
}

#[derive(Debug, PartialEq, Getters)]
pub struct ErrorData {
	code: u8,
	reason: String,
}

#[async_trait]
impl StealthStreamPacketParser for ErrorData {
	fn metadata(&self) -> (FrameOpcodes, Vec<u8>) {
		let length = self.reason.len() + 1;
		let mut array: Vec<u8> = Vec::with_capacity(length);
		array.push(self.code);
		array.extend_from_slice(self.reason.as_bytes());

		(FrameOpcodes::try_from(ERROR_OPCODE).unwrap(), array)
	}

	async fn from_packet(packet: &StealthStreamPacket) -> Result<Self, StealthStreamPacketError> {
		let mut message_buffer = packet.content();
		let mut error_code = [0u8; 1];
		message_buffer.read_exact(&mut error_code).await?;
		let code = error_code[0];

		let mut reason = String::with_capacity(message_buffer.len());
		message_buffer.read_to_string(&mut reason).await?;

		Ok(ErrorData { code, reason })
	}
}

/* Display Implementations */
impl Display for HandshakeData {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "HandshakeData(version={}, session_id={:?})", self.version, self.session_id)
	}
}

impl Display for GoodbyeData {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "GoodbyeData(code={:?}, reason={:?})", self.code, self.reason)
	}
}

impl Display for ErrorData {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "ErrorData(code={:?}, reason={:?})", self.code, self.reason)
	}
}

/* New Implementations */
impl HandshakeData {
	pub fn new(version: u8, should_compress: bool, session_id: Option<Uuid>) -> Self {
		Self {
			version,
			should_compress,
			session_id,
		}
	}
}

impl GoodbyeData {
	pub fn new(code: GoodbyeCodes, reason: Option<String>) -> Self { Self { code, reason } }
}

impl ErrorData {
	pub fn new(code: u8, reason: String) -> Self { Self { code, reason } }
}
