use std::fmt::Display;

use bytes::{Buf, Bytes};
use derive_getters::Getters;

use super::{GoodbyeCodes, StealthStreamPacketParser};
use crate::protocol::{
	constants::SUPPORTED_VERSIONS, framing::FrameOpcodes, HandshakeErrors, StealthStreamPacket,
	StealthStreamPacketError,
};

#[derive(Debug, Getters, PartialEq)]
pub struct AuthData {
	username: String,
	hashed_password: String,
}

#[derive(Debug, PartialEq, Getters)]
pub struct HandshakeData {
	pub(crate) version: u8,
	pub(crate) should_compress: bool,
	pub(crate) namespace: String,
	pub(crate) auth: Option<AuthData>,
}

impl StealthStreamPacketParser for HandshakeData {
	fn metadata(&self) -> (FrameOpcodes, Vec<u8>) {
		let mut handshake = Vec::new();
		handshake.push(self.version);
		handshake.push(self.should_compress as u8);

		// Namespace
		let namespace_bytes = self.namespace.as_bytes();
		let namespace_len = namespace_bytes.len() as u16;
		handshake.extend_from_slice(&namespace_len.to_be_bytes());
		handshake.extend_from_slice(namespace_bytes);

		// Auth
		match &self.auth {
			Some(auth) => {
				handshake.push(1); // Auth present

				// Push username length prefix and bytes
				let username_bytes = auth.username.as_bytes();
				let username_len = username_bytes.len() as u16;

				handshake.extend_from_slice(&username_len.to_be_bytes());
				handshake.extend_from_slice(username_bytes);

				// Push password length prefix and bytes
				let password_bytes = auth.hashed_password.as_bytes();
				let password_len = password_bytes.len() as u16;

				handshake.extend_from_slice(&password_len.to_be_bytes());
				handshake.extend_from_slice(password_bytes);
			},
			None => handshake.push(0), // No auth
		}

		(FrameOpcodes::Handshake, handshake)
	}

	fn from_packet(packet: StealthStreamPacket) -> Result<Self, StealthStreamPacketError> {
		let mut bytes = Bytes::from(packet.content().to_owned());

		let version = bytes.get_u8();

		if !SUPPORTED_VERSIONS.contains(&version) {
			return Err(HandshakeErrors::UnsupportedVersion(version))?;
		}

		let should_compress = bytes.get_u8() != 0;

		let namespace_len = bytes.get_u16() as usize;
		let namespace = String::from_utf8(bytes.copy_to_bytes(namespace_len).to_vec()).map_err(|e| {
			StealthStreamPacketError::InvalidUtf8 {
				source: e,
				field: "namespace".to_string(),
			}
		})?;

		let auth =
			if bytes.get_u8() == 1 {
				let username_len = bytes.get_u16() as usize;
				let username =
					String::from_utf8(bytes.copy_to_bytes(username_len).to_vec()).map_err(|e| {
						StealthStreamPacketError::InvalidUtf8 {
							source: e,
							field: "username".to_string(),
						}
					})?;

				let password_len = bytes.get_u16() as usize;
				let hashed_password = String::from_utf8(bytes.copy_to_bytes(password_len).to_vec()).map_err(|e| {
					StealthStreamPacketError::InvalidUtf8 {
						source: e,
						field: "hashed_password".to_string(),
					}
				})?;

				Some(AuthData {
					username,
					hashed_password,
				})
			} else {
				None
			};

		Ok(Self {
			version,
			should_compress,
			namespace,
			auth,
		})
	}
}

#[derive(Debug, PartialEq, Getters)]
pub struct GoodbyeData {
	code: GoodbyeCodes,
	reason: Option<String>,
}

impl StealthStreamPacketParser for GoodbyeData {
	fn metadata(&self) -> (FrameOpcodes, Vec<u8>) {
		let mut code_bytes = vec![self.code as u8];
		if let Some(reason) = &self.reason {
			code_bytes.extend_from_slice(reason.as_bytes());
		}

		(FrameOpcodes::Goodbye, code_bytes)
	}

	fn from_packet(packet: StealthStreamPacket) -> Result<Self, StealthStreamPacketError>
	where
		Self: Sized,
	{
		let mut message_buffer = Bytes::from(packet.into_content());
		let code = GoodbyeCodes::from(message_buffer.get_u8());

		let reason = String::from_utf8(message_buffer.to_vec()).map_err(|e| StealthStreamPacketError::InvalidUtf8 {
			source: e,
			field: "reason".to_string(),
		})?;

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

impl StealthStreamPacketParser for ErrorData {
	fn metadata(&self) -> (FrameOpcodes, Vec<u8>) {
		let length = self.reason.len() + 1;
		let mut array: Vec<u8> = Vec::with_capacity(length);
		array.push(self.code);
		array.extend_from_slice(self.reason.as_bytes());

		(FrameOpcodes::Error, array)
	}

	fn from_packet(packet: StealthStreamPacket) -> Result<Self, StealthStreamPacketError> {
		let mut message_buffer = Bytes::from(packet.content().to_owned());
		let code = message_buffer.get_u8();

		let reason = String::from_utf8(message_buffer.to_vec()).map_err(|e| StealthStreamPacketError::InvalidUtf8 {
			source: e,
			field: "reason".to_string(),
		})?;

		Ok(ErrorData { code, reason })
	}
}

/* Display Implementations */
impl Display for HandshakeData {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(
			f,
			"HandshakeData(version={}, should_compress={}, namespace={}, auth={:?})",
			self.version, self.should_compress, self.namespace, self.auth
		)
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
	pub fn new(version: u8, should_compress: bool, namespace: &str, auth: Option<AuthData>) -> Self {
		let namespace = namespace.to_string();
		Self {
			version,
			should_compress,
			namespace,
			auth,
		}
	}
}

impl GoodbyeData {
	pub fn new(code: GoodbyeCodes, reason: Option<String>) -> Self { Self { code, reason } }
}

impl ErrorData {
	pub fn new(code: u8, reason: String) -> Self { Self { code, reason } }
}
