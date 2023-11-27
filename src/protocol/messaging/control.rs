use std::{collections::HashMap, fmt::Display};

use bytes::{Buf, Bytes};
use derive_getters::Getters;

use super::{GoodbyeCodes, StealthStreamPacketParser};
use crate::protocol::{
	constants::SUPPORTED_VERSIONS, framing::FrameOpcodes, HandshakeErrors, StealthStreamPacket,
	StealthStreamPacketError,
};

#[derive(Debug, Getters, PartialEq, Clone)]
pub struct AuthData {
	username: String,
	password: String,
}

#[derive(Debug, PartialEq, Getters)]
pub struct HandshakeData {
	pub(crate) version: u8,
	pub(crate) should_compress: bool,
	pub(crate) namespace: String,
	pub(crate) auth: Option<AuthData>,
	pub(crate) headers: HashMap<String, String>,
}

impl StealthStreamPacketParser for HandshakeData {
	fn metadata(&self) -> (FrameOpcodes, Vec<u8>) {
		let mut handshake = Vec::new();
		handshake.push(self.version);
		handshake.push(self.should_compress as u8);

		// Headers
		if !&self.headers.is_empty() {
			handshake.push(1); // Headers present
			let headers_bytes = serde_json::to_string(&self.headers).unwrap();
			let headers_len = headers_bytes.len() as u16;

			handshake.extend(headers_len.to_be_bytes());
			handshake.extend(headers_bytes.as_bytes());
		} else {
			handshake.push(0); // Headers not present
		}

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
				let password_bytes = auth.password.as_bytes();
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
		let headers = if bytes.get_u8() == 1 {
			let headers_len = bytes.get_u16() as usize;
			let slice = bytes.copy_to_bytes(headers_len);
			Some(
				serde_json::from_slice::<HashMap<String, String>>(&slice.to_vec())
					.map_err(|_| StealthStreamPacketError::InvalidHeaders)?,
			)
		} else {
			None
		}
		.unwrap_or_default();

		let namespace_len = bytes.get_u16() as usize;
		let namespace = String::from_utf8(bytes.copy_to_bytes(namespace_len).to_vec()).map_err(|e| {
			StealthStreamPacketError::InvalidUtf8 {
				source: e,
				field: "namespace".to_string(),
			}
		})?;

		let auth = if bytes.get_u8() == 1 {
			let username_len = bytes.get_u16() as usize;
			let username = String::from_utf8(bytes.copy_to_bytes(username_len).to_vec()).map_err(|e| {
				StealthStreamPacketError::InvalidUtf8 {
					source: e,
					field: "username".to_string(),
				}
			})?;

			let password_len = bytes.get_u16() as usize;
			let password = String::from_utf8(bytes.copy_to_bytes(password_len).to_vec()).map_err(|e| {
				StealthStreamPacketError::InvalidUtf8 {
					source: e,
					field: "password".to_string(),
				}
			})?;

			Some(AuthData { username, password })
		} else {
			None
		};

		Ok(Self {
			version,
			should_compress,
			namespace,
			headers,
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
impl AuthData {
	/// Note: For security purposes, the password should be hashed before being
	/// passed to this function. The hash can then be verified on the server
	/// side via the auth callback.
	pub fn new(username: impl Into<String>, hashed_password: impl Into<String>) -> Self {
		let (username, hashed_password) = (username.into(), hashed_password.into());

		Self {
			username,
			password: hashed_password,
		}
	}
}

impl HandshakeData {
	pub fn new(
		version: u8, should_compress: bool, headers: Option<HashMap<String, String>>, namespace: &str,
		auth: Option<AuthData>,
	) -> Self {
		let namespace = namespace.to_string();
		Self {
			version,
			should_compress,
			headers: headers.unwrap_or_default(),
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
