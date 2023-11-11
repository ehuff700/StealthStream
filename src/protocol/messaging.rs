use std::io::Read;

use uuid::Uuid;

use super::{
	constants::{
		GOODBYE_OPCODE, GRACEFUL, HANDSHAKE_OPCODE, INVALID_HANDSHAKE, MESSAGE_OPCODE, POKE_OPCODE, SERVER_RESTARTING,
		UNKNOWN,
	},
	Handshake, StealthStreamPacket,
};
use crate::errors::{Error, ServerErrors};

#[derive(Debug, PartialEq)]
pub enum StealthStreamMessage {
	Handshake { version: u8, session_id: Option<Uuid> },    // 0x0
	Poke,                                                   // 0x1
	Message(String),                                        // 0x2
	Goodbye { code: GoodbyeCodes, reason: Option<String> }, // 0x3
}

impl StealthStreamMessage {
	/// Returns the opcode for the corresponding message type.
	///
	/// The opcode is always the first byte of the message and indicates the
	/// type of message.
	pub fn opcode(&self) -> u8 {
		match self {
			StealthStreamMessage::Handshake { .. } => HANDSHAKE_OPCODE,
			StealthStreamMessage::Poke => POKE_OPCODE,
			StealthStreamMessage::Message(_) => MESSAGE_OPCODE,
			StealthStreamMessage::Goodbye { .. } => GOODBYE_OPCODE,
		}
	}

	/// Serializes the message content into bytes. This is only applicable to
	/// the opcodes that have actual content
	pub fn serialize_content_bytes(&self) -> Vec<u8> {
		match self {
			StealthStreamMessage::Goodbye { code, reason } => {
				let mut code_bytes = code.to_byte().to_vec();
				let mut reason_bytes = reason.as_ref().map_or_else(Vec::new, |v| v.as_bytes().to_vec());

				code_bytes.append(&mut reason_bytes);
				code_bytes
			},

			StealthStreamMessage::Message(text) => {
				let bytes = text.as_bytes();
				let mut array = Vec::with_capacity(bytes.len());
				array.extend(bytes);
				array
			},
			StealthStreamMessage::Handshake { version, session_id } => {
				let mut handshake = vec![*version];
				let mut session_id = session_id.as_ref().map_or_else(Vec::new, |v| v.as_bytes().to_vec());
				handshake.append(&mut session_id);
				handshake
			},
			_ => Vec::new(),
		}
	}

	/// Converts a raw message buffer into a `StealthStreamMessage`.
	///
	/// This method handles the deserialization of messages with extra content,
	/// such as Message, Goodbye, Handshake, etc. If the provided opcode byte
	/// was not valid, this method will return an [Error::InvalidOpcode] error.
	pub fn from_message(packet: &StealthStreamPacket) -> Result<Self, Error> {
		let mut message_buffer = packet.content();
		let opcode_byte = packet.opcode();

		match opcode_byte {
			HANDSHAKE_OPCODE => {
				let handshake = Handshake::parse_handshake(message_buffer).map_err(ServerErrors::from)?;
				Ok(handshake.into())
			},
			MESSAGE_OPCODE => Ok(StealthStreamMessage::Message(
				String::from_utf8(message_buffer.to_vec()).unwrap(),
			)),
			GOODBYE_OPCODE => {
				let mut goodbye_code = [0u8; 1];
				message_buffer.read_exact(&mut goodbye_code)?;
				let code = GoodbyeCodes::from(goodbye_code[0]);

				let mut reason = vec![0u8; message_buffer.len()];
				message_buffer.read_exact(&mut reason)?;

				let message = if reason.is_empty() {
					StealthStreamMessage::create_goodbye(code)
				} else {
					StealthStreamMessage::create_goodbye_with_reason(code, &String::from_utf8_lossy(&reason))
				};

				Ok(message)
			},
			POKE_OPCODE => Ok(StealthStreamMessage::Poke),
			_ => unreachable!(), // TODO: find more scalable solution, see is_opcode_valid in stream.rs
		}
	}

	/// Utility function to create a [StealthStreamMessage::Goodbye] message
	/// without a reason.
	pub fn create_goodbye(code: impl Into<GoodbyeCodes>) -> Self {
		StealthStreamMessage::Goodbye {
			code: code.into(),
			reason: None,
		}
	}

	/// Utility function to create a [StealthStreamMessage::Goodbye] message
	/// with a reason
	pub fn create_goodbye_with_reason(code: impl Into<GoodbyeCodes>, reason: &str) -> Self {
		StealthStreamMessage::Goodbye {
			code: code.into(),
			reason: Some(reason.to_string()),
		}
	}
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GoodbyeCodes {
	/// Indicates a graceful closure initiated by the client or server
	Graceful,
	/// Sent by the server to indicate a server restart
	ServerRestarting,
	/// Sent by the server if the handshake failed / was invalid
	InvalidHandshake,
	/// Fallback code
	Unknown,
}

impl From<u8> for GoodbyeCodes {
	fn from(value: u8) -> Self {
		match value {
			GRACEFUL => GoodbyeCodes::Graceful,
			SERVER_RESTARTING => GoodbyeCodes::ServerRestarting,
			_ => GoodbyeCodes::Unknown,
		}
	}
}

impl From<GoodbyeCodes> for u8 {
	fn from(value: GoodbyeCodes) -> Self {
		match value {
			GoodbyeCodes::Graceful => GRACEFUL,
			GoodbyeCodes::InvalidHandshake => INVALID_HANDSHAKE,
			GoodbyeCodes::ServerRestarting => SERVER_RESTARTING,
			GoodbyeCodes::Unknown => UNKNOWN,
		}
	}
}

impl From<Vec<u8>> for GoodbyeCodes {
	fn from(value: Vec<u8>) -> Self {
		match value.as_slice() {
			[GRACEFUL] => GoodbyeCodes::Graceful,
			[SERVER_RESTARTING] => GoodbyeCodes::ServerRestarting,
			[INVALID_HANDSHAKE] => GoodbyeCodes::InvalidHandshake,
			_ => GoodbyeCodes::Unknown,
		}
	}
}

impl GoodbyeCodes {
	pub fn to_byte(&self) -> [u8; 1] { [(*self).into()] }
}
