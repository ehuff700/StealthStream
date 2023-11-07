use std::io::Read;

use crate::errors::Error;

/* Opcode Consts */
pub(crate) const HANDSHAKE_OPCODE: u8 = 0x0;
pub(crate) const POKE_OPCODE: u8 = 0x1;
pub(crate) const MESSAGE_OPCODE: u8 = 0x2;
pub(crate) const GOODBYE_OPCODE: u8 = 0x3;

/* Goodbye Codes */
pub(crate) const GRACEFUL: u8 = 100;
pub(crate) const SERVER_RESTARTING: u8 = 101;
pub(crate) const UNKNOWN: u8 = 0;

#[derive(Debug, PartialEq)]
pub enum StealthStreamMessage {
	Handshake,                                              // 0x0
	Poke,                                                   // 0x1
	Message(String),                                        // 0x2
	Goodbye { code: GoodbyeCodes, reason: Option<String> }, // 0x3
}

impl StealthStreamMessage {
	/// Returns the opcode for the corresponding message type.
	///
	/// The opcode is always the first byte of the message and indicates the type of message.
	pub fn opcode(&self) -> u8 {
		match self {
			StealthStreamMessage::Handshake => HANDSHAKE_OPCODE,
			StealthStreamMessage::Poke => POKE_OPCODE,
			StealthStreamMessage::Message(_) => MESSAGE_OPCODE,
			StealthStreamMessage::Goodbye { .. } => GOODBYE_OPCODE,
		}
	}

	/// Converts an opcode byte to a MessageType.
	///
	/// This function will return an `InvalidOpcode` error if the opcode byte was not valid.
	/// For the Message and Goodbye types, it generates an empty [String] / [Option] accordingly, leaving the allocation up to the caller.
	pub fn from_opcode(opcode: u8) -> Result<StealthStreamMessage, Error> {
		match opcode {
			HANDSHAKE_OPCODE => Ok(StealthStreamMessage::Handshake),
			POKE_OPCODE => Ok(StealthStreamMessage::Poke),
			MESSAGE_OPCODE => Ok(StealthStreamMessage::Message(String::new())),
			GOODBYE_OPCODE => Ok(Self::create_goodbye(GoodbyeCodes::Unknown)),
			_ => Err(Error::InvalidOpcode(opcode)),
		}
	}

	/// Formats a [StealthStreamMessage] into a raw [Vec<u8>] used to send over the wire.
	pub fn to_message(&self) -> Vec<u8> {
		let mut message = Vec::new();

		// Add the opcode byte to the message
		message.push(self.opcode());

		// Serialize the message content based on type and calculate length
		let content_bytes = match self {
			StealthStreamMessage::Goodbye { code, reason } => {
				let mut code_bytes = code.to_byte().to_vec();
				let mut reason_bytes = reason.as_ref().map_or_else(Vec::new, |v| v.as_bytes().to_vec());

				code_bytes.append(&mut reason_bytes);
				code_bytes
			},

			StealthStreamMessage::Message(text) => text.as_bytes().to_vec(),
			_ => Vec::new(),
		};

		// Add the length bytes to the message, using two bytes (16 bits) in big-endian format
		let length = content_bytes.len() as u16;
		message.extend_from_slice(&length.to_be_bytes()); // Length prefix

		// Add the actual message content
		message.extend_from_slice(&content_bytes);

		message
	}

	/// Converts a raw message buffer into a `StealthStreamMessage`. This method is only applicable for MessageTypes that have extra data,
	/// such as Goodbye and Message.
	pub fn from_message(self, mut message_buffer: &[u8]) -> Result<Self, Error> {
		match self {
			StealthStreamMessage::Message(_) => Ok(StealthStreamMessage::Message(
				String::from_utf8(message_buffer.to_vec()).unwrap(),
			)),
			StealthStreamMessage::Goodbye { .. } => {
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
			_ => Ok(self),
		}
	}

	/// Utility function to create a [StealthStreamMessage::Goodbye] message without a reason.
	pub fn create_goodbye(code: impl Into<GoodbyeCodes>) -> Self {
		StealthStreamMessage::Goodbye {
			code: code.into(),
			reason: None,
		}
	}

	/// Utility function to create a [StealthStreamMessage::Goodbye] message with a reason
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
			_ => GoodbyeCodes::Unknown,
		}
	}
}

impl GoodbyeCodes {
	pub fn to_byte(&self) -> [u8; 1] {
		[(*self).into()]
	}
}
