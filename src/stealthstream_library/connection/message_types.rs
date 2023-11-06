use crate::errors::Error;

pub const HANDSHAKE_OPCODE: u8 = 0x0;
pub const POKE_OPCODE: u8 = 0x1;
pub const MESSAGE_OPCODE: u8 = 0x2;
pub const GOODBYE_OPCODE: u8 = 0x3;

#[derive(Debug)]
pub enum StealthStreamMessage {
	Handshake,               // 0x0
	Poke,                    // 0x1
	Message(String),         // 0x2
	Goodbye(Option<String>), // 0x3
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
			StealthStreamMessage::Goodbye(_) => GOODBYE_OPCODE,
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
			GOODBYE_OPCODE => Ok(StealthStreamMessage::Goodbye(None)),
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
			StealthStreamMessage::Poke => Vec::new(),
			StealthStreamMessage::Goodbye(reason) => reason.as_ref().map_or_else(Vec::new, |r| r.as_bytes().to_vec()),
			StealthStreamMessage::Message(text) => text.as_bytes().to_vec(),
			_ => unreachable!(),
		};

		// Add the length bytes to the message, using two bytes (16 bits) in big-endian format
		let length = content_bytes.len() as u16;
		message.extend_from_slice(&length.to_be_bytes()); // Length prefix

		// Add the actual message content
		message.extend_from_slice(&content_bytes);

		message
	}
}
