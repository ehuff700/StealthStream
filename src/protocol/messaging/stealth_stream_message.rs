use std::fmt::Display;

use super::{
	control::{ErrorData, GoodbyeData, HandshakeData},
	data::{AcknowledgeData, MessageData},
	StealthStreamPacketParser,
};
use crate::protocol::{
	constants::{
		ACKNOWLEDGEMENT_OPCODE, ERROR_OPCODE, GOODBYE_OPCODE, GRACEFUL, HANDSHAKE_OPCODE, HEARTBEAT_OPCODE,
		INVALID_HANDSHAKE, MESSAGE_OPCODE, SERVER_RESTARTING, UNKNOWN,
	},
	framing::{FrameFlags, FrameOpcodes},
	StealthStreamPacket, StealthStreamPacketError,
};

#[derive(Debug, PartialEq)]
/// An overarching enum representing the different types of messages that can be
/// sent over a StealthStream.
pub enum StealthStreamMessage {
	Handshake(HandshakeData),
	Acknowledge(AcknowledgeData),
	Heartbeat,
	Message(MessageData),
	Goodbye(GoodbyeData),
	Error(ErrorData),
}

impl StealthStreamMessage {
	/// Converts a `StealthStreamPacket` into a `StealthStreamMessage`
	pub async fn from_packet(packet: StealthStreamPacket) -> Result<Self, StealthStreamPacketError> {
		let data = match packet.opcode() {
			HANDSHAKE_OPCODE => StealthStreamMessage::Handshake(HandshakeData::from_packet(packet)?),
			HEARTBEAT_OPCODE => StealthStreamMessage::Heartbeat,
			MESSAGE_OPCODE => StealthStreamMessage::Message(MessageData::from_packet(packet)?),
			GOODBYE_OPCODE => StealthStreamMessage::Goodbye(GoodbyeData::from_packet(packet)?),
			ERROR_OPCODE => StealthStreamMessage::Error(ErrorData::from_packet(packet)?),
			ACKNOWLEDGEMENT_OPCODE => StealthStreamMessage::Acknowledge(AcknowledgeData::from_packet(packet)?),
			_ => unreachable!(),
		};

		Ok(data)
	}

	/// Converts a `StealthStreamMessage` into a `StealthStreamPacket`
	///
	/// This method internally calls the `to_packet` method on the
	/// [StealthStreamPacketParser] trait and serializes any needed data.
	pub fn to_packet(&self) -> Result<Vec<StealthStreamPacket>, StealthStreamPacketError> {
		let packet = match self {
			StealthStreamMessage::Handshake(handshake) => handshake.to_packet()?,
			StealthStreamMessage::Heartbeat => vec![StealthStreamPacket::new_v2(
				FrameOpcodes::try_from(HEARTBEAT_OPCODE).unwrap(),
				FrameFlags::Complete,
				None,
				vec![],
			)],
			StealthStreamMessage::Message(message) => message.to_packet()?,
			StealthStreamMessage::Goodbye(goodbye) => goodbye.to_packet()?,
			StealthStreamMessage::Error(error) => error.to_packet()?,
			StealthStreamMessage::Acknowledge(ack_data) => ack_data.to_packet()?,
		};

		Ok(packet)
	}

	/// Utility function to create a [StealthStreamMessage::Goodbye] message
	/// without a reason.
	pub fn create_goodbye(code: impl Into<GoodbyeCodes>) -> Self {
		StealthStreamMessage::Goodbye(GoodbyeData::new(code.into(), None))
	}

	/// Utility function to create a [StealthStreamMessage::Goodbye] message
	/// with a reason
	pub fn create_goodbye_with_reason(code: impl Into<GoodbyeCodes>, reason: &str) -> Self {
		StealthStreamMessage::Goodbye(GoodbyeData::new(code.into(), Some(reason.to_string())))
	}

	/// Utility function which creates a utf-8 binary message from a string.
	pub fn create_utf8_message(message: &str) -> Self {
		let mdata = MessageData::new(message.as_bytes(), true, false);
		Self::Message(mdata)
	}

	/// Utility function which creates a non-utf8 binary message.
	pub fn create_binary_message(message: &[u8]) -> Self {
		let mdata = MessageData::new(message, false, false);
		Self::Message(mdata)
	}

	/// Utility function which creates a [StealthStreamMessage::Error] message
	pub fn create_error_message(code: u8, reason: &str) -> Self {
		let edata = ErrorData::new(code, reason.to_string());
		Self::Error(edata)
	}

	/// Determines whether or not the boolean needs an acknowledgement.
	pub fn needs_ack(&self) -> bool {
		match self {
			StealthStreamMessage::Message(data) => data.ack_id().is_some(),
			_ => false,
		}
	}
}

impl Display for StealthStreamMessage {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			StealthStreamMessage::Handshake(handshake) => handshake.fmt(f),
			StealthStreamMessage::Heartbeat => write!(f, "Heartbeat"),
			StealthStreamMessage::Message(message) => message.fmt(f),
			StealthStreamMessage::Goodbye(goodbye) => goodbye.fmt(f),
			StealthStreamMessage::Error(error) => error.fmt(f),
			StealthStreamMessage::Acknowledge(ack) => ack.fmt(f),
		}
	}
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum GoodbyeCodes {
	/// Indicates a graceful closure initiated by the client or server
	Graceful = GRACEFUL,
	/// Sent by the server to indicate a server restart
	ServerRestarting = SERVER_RESTARTING,
	/// Sent by the server if the handshake failed / was invalid
	InvalidHandshake = INVALID_HANDSHAKE,
	/// Fallback code
	Unknown = UNKNOWN,
}

impl From<u8> for GoodbyeCodes {
	fn from(value: u8) -> Self {
		match value {
			GRACEFUL => GoodbyeCodes::Graceful,
			SERVER_RESTARTING => GoodbyeCodes::ServerRestarting,
			INVALID_HANDSHAKE => GoodbyeCodes::InvalidHandshake,
			_ => GoodbyeCodes::Unknown,
		}
	}
}
