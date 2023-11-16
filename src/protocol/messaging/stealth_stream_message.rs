use std::{collections::VecDeque, fmt::Display};

use async_trait::async_trait;
use uuid::Uuid;

use super::{
	control_messages::{ErrorData, GoodbyeData, HandshakeData},
	data_messages::MessageData,
};
use crate::protocol::{
	constants::{
		ERROR_OPCODE, GOODBYE_OPCODE, GRACEFUL, HANDSHAKE_OPCODE, HEARTBEAT_OPCODE, INVALID_HANDSHAKE,
		MAX_COMPLETE_FRAME_LENGTH, MESSAGE_OPCODE, SERVER_RESTARTING, UNKNOWN,
	},
	framing::{FrameFlags, FrameOpcodes, MessageId},
	StealthStreamPacket, StealthStreamPacketError,
};

#[async_trait]
pub trait StealthStreamPacketParser {
	/// Returns a tuple containing the opcode and serialized content for the
	/// packet
	fn metadata(&self) -> (FrameOpcodes, Vec<u8>);

	/// Parses a packet and returns the corresponding data object.
	async fn from_packet(packet: &StealthStreamPacket) -> Result<Self, StealthStreamPacketError>
	where
		Self: Sized;

	/// Calls the metadata method to get the opcode and serialized content
	/// bytes, and returns a `Vec` of [StealthStreamPacket].
	///
	/// If the packet is a control message, it will return a `Vec` of
	/// [StealthStreamPacket] with a single object, otherwise it will
	/// break the message contents into multiple frames as required.
	fn to_packet(&self) -> Vec<StealthStreamPacket> {
		let (opcode, content_bytes) = self.metadata();
		let mut packets: VecDeque<StealthStreamPacket> = VecDeque::with_capacity(1); // will need at least one

		// TODO: do we implement max length check?

		if opcode.is_data_frame() && content_bytes.len() > MAX_COMPLETE_FRAME_LENGTH as usize {
			let mut slices: VecDeque<Vec<u8>> = content_bytes
				.chunks(MAX_COMPLETE_FRAME_LENGTH as usize)
				.map(|chunk| chunk.to_vec())
				.collect();

			let (beginning_content, end_content) = (slices.pop_front().unwrap(), slices.pop_back().unwrap());
			let message_id = MessageId(Uuid::new_v4());

			packets.push_front(StealthStreamPacket::new_v2(
				opcode,
				FrameFlags::Beginning,
				Some(message_id),
				beginning_content,
			));

			if !slices.is_empty() {
				for slice in slices {
					packets.push_back(StealthStreamPacket::new_v2(
						opcode,
						FrameFlags::Continuation,
						Some(message_id),
						slice,
					));
				}
			}

			packets.push_back(StealthStreamPacket::new_v2(
				opcode,
				FrameFlags::End,
				Some(message_id),
				end_content,
			));
		} else {
			packets.push_back(StealthStreamPacket::new_v2(opcode, FrameFlags::Complete, None, content_bytes));
		}

		packets.into()
	}
}

#[derive(Debug, PartialEq)]
/// An overarching enum repsenting the different types of messages that can be
/// sent over a StealthStream.
pub enum StealthStreamMessage {
	Handshake(HandshakeData), // 0x0
	Heartbeat,                // 0x1
	Message(MessageData),     // 0x2
	Goodbye(GoodbyeData),     // 0x3
	Error(ErrorData),
}

impl StealthStreamMessage {
	/// Converts a `StealthStreamPacket` into a `StealthStreamMessage`
	///
	/// This method will match on the packet opcode and deserialize any needed
	/// data by calling the `from_packet` method on the
	/// [StealthStreamPacketParser] trait.
	pub async fn from_packet(packet: &StealthStreamPacket) -> Result<Self, StealthStreamPacketError> {
		let data = match packet.opcode() {
			HANDSHAKE_OPCODE => StealthStreamMessage::Handshake(HandshakeData::from_packet(packet).await?),
			HEARTBEAT_OPCODE => StealthStreamMessage::Heartbeat,
			MESSAGE_OPCODE => StealthStreamMessage::Message(MessageData::from_packet(packet).await?),
			GOODBYE_OPCODE => StealthStreamMessage::Goodbye(GoodbyeData::from_packet(packet).await?),
			ERROR_OPCODE => StealthStreamMessage::Error(ErrorData::from_packet(packet).await?),
			_ => unreachable!(),
		};

		Ok(data)
	}

	/// Converts a `StealthStreamMessage` into a `StealthStreamPacket`
	///
	/// This method internally calls the `to_packet` method on the
	/// [StealthStreamPacketParser] trait and serializes any needed data.
	pub fn to_packet(&self) -> Vec<StealthStreamPacket> {
		match self {
			StealthStreamMessage::Handshake(handshake) => handshake.to_packet(),
			StealthStreamMessage::Heartbeat => vec![StealthStreamPacket::new_v2(
				FrameOpcodes::try_from(HEARTBEAT_OPCODE).unwrap(),
				FrameFlags::Complete,
				None,
				vec![],
			)],
			StealthStreamMessage::Message(message) => message.to_packet(),
			StealthStreamMessage::Goodbye(goodbye) => goodbye.to_packet(),
			StealthStreamMessage::Error(error) => error.to_packet(),
		}
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
		let mdata = MessageData::new(message.as_bytes(), true);
		Self::Message(mdata)
	}

	/// Utility function which creates a non-utf8 binary message.
	pub fn create_binary_message(message: &[u8]) -> Self {
		let mdata = MessageData::new(message, false);
		Self::Message(mdata)
	}

	/// Utility function which creates a [StealthStreamMessage::Error] message
	pub fn create_error_message(code: u8, reason: &str) -> Self {
		let edata = ErrorData::new(code, reason.to_string());
		Self::Error(edata)
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
