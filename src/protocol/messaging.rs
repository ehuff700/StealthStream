#![allow(dead_code)]
use std::{collections::VecDeque, io::Read};

use derive_getters::Getters;
use uuid::Uuid;

use crate::protocol::{
	constants::MAX_COMPLETE_FRAME_LENGTH,
	framing::{FrameFlags, MessageId},
};

use super::{
	constants::{
		GOODBYE_OPCODE, GRACEFUL, HANDSHAKE_OPCODE, HEARTBEAT_OPCODE, INVALID_HANDSHAKE, MESSAGE_OPCODE,
		SERVER_RESTARTING, UNKNOWN,
	},
	framing::FrameOpcodes,
	Handshake, StealthStreamPacket, StealthStreamPacketError,
};

#[derive(Debug, PartialEq, Getters)]
pub struct HandshakeData {
	version: u8,
	session_id: Option<Uuid>,
}

impl HandshakeData {
	pub fn new(version: u8, session_id: Option<Uuid>) -> Self {
		Self { version, session_id }
	}
}

impl StealthStreamPacketParser for HandshakeData {
	fn metadata(&self) -> (FrameOpcodes, Vec<u8>) {
		let mut handshake = vec![self.version];
		let mut session_id = self
			.session_id
			.as_ref()
			.map_or_else(Vec::new, |v| v.as_bytes().to_vec());
		handshake.append(&mut session_id);
		(FrameOpcodes::try_from(HANDSHAKE_OPCODE).unwrap(), handshake)
	}

	fn from_packet(packet: &StealthStreamPacket) -> Result<Self, StealthStreamPacketError> {
		let message_buffer = packet.content();
		let handshake = Handshake::parse_handshake(message_buffer)?;
		Ok(handshake.into())
	}
}

#[derive(Debug, PartialEq, Getters)]
pub struct MessageData {
	is_utf_8: bool,
	content: Vec<u8>,
}

impl MessageData {
	pub fn new(msg: &str, is_utf_8: bool) -> Self {
		Self {
			is_utf_8,
			content: msg.as_bytes().to_vec(),
		}
	}
}
impl StealthStreamPacketParser for MessageData {
	fn metadata(&self) -> (FrameOpcodes, Vec<u8>) {
		let opcode = FrameOpcodes::try_from(MESSAGE_OPCODE).unwrap();
		let bytes = &self.content;
		let mut array = Vec::with_capacity(self.content.len());
		array.extend_from_slice(bytes);
		(opcode, array)
	}
	fn from_packet(packet: &StealthStreamPacket) -> Result<Self, StealthStreamPacketError> {
		let content_bytes = packet.content();
		let is_utf_8 = true; // TODO: do this

		Ok(Self {
			is_utf_8,
			content: content_bytes.to_vec(),
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
		let opcode = FrameOpcodes::try_from(GOODBYE_OPCODE).unwrap();
		let mut code_bytes = self.code.to_byte().to_vec();
		let mut reason_bytes: Vec<u8> = self.reason.as_ref().map_or_else(Vec::new, |v| v.as_bytes().to_vec());

		code_bytes.append(&mut reason_bytes);

		(opcode, code_bytes)
	}

	fn from_packet(packet: &StealthStreamPacket) -> Result<Self, StealthStreamPacketError>
	where
		Self: Sized,
	{
		let mut message_buffer = packet.content();
		let mut goodbye_code = [0u8; 1];
		message_buffer.read_exact(&mut goodbye_code)?;
		let code = GoodbyeCodes::from(goodbye_code[0]);

		let mut reason = vec![0u8; message_buffer.len()];
		message_buffer.read_exact(&mut reason)?;

		let message = if reason.is_empty() {
			GoodbyeData { code, reason: None }
		} else {
			GoodbyeData {
				code,
				reason: Some(String::from_utf8_lossy(&reason).to_string()),
			}
		};

		Ok(message)
	}
}

pub trait StealthStreamPacketParser {
	/// Returns a tuple containing the opcode and serialized content for the packet
	fn metadata(&self) -> (FrameOpcodes, Vec<u8>);

	fn from_packet(packet: &StealthStreamPacket) -> Result<Self, StealthStreamPacketError>
	where
		Self: Sized;

	fn to_packet(&self) -> Vec<StealthStreamPacket> {
		let (opcode, content_bytes) = self.metadata();
		let mut packets: VecDeque<StealthStreamPacket> = VecDeque::with_capacity(1);

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
pub enum StealthStreamMessage {
	Handshake(HandshakeData), // 0x0
	Heartbeat,                // 0x1
	Message(MessageData),     // 0x2
	Goodbye(GoodbyeData),     // 0x3
}

impl StealthStreamMessage {
	/// Returns the opcode for the corresponding message type.
	///
	/// The opcode is always the first byte of the message and indicates the
	/// type of message.
	pub fn opcode(&self) -> u8 {
		match self {
			StealthStreamMessage::Handshake { .. } => HANDSHAKE_OPCODE,
			StealthStreamMessage::Heartbeat => HEARTBEAT_OPCODE,
			StealthStreamMessage::Message(_) => MESSAGE_OPCODE, // FIXME
			StealthStreamMessage::Goodbye { .. } => GOODBYE_OPCODE,
		}
	}

	pub fn from_message(packet: &StealthStreamPacket) -> Result<Self, StealthStreamPacketError> {
		let data = match packet.opcode() {
			HANDSHAKE_OPCODE => StealthStreamMessage::Handshake(HandshakeData::from_packet(packet)?),
			HEARTBEAT_OPCODE => StealthStreamMessage::Heartbeat,
			MESSAGE_OPCODE => StealthStreamMessage::Message(MessageData::from_packet(packet)?),
			GOODBYE_OPCODE => StealthStreamMessage::Goodbye(GoodbyeData::from_packet(packet)?),
			_ => unreachable!(),
		};

		Ok(data)
	}

	pub fn to_message(&self) -> Vec<StealthStreamPacket> {
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
		}
	}

	/// Utility function to create a [StealthStreamMessage::Goodbye] message
	/// without a reason.
	pub fn create_goodbye(code: impl Into<GoodbyeCodes>) -> Self {
		StealthStreamMessage::Goodbye(GoodbyeData {
			code: code.into(),
			reason: None,
		})
	}

	/// Utility function to create a [StealthStreamMessage::Goodbye] message
	/// with a reason
	pub fn create_goodbye_with_reason(code: impl Into<GoodbyeCodes>, reason: &str) -> Self {
		StealthStreamMessage::Goodbye(GoodbyeData {
			code: code.into(),
			reason: Some(reason.to_string()),
		})
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
		match &value[..] {
			[GRACEFUL] => GoodbyeCodes::Graceful,
			[SERVER_RESTARTING] => GoodbyeCodes::ServerRestarting,
			[INVALID_HANDSHAKE] => GoodbyeCodes::InvalidHandshake,
			_ => GoodbyeCodes::Unknown,
		}
	}
}

impl GoodbyeCodes {
	pub fn to_byte(&self) -> [u8; 1] {
		[(*self).into()]
	}
}
