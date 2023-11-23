use std::fmt::Display;

use bytes::{Buf, Bytes};
use derive_getters::Getters;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::StealthStreamPacketParser;
use crate::protocol::{framing::FrameOpcodes, StealthStreamPacket, StealthStreamPacketError};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct AcknowledgeData {
	pub(crate) ack_id: Uuid,
	pub(crate) content: Vec<u8>,
}

impl StealthStreamPacketParser for AcknowledgeData {
	fn metadata(&self) -> (FrameOpcodes, Vec<u8>) {
		let mut buf = Vec::new();
		buf.extend_from_slice(&self.ack_id.into_bytes());
		buf.extend_from_slice(&self.content);
		(FrameOpcodes::Acknowledgement, buf)
	}

	fn from_packet(packet: StealthStreamPacket) -> Result<Self, StealthStreamPacketError> {
		let mut reader = Bytes::from(packet.into_content());
		let ack_id = Uuid::from_u128(reader.get_u128());
		let content = reader.to_vec();

		let ack_data = Self { ack_id, content };
		Ok(ack_data)
	}
}

#[derive(Debug, PartialEq, Getters)]
pub struct MessageData {
	is_utf_8: bool,
	content: Vec<u8>,
	ack_id: Option<Uuid>,
}

impl StealthStreamPacketParser for MessageData {
	fn metadata(&self) -> (FrameOpcodes, Vec<u8>) {
		let bytes = &self.content;
		let mut array = Vec::with_capacity(self.content.len());
		array.push(self.is_utf_8 as u8);

		if let Some(uuid) = self.ack_id.as_ref() {
			array.push(1); // 1 means we have an ack_id
			array.extend_from_slice(uuid.as_bytes())
		} else {
			array.push(0); // 0 means we don't have an ack_id
		}
		array.extend_from_slice(bytes);
		(FrameOpcodes::Binary, array)
	}

	fn from_packet(packet: StealthStreamPacket) -> Result<Self, StealthStreamPacketError> {
		let mut message_buffer = Bytes::from(packet.into_content());
		let potential_is_utf_8 = message_buffer.get_u8();

		let is_utf_8 = match potential_is_utf_8 {
			1 => true,
			0 => false,
			_ => return Err(StealthStreamPacketError::ArbitraryBytes([potential_is_utf_8].to_vec())),
		};

		let has_slice = message_buffer.get_u8();

		let ack_id = match has_slice {
			0 => None,
			1 => Some(Uuid::from_u128(message_buffer.get_u128())),
			_ => return Err(StealthStreamPacketError::ArbitraryBytes([has_slice].to_vec())),
		};

		Ok(Self {
			is_utf_8,
			content: message_buffer.to_vec(),
			ack_id,
		})
	}
}

/* Display Implementations */
impl Display for MessageData {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self.is_utf_8 {
			true => write!(f, "MessageData(\"{}\")", String::from_utf8_lossy(&self.content)),
			false => write!(f, "MessageData({:#?})", self.content),
		}
	}
}

impl Display for AcknowledgeData {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "AcknowledgeData(ack_id={:#?})", self.ack_id)
	}
}

/* New Implementations */
impl MessageData {
	pub fn new(msg: &[u8], is_utf_8: bool, should_ack: bool) -> Self {
		let ack_id = match should_ack {
			true => Some(Uuid::new_v4()),
			false => None,
		};

		Self {
			is_utf_8,
			ack_id,
			content: msg.to_vec(),
		}
	}
}

impl AcknowledgeData {
	pub fn new<T>(ack_id: Uuid, content: T) -> Self
	where
		T: Serialize,
	{
		Self {
			ack_id,
			content: Self::serialize(content).unwrap(),
		}
	}

	fn serialize<T>(content: T) -> Result<Vec<u8>, rmp_serde::encode::Error>
	where
		T: Serialize,
	{
		rmp_serde::to_vec(&content)
	}

	//TODO: make better error type
	pub fn deserialize<T>(&self) -> Result<T, rmp_serde::decode::Error>
	where
		T: for<'a> Deserialize<'a>,
	{
		rmp_serde::from_slice(&self.content)
	}
}
