use std::fmt::Display;

use bytes::{Buf, Bytes};
use derive_getters::Getters;

use super::StealthStreamPacketParser;
use crate::protocol::{framing::FrameOpcodes, StealthStreamPacket, StealthStreamPacketError};

#[derive(Debug, PartialEq, Getters)]
pub struct MessageData {
	is_utf_8: bool,
	content: Vec<u8>,
}

impl MessageData {
	pub fn new(msg: &[u8], is_utf_8: bool) -> Self {
		Self {
			is_utf_8,
			content: msg.to_vec(),
		}
	}
}

impl StealthStreamPacketParser for MessageData {
	fn metadata(&self) -> (FrameOpcodes, Vec<u8>) {
		let bytes = &self.content;
		let mut array = Vec::with_capacity(self.content.len());
		array.push(self.is_utf_8 as u8);
		array.extend_from_slice(bytes);
		(FrameOpcodes::Binary, array)
	}

	fn from_packet(packet: StealthStreamPacket) -> Result<Self, StealthStreamPacketError> {
		let mut message_buffer = Bytes::from(packet.into_content());
		let is_utf_8 = message_buffer.get_u8() == 1;

		Ok(Self {
			is_utf_8,
			content: message_buffer.to_vec(),
		})
	}
}

/* Display Implementations */
impl Display for MessageData {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self.is_utf_8 {
			true => write!(f, "MessageData(\"{}\")", String::from_utf8_lossy(&self.content)),
			false => write!(f, "MessageData({:?})", self.content),
		}
	}
}
