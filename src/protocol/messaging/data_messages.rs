use std::fmt::Display;

use async_trait::async_trait;
use derive_getters::Getters;
use tokio::io::AsyncReadExt;

use super::StealthStreamPacketParser;
use crate::protocol::{
	constants::MESSAGE_OPCODE, framing::FrameOpcodes, StealthStreamPacket, StealthStreamPacketError,
};

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
#[async_trait]
impl StealthStreamPacketParser for MessageData {
	fn metadata(&self) -> (FrameOpcodes, Vec<u8>) {
		let opcode = FrameOpcodes::try_from(MESSAGE_OPCODE).unwrap();
		let bytes = &self.content;
		let mut array = Vec::with_capacity(self.content.len());
		array.push(self.is_utf_8 as u8);
		array.extend_from_slice(bytes);
		(opcode, array)
	}

	async fn from_packet(packet: &StealthStreamPacket) -> Result<Self, StealthStreamPacketError> {
		let mut message_buffer = packet.content();
		let mut is_utf_8 = [0u8; 1];
		message_buffer.read_exact(&mut is_utf_8).await?;

		let is_utf_8 = is_utf_8[0] == 1;

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
