use thiserror::Error;
use tokio::io::AsyncReadExt;

use super::{
	constants::{GOODBYE_OPCODE, HANDSHAKE_OPCODE, MESSAGE_OPCODE, POKE_OPCODE},
	StealthStreamMessage,
};
use crate::errors::Error;

#[derive(Debug, Error)]
pub enum StealthStreamPacketErrors {
	#[error("packet missing opcode byte")]
	OpcodeByteMissing,
	#[error("packet contains invalid opco byte: {0}")]
	InvalidOpcodeByte(u8),
	#[error("packet missing length prefix")]
	LengthPrefixMissing,
	#[error("packet length out of bounds: {0}")]
	LengthOutOfBounds(usize), // TODO: implement max length
}

#[derive(Debug)]
pub struct StealthStreamPacket {
	opcode: u8,
	length: u16,
	content: Vec<u8>,
}

impl StealthStreamPacket {
	pub async fn from_stream<T>(stream: &mut T) -> Result<StealthStreamPacket, Error>
	where
		T: AsyncReadExt + Unpin + Send + Sync,
	{
		let mut opcode_buffer = [0u8; 1];
		let mut length_buffer = [0u8; 2];

		stream
			.read_exact(&mut opcode_buffer)
			.await
			.map_err(|_| StealthStreamPacketErrors::OpcodeByteMissing)?;

		stream
			.read_exact(&mut length_buffer)
			.await
			.map_err(|_| StealthStreamPacketErrors::LengthPrefixMissing)?;

		let length = u16::from_be_bytes(length_buffer);

		// TODO: implement max length and message fragmenting
		// result.map_err(|_| StealthStreamPacketErrors::LengthOutOfBounds(length))?;

		let mut message_buffer = vec![0u8; length as usize];
		stream.read_exact(&mut message_buffer).await?;

		let opcode = opcode_buffer[0];
		if !Self::is_opcode_valid(opcode) {
			return Err(StealthStreamPacketErrors::InvalidOpcodeByte(opcode))?;
		}

		let packet = StealthStreamPacket {
			opcode,
			length,
			content: message_buffer,
		};

		Ok(packet)
	}

	/* TODO: implement cryptography 😎
	pub fn decrypt(&self) -> ! { todo!() }

	pub fn encrypt(&self) -> ! { todo!() } */

	/* Getters */
	pub fn opcode(&self) -> u8 { self.opcode }

	pub fn length(&self) -> u16 { self.length }

	pub fn content(&self) -> &[u8] { &self.content }

	/// Determines whether or not the provided opcode parsed from the stream is
	/// valid, otherwise returns an InvalidOpcode error.
	fn is_opcode_valid(opcode: u8) -> bool {
		opcode == HANDSHAKE_OPCODE || opcode == MESSAGE_OPCODE || opcode == POKE_OPCODE || opcode == GOODBYE_OPCODE
		// TODO: find more scalable solution
	}
}

impl From<StealthStreamPacket> for Vec<u8> {
	fn from(packet: StealthStreamPacket) -> Self {
		let mut content: Vec<u8> =
			Vec::with_capacity(packet.opcode as usize + packet.length as usize + packet.content.len());
		content.push(packet.opcode);
		content.extend_from_slice(&packet.length.to_be_bytes());
		content.extend_from_slice(&packet.content);
		content
	}
}

impl From<StealthStreamMessage> for StealthStreamPacket {
	fn from(message: StealthStreamMessage) -> Self {
		let opcode = message.opcode();

		// Serialize the message content based on type and calculate length
		let content = message.serialize_content_bytes();
		let length = content.len() as u16;

		StealthStreamPacket {
			opcode,
			length,
			content,
		}
	}
}

pub trait PacketContent {}
