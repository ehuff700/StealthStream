use std::{io::ErrorKind, time::Duration};

#[cfg(unix)]
use arbitrary::Arbitrary;
use thiserror::Error;
use tokio::{io::AsyncReadExt, time::timeout};

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
	#[error("message content read timed out, faulty length prefix?")]
	ContentReadTimedOut,
	#[error("error reading from the underlying stream: {0}")]
	StreamError(#[from] std::io::Error),
	#[error("the stream has been closed")]
	StreamClosed,
}

#[cfg(target_os = "unix")]
#[derive(Debug, Arbitrary)]
pub struct StealthStreamPacket {
	opcode: u8,
	length: u16,
	content: Vec<u8>,
}

#[cfg(not(target_os = "unix"))]
#[derive(Debug)]
pub struct StealthStreamPacket {
	opcode: u8,
	length: u16,
	content: Vec<u8>,
}

impl StealthStreamPacket {
	#[cfg(test)]
	/// Used only internally for testing purposes.
	pub(crate) fn new(opcode: u8, length: u16, content: Vec<u8>) -> Self {
		Self {
			opcode,
			length,
			content,
		}
	}

	pub async fn from_stream<T>(stream: &mut T) -> Result<StealthStreamPacket, Error>
	where
		T: AsyncReadExt + Unpin + Send + Sync,
	{
		let mut opcode_buffer = [0u8; 1]; // set a hard buffer of one byte for the opcode
		let mut length_buffer = [0u8; 2]; // set a hard buffer of two bytes for the length prefix

		// Read Opcode Byte
		stream.read_exact(&mut opcode_buffer).await.map_err(|e| {
			if e.kind() == ErrorKind::UnexpectedEof {
				StealthStreamPacketErrors::StreamClosed
			} else {
				StealthStreamPacketErrors::StreamError(e)
			}
		})?;

		let opcode = opcode_buffer[0];

		if !Self::is_opcode_valid(opcode) {
			return Err(StealthStreamPacketErrors::InvalidOpcodeByte(opcode))?;
		}

		// Read Length Prefix
		timeout(Duration::from_millis(500), stream.read_exact(&mut length_buffer)) //TODO: make timeout configurable
			.await
			.map_err(|_| StealthStreamPacketErrors::LengthPrefixMissing)?
			.map_err(|e| {
				if e.kind() == ErrorKind::UnexpectedEof {
					StealthStreamPacketErrors::StreamClosed
				} else {
					StealthStreamPacketErrors::StreamError(e)
				}
			})?;

		let length = u16::from_be_bytes(length_buffer);

		// TODO: implement max length and message fragmenting
		// result.map_err(|_| StealthStreamPacketErrors::LengthOutOfBounds(length))?;

		let mut message_buffer = vec![0u8; length as usize];
		timeout(Duration::from_millis(500), stream.read_exact(&mut message_buffer))
			.await
			.map_err(|_| StealthStreamPacketErrors::ContentReadTimedOut)?
			.map_err(|e| {
				if e.kind() == ErrorKind::UnexpectedEof {
					StealthStreamPacketErrors::StreamClosed
				} else {
					StealthStreamPacketErrors::StreamError(e)
				}
			})?;

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
