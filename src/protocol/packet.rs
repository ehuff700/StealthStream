use tokio::io::AsyncReadExt;

use super::StealthStreamMessage;

#[derive(Debug)]
pub struct StealthStreamPacket {
	opcode: u8,
	length: u16,
	content: Vec<u8>,
}

impl StealthStreamPacket {
	pub async fn from_stream<T>(stream: &mut T) -> Option<StealthStreamPacket>
	where
		T: AsyncReadExt + Unpin,
	{
		let mut opcode_buffer = [0u8; 1];
		let mut length_buffer = [0u8; 2];

		if stream.read_exact(&mut opcode_buffer).await.is_err() {
			return None;
		}

		if stream.read_exact(&mut length_buffer).await.is_err() {
			return None;
		}

		let length = u16::from_be_bytes(length_buffer);

		let mut message_buffer = vec![0u8; length as usize];
		if stream.read_exact(&mut message_buffer).await.is_err() {
			return None;
		}

		let opcode = opcode_buffer[0];

		let packet = StealthStreamPacket {
			opcode,
			length,
			content: message_buffer,
		};

		Some(packet)
	}

	/* Getters */
	pub fn opcode(&self) -> u8 {
		self.opcode
	}

	pub fn length(&self) -> u16 {
		self.length
	}

	pub fn content(&self) -> &[u8] {
		&self.content
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
