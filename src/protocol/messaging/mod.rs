pub mod control;
pub mod data;
mod stealth_stream_message;

use std::collections::VecDeque;

use uuid::Uuid;

pub use self::stealth_stream_message::*;
use super::{
	constants::{MAX_COMPLETE_FRAME_LENGTH, MAX_MESSAGE_LENGTH},
	framing::{FrameFlags, FrameIdentifier, FrameOpcodes},
	StealthStreamPacket, StealthStreamPacketError,
};

pub trait StealthStreamPacketParser {
	/// Returns a tuple containing the opcode and serialized content for the
	/// packet
	fn metadata(&self) -> (FrameOpcodes, Vec<u8>);

	/// Parses a packet and returns the corresponding data object.
	fn from_packet(packet: StealthStreamPacket) -> Result<Self, StealthStreamPacketError>
	where
		Self: Sized;

	/// Calls the metadata method to get the opcode and serialized content
	/// bytes, and returns a `Vec` of [StealthStreamPacket].
	///
	/// If the packet is a control message, it will return a `Vec` of
	/// [StealthStreamPacket] with a single object, otherwise it will
	/// break the message contents into multiple frames as required.
	///
	/// # Returns
	/// This method will return a Result<E> if the packet content length is
	/// greater than the MAX_COMPLETE_FRAME_LENGTH.
	fn to_packet(&self) -> Result<Vec<StealthStreamPacket>, StealthStreamPacketError> {
		let (opcode, content_bytes) = self.metadata();
		let mut packets: VecDeque<StealthStreamPacket> = VecDeque::with_capacity(1); // will need at least one

		// TODO: do we implement max length check?
		if content_bytes.len() > MAX_MESSAGE_LENGTH as usize {
			return Err(StealthStreamPacketError::MessageContentsOverflowed(content_bytes.len()));
		}

		if opcode.is_data_frame() && content_bytes.len() > MAX_COMPLETE_FRAME_LENGTH as usize {
			let mut slices: VecDeque<Vec<u8>> = content_bytes
				.chunks(MAX_COMPLETE_FRAME_LENGTH as usize)
				.map(|chunk| chunk.to_vec())
				.collect();

			let (beginning_content, end_content) = (slices.pop_front().unwrap(), slices.pop_back().unwrap());
			let message_id = FrameIdentifier(Uuid::new_v4());

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

		Ok(packets.into())
	}
}
