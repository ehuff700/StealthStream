use bytes::{Buf, BytesMut};
use tracing::{debug, error};
use uuid::Uuid;

use super::{
	constants::{
		ACKNOWLEDGEMENT_OPCODE, BEGINNING_FLAG, COMPLETION_FLAG, CONTINUATION_FLAG, END_FLAG, ERROR_OPCODE,
		GOODBYE_OPCODE, HANDSHAKE_OPCODE, HEARTBEAT_OPCODE, MESSAGE_OPCODE,
	},
	StealthStreamPacketError,
};
use crate::protocol::constants::{MAX_COMPLETE_FRAME_LENGTH, MAX_MESSAGE_LENGTH};

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
/// Frame Opcodes represent the different types of messages that can be sent by
/// the client or server. They are the first byte of a
/// [StealthStreamPacket](crate::protocol::StealthStreamPacket) and can be
/// either a control or a data frame.
///
/// Control frames **DO NOT** support fragmentation. Data frames **DO** support
/// fragmentation.
pub enum FrameOpcodes {
	Handshake = HANDSHAKE_OPCODE,
	Heartbeat = HEARTBEAT_OPCODE,
	Goodbye = GOODBYE_OPCODE,
	Binary = MESSAGE_OPCODE,
	Acknowledgement = ACKNOWLEDGEMENT_OPCODE,
	Error = ERROR_OPCODE,
}

impl FrameOpcodes {
	/// Indicates whether the frame opcode is a control frame.
	pub fn is_control_frame(&self) -> bool {
		matches!(self, FrameOpcodes::Handshake | FrameOpcodes::Heartbeat | FrameOpcodes::Goodbye)
	}

	/// Indicates whether the frame opcode is a data frame.
	pub fn is_data_frame(&self) -> bool {
		matches!(self, FrameOpcodes::Binary | FrameOpcodes::Acknowledgement | FrameOpcodes::Error)
	}
}

impl TryFrom<u8> for FrameOpcodes {
	type Error = StealthStreamPacketError;

	fn try_from(opcode: u8) -> Result<Self, <FrameOpcodes as TryFrom<u8>>::Error> {
		match opcode {
			HANDSHAKE_OPCODE => Ok(FrameOpcodes::Handshake),
			HEARTBEAT_OPCODE => Ok(FrameOpcodes::Heartbeat),
			GOODBYE_OPCODE => Ok(FrameOpcodes::Goodbye),
			MESSAGE_OPCODE => Ok(FrameOpcodes::Binary),
			ACKNOWLEDGEMENT_OPCODE => Ok(FrameOpcodes::Acknowledgement),
			ERROR_OPCODE => Ok(FrameOpcodes::Error),
			_ => Err(StealthStreamPacketError::InvalidOpcodeByte(opcode)),
		}
	}
}

#[derive(Debug, Clone)]
#[repr(u8)]
/// Frame Flags represent the different states of a data frame.
///
/// **Complete** = No more related frames will be sent. This is considered a
/// complete message.
///
/// **Beginning** = This frame is the beginning of a new message. When received,
/// the caller should be prepared to receive additional contiuation frames, and
/// append the message contents.
///
/// **Continuation** = This frame is a continuation of the previous message,
/// however the message is not yet complete
///
/// **End** = This frame is the end of the previous message, and indicates a
/// complete message.
pub enum FrameFlags {
	Complete = COMPLETION_FLAG,
	Beginning = BEGINNING_FLAG,
	Continuation = CONTINUATION_FLAG,
	End = END_FLAG,
}

impl FrameFlags {
	/// Validates whether or not the parsed flags are valid for the given
	/// opcode.
	fn validate_flag_for_opcode(flag: &FrameFlags, opcode: &FrameOpcodes) -> Result<(), StealthStreamPacketError> {
		// If the opcode is a control frame and the flag is not Complete
		if opcode.is_control_frame() && !matches!(flag, FrameFlags::Complete) {
			return Err(StealthStreamPacketError::InvalidFlagForOpcode {
				flag: flag.clone(),
				opcode: *opcode,
			});
		}
		Ok(())
	}

	/// Custom implementation of the TryFrom trait for the FrameFlags enum.
	pub fn try_from(flag: u8, opcode: &FrameOpcodes) -> Result<Self, StealthStreamPacketError> {
		let flag = match flag {
			COMPLETION_FLAG => Ok(FrameFlags::Complete),
			BEGINNING_FLAG => Ok(FrameFlags::Beginning),
			CONTINUATION_FLAG => Ok(FrameFlags::Continuation),
			END_FLAG => Ok(FrameFlags::End),
			_ => Err(StealthStreamPacketError::InvalidFlagByte(flag)),
		}?;

		Self::validate_flag_for_opcode(&flag, opcode)?;

		Ok(flag)
	}

	/// Custom implementation of `Into<u8>` for `FrameFlags`.
	pub fn into(self) -> Result<u8, StealthStreamPacketError> {
		match self {
			FrameFlags::Complete => Ok(COMPLETION_FLAG),
			FrameFlags::Beginning => Ok(BEGINNING_FLAG),
			FrameFlags::Continuation => Ok(CONTINUATION_FLAG),
			FrameFlags::End => Ok(END_FLAG),
		}
	}
}
#[derive(Debug)]
/// The length prefix is a 4 byte long u32 value representing the number of
/// bytes to be read from the stream to compose the frame/message.
///
/// For frames that are NOT [FrameFlags::Beginning], the maximum length prefix
/// is [MAX_COMPLETE_FRAME_LENGTH]. If the frame is a [FrameFlags::Beginning],
/// the maximum length prefix is [MAX_MESSAGE_LENGTH].
pub struct LengthPrefix(pub(crate) u32);
impl LengthPrefix {
	pub fn try_from_v2(src: &mut BytesMut) -> Result<Self, StealthStreamPacketError> {
		let length_prefix = u32::from_le_bytes([src[0], src[1], src[2], src[3]]);

		debug!("what is length prefix: {:?}", length_prefix);
		if length_prefix > MAX_COMPLETE_FRAME_LENGTH {
			src.advance(src.len());
			Err(StealthStreamPacketError::LengthOutOfBounds(length_prefix as usize))
		} else {
			Ok(LengthPrefix(length_prefix))
		}
	}

	/// Creates a new LengthPrefix from a [buffer](BytesMut).
	///
	/// This method also accepts the [FrameFlags] of the current frame. If the
	/// frame is a [FrameFlags::Beginning], then we check the
	/// [MAX_MESSAGE_LENGTH]. Otherwise, the frame length must be less than or
	/// equal to the [MAX_COMPLETE_FRAME_LENGTH].
	///
	/// This method also advanced the cursor by 4 bytes internally, due to the
	/// [BytesMut::get_u32_le] method.
	pub fn try_from(src: &mut BytesMut, frame_flags: &FrameFlags) -> Result<Self, StealthStreamPacketError> {
		// Buffer is missing the length prefix.
		if src.len() < 4 {
			return Err(StealthStreamPacketError::LengthPrefixMissing);
		}

		let frame_length = src.get_u32_le();

		// If the message is a beginning frame, the length prefix must be less than
		// MAX_MESSAGE_LENGTH. Else, if it's greater than MAX_COMPLETE_FRAME_LENGTH, the
		// length prefix is invalid.
		if matches!(frame_flags, FrameFlags::Beginning) {
			if frame_length > MAX_MESSAGE_LENGTH {
				return Err(StealthStreamPacketError::LengthOutOfBounds(frame_length as usize));
			}
		} else if frame_length > MAX_COMPLETE_FRAME_LENGTH {
			return Err(StealthStreamPacketError::LengthOutOfBounds(frame_length as usize));
		}

		Ok(Self(frame_length))
	}

	/// Checks if the buffer is ready to receive data, if so, then advance the
	/// cursor and return the length of the buffer.
	pub fn check_buffer_length_v2(&self, src: &mut BytesMut) -> Option<usize> {
		if src.len() < 2 + self.0 as usize {
			None
		} else {
			src.advance(4);
			Some(src.len())
		}
	}

	/// Checks if the buffer is ready to receive the length prefix. This will
	/// return None if the buffer is not ready to receive the length prefix.
	///
	/// If this method return Some(usize), usize will be the amount of bytes
	/// that need to be read to receive the message content.
	pub fn check_buffer_length(&self, buffer: &mut BytesMut, flags: &FrameFlags) -> Option<usize> {
		let length_prefix = self.0 as usize;
		// If this is a beginning frame with the length prefix matching max message
		// length
		if matches!(flags, FrameFlags::Beginning) && self.0 == MAX_MESSAGE_LENGTH {
			if buffer.len() < MAX_MESSAGE_LENGTH as usize {
				None
			} else {
				buffer.reserve(MAX_MESSAGE_LENGTH as usize);
				Some(MAX_MESSAGE_LENGTH as usize)
			}
		} else if buffer.len() < length_prefix {
			debug!("length prefix: {:?}", length_prefix);
			debug!("buffer length: {:?}", buffer.len());
			return None; // we don't have enough bytes in the buffer.
		} else {
			let test = buffer.len().checked_sub(length_prefix);
			if let Some(size) = test {
				buffer.reserve(size);
			} else {
				error!(
					"buffer overflow occurred: buffer: {} | length_prefix: {}",
					buffer.len(),
					length_prefix
				);
			}
			return Some(length_prefix); // we have enough bytes
		}
	}
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct MessageId(pub(crate) Uuid);
impl MessageId {
	/// Converts a [buffer](BytesMut) into a [MessageId].
	///
	/// This method will internally advance the cursor by 16 bytes internally.
	pub fn try_from(src: &mut BytesMut) -> Result<Self, StealthStreamPacketError> {
		if src.len() < 16 {
			return Err(StealthStreamPacketError::MessageIdMissing);
		}

		let id = src.get_i128_le().to_le_bytes();
		let uuid = Uuid::from_slice(&id)?;
		let message_id = MessageId(uuid);
		Ok(message_id)
	}
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct MessageContent(pub(crate) Vec<u8>);

impl MessageContent {
	pub fn new(length: &LengthPrefix, src: &mut BytesMut) -> Self {
		let content = src[0..length.0 as usize].to_vec();
		src.advance(length.0 as usize);
		Self(content)
	}

	pub fn extend_from_slice(&mut self, src: &[u8]) { self.0.extend_from_slice(src); }

	pub fn content(&self) -> &[u8] { &self.0 }
}
