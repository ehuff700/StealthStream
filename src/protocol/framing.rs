use bytes::{Buf, BytesMut};
#[cfg(test)]
use tracing::debug;
use uuid::Uuid;

use super::{
	constants::{
		ACKNOWLEDGEMENT_OPCODE, BEGINNING_FLAG, COMPLETION_FLAG, CONTINUATION_FLAG, END_FLAG, ERROR_OPCODE,
		GOODBYE_OPCODE, HANDSHAKE_OPCODE, HEARTBEAT_OPCODE, MESSAGE_OPCODE,
	},
	StealthStreamPacketError,
};
use crate::protocol::constants::MAX_COMPLETE_FRAME_LENGTH;

#[derive(Debug, Clone, Copy, PartialEq)]
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

#[derive(Debug, Clone, Copy, PartialEq)]
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
				flag: *flag,
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
#[derive(Debug, Clone, Copy, PartialEq)]
/// The length prefix is a 4 byte long u32 value representing the number of
/// bytes to be read from the stream to compose the frame/message.
///
/// For frames that are NOT [FrameFlags::Beginning], the maximum length prefix
/// is [MAX_COMPLETE_FRAME_LENGTH]. If the frame is a [FrameFlags::Beginning],
/// the maximum length prefix is [MAX_MESSAGE_LENGTH].
pub struct LengthPrefix(pub(crate) u32);
impl LengthPrefix {
	/// Attempts to compose the LengthPrefix from the buffer.
	///
	/// This method only peeks at the buffer and will not advance it.
	/// Advancement is performed after the length buffer check is performed
	/// successfully in the [check_buffer_length] method.
	pub fn try_from_buffer(src: &mut BytesMut) -> Result<Self, StealthStreamPacketError> {
		let length_prefix = u32::from_le_bytes([src[0], src[1], src[2], src[3]]);

		#[cfg(test)]
		debug!("what is length prefix: {:?}", length_prefix);

		if length_prefix > MAX_COMPLETE_FRAME_LENGTH {
			src.advance(src.len());
			Err(StealthStreamPacketError::LengthOutOfBounds(length_prefix as usize))
		} else {
			Ok(LengthPrefix(length_prefix))
		}
	}

	/// Checks if the buffer is ready to receive data, if so, then advance the
	/// cursor and return the total length of the buffer.
	pub fn check_buffer_length(&self, src: &mut BytesMut) -> Option<usize> {
		// frame opcode/flag size + length prefix
		if src.len() < 2 + self.0 as usize {
			None
		} else {
			src.advance(4);
			Some(src.len())
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
