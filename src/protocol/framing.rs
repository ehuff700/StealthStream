#![allow(dead_code)]
use super::{
	constants::{
		ACKNOWLEDGEMENT_OPCODE, BEGINNING_FLAG, BINARY_OPCODE, COMPLETION_FLAG, CONTINUATION_FLAG, END_FLAG,
		ERROR_OPCODE, GOODBYE_OPCODE, HANDSHAKE_OPCODE, HEARTBEAT_OPCODE,
	},
	StealthStreamPacketErrors,
};

#[derive(Debug, Clone)]
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
	Binary = BINARY_OPCODE,
	Acknowledgement = ACKNOWLEDGEMENT_OPCODE,
	Error = ERROR_OPCODE,
}

impl FrameOpcodes {
	/// Indicates whether the frame opcode is a control frame.
	fn is_control_frame(&self) -> bool {
		matches!(self, FrameOpcodes::Handshake | FrameOpcodes::Heartbeat | FrameOpcodes::Goodbye)
	}

	/// Indicates whether the frame opcode is a data frame.
	fn is_data_frame(&self) -> bool {
		matches!(self, FrameOpcodes::Binary | FrameOpcodes::Acknowledgement | FrameOpcodes::Error)
	}
}

impl TryFrom<u8> for FrameOpcodes {
	type Error = StealthStreamPacketErrors;

	fn try_from(opcode: u8) -> Result<Self, <FrameOpcodes as TryFrom<u8>>::Error> {
		match opcode {
			HANDSHAKE_OPCODE => Ok(FrameOpcodes::Handshake),
			HEARTBEAT_OPCODE => Ok(FrameOpcodes::Heartbeat),
			GOODBYE_OPCODE => Ok(FrameOpcodes::Goodbye),
			BINARY_OPCODE => Ok(FrameOpcodes::Binary),
			ACKNOWLEDGEMENT_OPCODE => Ok(FrameOpcodes::Acknowledgement),
			ERROR_OPCODE => Ok(FrameOpcodes::Error),
			_ => Err(StealthStreamPacketErrors::InvalidOpcodeByte(opcode)),
		}
	}
}

#[derive(Debug)]
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

impl TryFrom<u8> for FrameFlags {
	type Error = StealthStreamPacketErrors;

	fn try_from(flag: u8) -> Result<Self, <FrameFlags as TryFrom<u8>>::Error> {
		match flag {
			COMPLETION_FLAG => Ok(FrameFlags::Complete),
			BEGINNING_FLAG => Ok(FrameFlags::Beginning),
			CONTINUATION_FLAG => Ok(FrameFlags::Continuation),
			END_FLAG => Ok(FrameFlags::End),
			_ => Err(StealthStreamPacketErrors::InvalidFlagByte(flag)),
		}
	}
}
