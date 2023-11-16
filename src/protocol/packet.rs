use std::collections::HashMap;

use bytes::{Buf, BufMut, BytesMut};
use thiserror::Error;
use tokio_util::codec::{Decoder, Encoder};

#[cfg(test)]
use tracing::debug;

use super::{
	constants::HEADER_LENGTH,
	framing::{FrameFlags, LengthPrefix, MessageContent},
	HandshakeErrors,
};
use crate::protocol::framing::{FrameOpcodes, MessageId};

#[derive(Debug, Error)]
pub enum StealthStreamPacketError {
	#[error("packet missing opcode byte")]
	OpcodeByteMissing,
	#[error("packet contains invalid opco byte: {0}")]
	InvalidOpcodeByte(u8),
	#[error("packet contains invalid flag byte: {0}")]
	InvalidFlagByte(u8),
	#[error("invalid flag {flag:?} for opcode: {opcode:?}")]
	InvalidFlagForOpcode { flag: FrameFlags, opcode: FrameOpcodes },
	#[error("packet missing message id")]
	MessageIdMissing,
	#[error("packet contains invalid message id, citing parse error: {0}")]
	InvalidMessageId(#[from] uuid::Error),
	#[error("message id '{{message_id.0}}' associated with continuation frame missing")]
	ArbitraryContinuationFrame {
		message_id: MessageId,
		continuation_frame: Vec<u8>,
	},
	#[error("message id '{{message_id.0}}' associated with end frame missing")]
	ArbitraryEndFrame { message_id: MessageId, end_frame: Vec<u8> },
	#[error("packet missing length prefix")]
	LengthPrefixMissing,
	#[error("packet length out of bounds: {0}")]
	LengthOutOfBounds(usize), // TODO: implement max length
	#[error(transparent)]
	HandshakeError(#[from] HandshakeErrors),
	#[error("error reading from the underlying stream: {0}")]
	StreamError(#[from] tokio::io::Error),
	#[error("the stream has been closed")]
	StreamClosed,
}

#[derive(Debug)]
pub struct StealthStreamPacket {
	opcode: FrameOpcodes,
	flag: FrameFlags,
	length: usize,
	message_id: Option<MessageId>,
	content: Vec<u8>,
}

impl StealthStreamPacket {
	pub fn new_v2(opcode: FrameOpcodes, flag: FrameFlags, message_id: Option<MessageId>, content: Vec<u8>) -> Self {
		Self {
			opcode,
			flag,
			length: content.len(),
			message_id,
			content,
		}
	}

	/// Used internally for fuzzing purposes.
	#[cfg(test)]
	pub(crate) fn new(opcode: u8, length: usize, content: Vec<u8>) -> Self {
		Self {
			opcode: FrameOpcodes::try_from(opcode).unwrap(),
			flag: FrameFlags::Complete,
			length,
			message_id: None,
			content,
		}
	}

	pub(crate) fn from_encoded(
		opcode: FrameOpcodes, flag: FrameFlags, length: LengthPrefix, content: MessageContent,
		message_id: Option<MessageId>,
	) -> Self {
		let (content, length) = (content.0, length.0 as usize);

		Self {
			opcode,
			flag,
			length,
			content,
			message_id,
		}
	}

	// FIXME
	pub fn opcode(&self) -> u8 {
		self.opcode as u8
	}

	pub fn length(&self) -> u16 {
		self.length as u16
	}

	pub fn content(&self) -> &[u8] {
		&self.content
	}

	pub fn needs_message_id(&self) -> bool {
		matches!(self.flag, FrameFlags::Beginning | FrameFlags::Continuation | FrameFlags::End)
			&& self.opcode.is_data_frame()
	}
}

#[cfg(test)]
impl From<StealthStreamPacket> for Vec<u8> {
	fn from(packet: StealthStreamPacket) -> Self {
		let mut dst = BytesMut::new();

		let length = u32::to_le_bytes(packet.length as u32);

		// Reserve space for opcode/flag/length prefix + content length
		if packet.needs_message_id() {
			dst.reserve(1 + 1 + 4 + 16 + packet.content.len());
			dst.put_u8(packet.opcode as u8);
			dst.put_u8(packet.flag as u8);
			dst.extend_from_slice(&packet.message_id.unwrap().0.to_bytes_le())
		} else {
			dst.reserve(1 + 1 + 4 + packet.content.len());
			dst.put_u8(packet.opcode as u8);
			dst.put_u8(packet.flag as u8);
		}

		dst.extend_from_slice(&length);
		dst.extend_from_slice(&packet.content);
		dst.to_vec()
	}
}

/// Codec for the Stealth Stream Protocol.
///
/// Implements the [Decoder] and [Encoder] traits to read and write frames to
/// the underlying stream.
#[derive(Debug, Default)]
pub struct StealthStreamCodec {
	message_buffers: HashMap<MessageId, MessageContent>,
}

impl Decoder for StealthStreamCodec {
	type Error = StealthStreamPacketError;
	type Item = StealthStreamPacket;

	fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
		if src.len() < 2 {
			return Ok(None);
		}

		let opcode = FrameOpcodes::try_from(src[0])?;
		let flag = FrameFlags::try_from(src[1], &opcode)?;
		src.advance(2);

		let message_id = if opcode.is_data_frame()
			&& matches!(flag, FrameFlags::Beginning | FrameFlags::Continuation | FrameFlags::End)
		{
			Some(MessageId::try_from(src)?)
		} else {
			None
		};

		// Not necessary to advance position, [LengthPrefix::try_from] does that internally.
		let length = LengthPrefix::try_from(src, &flag)?;
		let _bytes_to_read = match length.check_buffer_length(src, &flag) {
			None => return Ok(None),
			Some(bytes_read) => bytes_read,
		};

		#[cfg(test)]
		{
			debug!("length prefix: {:?}", length);
			debug!("bytes_to_read: {:?}", _bytes_to_read);
		}

		let message = MessageContent::new(&length, src);

		if let Some(message_id) = message_id {
			match flag {
				FrameFlags::Beginning => {
					self.message_buffers.insert(message_id, message);
					return Ok(None);
				},
				FrameFlags::Continuation | FrameFlags::End => match self.message_buffers.get_mut(&message_id) {
					Some(buffer) => {
						buffer.extend_from_slice(message.content());
						if matches!(flag, FrameFlags::End) {
							let content = self.message_buffers.remove(&message_id).unwrap();
							return Ok(Some(StealthStreamPacket::from_encoded(
								opcode,
								flag,
								length,
								content,
								Some(message_id),
							)));
						};
						return Ok(None);
					},
					None => {
						if matches!(flag, FrameFlags::Continuation) {
							return Err(StealthStreamPacketError::ArbitraryContinuationFrame {
								message_id,
								continuation_frame: message.content().to_vec(),
							});
						} else {
							return Err(StealthStreamPacketError::ArbitraryEndFrame {
								message_id,
								end_frame: message.content().to_vec(),
							});
						}
					},
				},
				_ => {},
			};
		}

		#[cfg(test)]
		{
			debug!(target: "test", "Message Completed.");
			debug!(target: "test", "opcode: {:?}", opcode);
			debug!(target: "test", "length: {:?}", length);
			debug!(target: "test", "flag: {:?}", flag);
		}

		// Reserve the amount of memory needed for the next header.
		src.reserve(HEADER_LENGTH);

		Ok(Some(StealthStreamPacket::from_encoded(
			opcode, flag, length, message, message_id,
		)))
	}
}

impl Encoder<StealthStreamPacket> for StealthStreamCodec {
	type Error = StealthStreamPacketError;

	fn encode(&mut self, item: StealthStreamPacket, dst: &mut BytesMut) -> Result<(), Self::Error> {
		// TODO: implement length requirements
		let length = u32::to_le_bytes(item.length as u32);

		// Reserve space for opcode/flag/length prefix + content length
		if item.needs_message_id() {
			dst.reserve(1 + 1 + 4 + 16 + item.content.len());
			dst.put_u8(item.opcode as u8);
			dst.put_u8(item.flag as u8);
			dst.extend_from_slice(&item.message_id.unwrap().0.to_bytes_le())
		} else {
			dst.reserve(1 + 1 + 4 + item.content.len());
			dst.put_u8(item.opcode as u8);
			dst.put_u8(item.flag as u8);
		}

		dst.extend_from_slice(&length);
		dst.extend_from_slice(&item.content);

		Ok(())
	}
}

#[cfg(test)]
mod tests {

	use futures_util::{SinkExt, StreamExt};
	use rand::Rng;
	use tokio::{
		net::{TcpListener, TcpStream},
		sync::mpsc::Sender,
	};
	use tokio_util::codec::{FramedRead, FramedWrite};
	#[allow(unused_imports)]
	use tracing::{error, level_filters::LevelFilter};
	use uuid::Uuid;

	use super::StealthStreamCodec;
	use crate::protocol::{
		framing::{FrameFlags, FrameOpcodes, MessageId},
		StealthStreamPacket, StealthStreamPacketError,
	};

	type PacketResult = Result<StealthStreamPacket, StealthStreamPacketError>;

	async fn setup_test_server(sender: Sender<PacketResult>) -> String {
		let mut rng = rand::thread_rng();
		let random_port: u16 = rng.gen_range(1000..65535);

		let address = format!("127.0.0.1:{random_port}");
		let listener = TcpListener::bind(&address).await.unwrap();
		tokio::spawn(async move {
			let (socket, _) = listener.accept().await.expect("Failed to accept connections");
			let mut framed = FramedRead::new(socket, StealthStreamCodec::default());

			loop {
				while let Some(packet) = framed.next().await {
					let _ = sender.send(packet).await;
				}
			}
		});

		address.to_string()
	}

	#[tokio::test]
	async fn test_basic_binary_send() {
		let (tx, mut rx) = tokio::sync::mpsc::channel::<PacketResult>(5);

		let address = setup_test_server(tx).await;
		let stream = TcpStream::connect(address).await.expect("couldn't setup TcpClient");
		let mut framed = FramedWrite::new(stream, StealthStreamCodec::default());

		let content: Vec<u8> = "hello".as_bytes().to_vec();

		let packet = StealthStreamPacket {
			opcode: FrameOpcodes::Binary,
			flag: FrameFlags::Complete,
			length: content.len(),
			content: content.clone(),
			message_id: None,
		};

		// Send the packet
		framed
			.send(packet)
			.await
			.map_err(|e| {
				// Map the error from the codec's error type to a standard error
				// This may involve conversion logic as per your error handling strategy
				error!("Error sending packet: {:?}", e);
				e
			})
			.expect("couldn't send the frame :(");

		let test = rx.recv().await;
		assert!(test.is_some_and(|v| v.is_ok_and(|v| v.content == content)))
	}

	#[tokio::test]
	async fn test_negative_framing() {
		//tracing_subscriber::fmt().with_max_level(LevelFilter::DEBUG).init();
		let (tx, mut rx) = tokio::sync::mpsc::channel::<PacketResult>(5);
		let address = setup_test_server(tx).await;
		let stream = TcpStream::connect(address).await.expect("couldn't setup TcpClient");
		let (_, owned_write) = stream.into_split();
		let mut framed = FramedWrite::new(owned_write, StealthStreamCodec::default());

		let content: Vec<u8> = "hello".as_bytes().to_vec();

		let packet = StealthStreamPacket {
			opcode: FrameOpcodes::Binary,
			flag: FrameFlags::Complete,
			length: content.len(),
			content: content.clone(),
			message_id: None,
		};

		let arbitrary_end_frame = StealthStreamPacket {
			opcode: FrameOpcodes::Binary,
			flag: FrameFlags::End,
			length: content.len(),
			content: content.clone(),
			message_id: Some(MessageId(Uuid::new_v4())),
		};

		let arbitrary_continuation_frame = StealthStreamPacket {
			opcode: FrameOpcodes::Binary,
			flag: FrameFlags::Continuation,
			length: content.len(),
			content: content.clone(),
			message_id: Some(MessageId(Uuid::new_v4())),
		};

		// Send the packet
		framed
			.send(packet)
			.await
			.map_err(|e| {
				eprintln!("Error sending packet: {:?}", e);
				e
			})
			.expect("couldn't send the frame :(");

		let resp = rx.recv().await;
		assert!(resp.is_some_and(|v| v.is_ok_and(|v| v.content == content)));

		/* Send the arbitrary end frame */
		framed
			.send(arbitrary_end_frame)
			.await
			.map_err(|e| {
				error!("Error sending packet: {:?}", e);
				e
			})
			.expect("couldn't send the frame :(");

		let response = rx.recv().await;
		assert!(
			response.is_some_and(|v| v.is_err_and(|e| matches!(e, StealthStreamPacketError::ArbitraryEndFrame { .. })))
		);

		/* Send the Arbitrary Continuation Frame */
		// Send the packet
		framed
			.send(arbitrary_continuation_frame)
			.await
			.map_err(|e| {
				eprintln!("Error sending packet: {:?}", e);
				e
			})
			.expect("couldn't send the frame :(");

		let resp = rx.recv().await;
		assert!(resp.is_some_and(
			|v| v.is_err_and(|e| matches!(e, StealthStreamPacketError::ArbitraryContinuationFrame { .. }))
		));
	}
}
