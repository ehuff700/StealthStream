use std::collections::HashMap;

use bytes::{Buf, BufMut, BytesMut};
use derive_getters::Getters;
use thiserror::Error;
use tokio_util::codec::{Decoder, Encoder};
#[cfg(test)]
use tracing::debug;

use super::{
	constants::MINIMUM_HEADER_LENGTH,
	framing::{FrameFlags, LengthPrefix, MessageContent},
	HandshakeErrors,
};
use crate::protocol::{
	constants::MAX_MESSAGE_LENGTH,
	framing::{FrameIdentifier, FrameOpcodes},
};

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
		message_id: FrameIdentifier,
		continuation_frame: Vec<u8>,
	},
	#[error("message id '{{message_id.0}}' associated with end frame missing")]
	ArbitraryEndFrame {
		message_id: FrameIdentifier,
		end_frame: Vec<u8>,
	},
	#[error("packet missing length prefix")]
	LengthPrefixMissing,
	#[error("packet length out of bounds: {0}")]
	LengthOutOfBounds(usize),
	#[error("message contents out of bounds (size): {size}")]
	MessageContentsOutOfBounds {
		size: usize,
		prev_contents: Vec<u8>,
		frame_identifier: FrameIdentifier,
	},
	#[error("message contents overflowed {MAX_MESSAGE_LENGTH} {0}")]
	MessageContentsOverflowed(usize),
	#[error(transparent)]
	HandshakeError(#[from] HandshakeErrors),
	#[error("error reading from the underlying stream: {0}")]
	StreamError(#[from] tokio::io::Error),
	#[error("the stream has been closed")]
	StreamClosed,
}

#[derive(Debug, Getters, PartialEq)]
pub struct StealthStreamPacket {
	#[getter(skip)]
	opcode: FrameOpcodes,
	flag: FrameFlags,
	#[getter(skip)]
	length: usize,
	frame_id: Option<FrameIdentifier>,
	#[getter(skip)]
	content: Vec<u8>,
}

impl StealthStreamPacket {
	pub fn new_v2(
		opcode: FrameOpcodes, flag: FrameFlags, message_id: Option<FrameIdentifier>, content: Vec<u8>,
	) -> Self {
		Self {
			opcode,
			flag,
			length: content.len(),
			frame_id: message_id,
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
			frame_id: None,
			content,
		}
	}

	pub(crate) fn from_encoded(
		opcode: FrameOpcodes, flag: FrameFlags, length: LengthPrefix, content: MessageContent,
		message_id: Option<FrameIdentifier>,
	) -> Self {
		let (content, length) = (content.0, length.0 as usize);

		Self {
			opcode,
			flag,
			length,
			content,
			frame_id: message_id,
		}
	}

	pub fn opcode(&self) -> u8 { self.opcode as u8 }

	pub fn length(&self) -> u16 { self.length as u16 }

	pub fn content(&self) -> &[u8] { &self.content }

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
			dst.extend_from_slice(&packet.frame_id.unwrap().0.into_bytes())
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
	message_buffers: HashMap<FrameIdentifier, MessageContent>,
}

impl Decoder for StealthStreamCodec {
	type Error = StealthStreamPacketError;
	type Item = StealthStreamPacket;

	fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
		loop {
			if src.len() < MINIMUM_HEADER_LENGTH {
				return Ok(None);
			}

			#[cfg(test)]
			debug!("src len: {}", src.len());

			// Parses the length prefix from the first 4 bytes, returning an error if it's
			// out of bounds.
			let length_prefix = LengthPrefix::try_from_buffer(src)?;
			let _bytes_to_read = match length_prefix.check_buffer_length(src) {
				None => return Ok(None),
				Some(bytes_read) => bytes_read,
			};

			#[cfg(test)]
			{
				debug!("length prefix: {:?}", length_prefix);
				debug!("bytes_to_read: {:?}", _bytes_to_read);
				debug!("current src len: {}", src.len());
			}

			let opcode = FrameOpcodes::try_from(src[0])?;
			let flag = FrameFlags::try_from(src[1], &opcode)?;
			src.advance(2);

			#[cfg(test)]
			{
				debug!("opcode: {:?}", opcode);
				debug!("flag: {:?}", flag);
			}

			let message_id = if opcode.is_data_frame()
				&& matches!(flag, FrameFlags::Beginning | FrameFlags::Continuation | FrameFlags::End)
			{
				Some(FrameIdentifier::try_from(src)?)
			} else {
				None
			};

			#[cfg(test)]
			debug!("message_id: {:?}", message_id);

			let message = MessageContent::new(&length_prefix, src);

			if let Some(message_id) = message_id {
				match flag {
					FrameFlags::Beginning => {
						self.message_buffers.insert(message_id, message.clone());
						if src.len() > MINIMUM_HEADER_LENGTH {
							continue;
						} else {
							return Ok(None);
						}
					},
					FrameFlags::Continuation | FrameFlags::End => {
						if let Some(mut buffer) = self.message_buffers.remove(&message_id) {
							let potential_length = buffer.content().len() + message.content().len();

							if potential_length > MAX_MESSAGE_LENGTH as usize {
								{
									self.message_buffers.remove(&message_id);
								}
								return Err(StealthStreamPacketError::MessageContentsOutOfBounds {
									size: potential_length,
									prev_contents: buffer.content().to_vec(),
									frame_identifier: message_id,
								});
							}

							buffer.extend_from_slice(message.content());

							if matches!(flag, FrameFlags::End) {
								return Ok(Some(StealthStreamPacket::from_encoded(
									opcode,
									flag,
									length_prefix,
									buffer,
									Some(message_id),
								)));
							};

							// Insert the modified buffer back into the map if it's not an end frame.
							self.message_buffers.insert(message_id, buffer);

							if src.len() > MINIMUM_HEADER_LENGTH {
								continue;
							} else {
								return Ok(None);
							}
						} else if matches!(flag, FrameFlags::Continuation) {
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
					_ => {},
				};
			}

			#[cfg(test)]
			{
				debug!(target: "test", "Message Completed.");
				debug!(target: "test", "opcode: {:?}", opcode);
				debug!(target: "test", "length: {:?}", length_prefix);
				debug!(target: "test", "flag: {:?}", flag);
			}

			// Reserve the amount of memory needed for the next header.
			src.reserve(MINIMUM_HEADER_LENGTH);

			if matches!(flag, FrameFlags::Complete) {
				return Ok(Some(StealthStreamPacket::from_encoded(
					opcode,
					flag,
					length_prefix,
					message,
					message_id,
				)));
			} else if src.len() > MINIMUM_HEADER_LENGTH {
				continue;
			} else {
				return Ok(None);
			}
		}
	}
}

impl Encoder<StealthStreamPacket> for StealthStreamCodec {
	type Error = StealthStreamPacketError;

	fn encode(&mut self, item: StealthStreamPacket, dst: &mut BytesMut) -> Result<(), Self::Error> {
		let length = u32::to_le_bytes(item.length as u32);

		// Reserve space for opcode/flag/length prefix + content length
		if item.needs_message_id() {
			dst.reserve(4 + 1 + 1 + 16 + item.content.len());
			dst.extend_from_slice(&length);
			dst.put_u8(item.opcode as u8);
			dst.put_u8(item.flag as u8);
			dst.extend_from_slice(&item.frame_id.unwrap().0.to_bytes_le())
		} else {
			dst.reserve(4 + 1 + 1 + item.content.len());
			dst.extend_from_slice(&length);
			dst.put_u8(item.opcode as u8);
			dst.put_u8(item.flag as u8);
		}

		dst.extend_from_slice(&item.content);

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use futures_util::{SinkExt, StreamExt};
	use rand::{distributions::Alphanumeric, Rng};
	use tokio::{
		net::{TcpListener, TcpStream},
		sync::mpsc::Sender,
	};
	use tokio_util::codec::{FramedRead, FramedWrite};
	#[allow(unused_imports)]
	use tracing::{debug, error, level_filters::LevelFilter};
	use uuid::Uuid;

	use super::StealthStreamCodec;
	use crate::protocol::{
		framing::{FrameFlags, FrameIdentifier, FrameOpcodes},
		StealthStreamPacket, StealthStreamPacketError,
		StealthStreamPacketError::LengthOutOfBounds,
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
			frame_id: None,
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
	async fn test_frame_size_overflow() {
		//tracing_subscriber::fmt().with_max_level(LevelFilter::DEBUG).init();
		let (tx, mut rx) = tokio::sync::mpsc::channel::<PacketResult>(5);
		let address = setup_test_server(tx).await;
		let stream = TcpStream::connect(address).await.expect("couldn't setup TcpClient");
		let (_, owned_write) = stream.into_split();
		let mut framed = FramedWrite::new(owned_write, StealthStreamCodec::default());

		let content: String = generate_long_string(50);
		framed
			.send(StealthStreamPacket {
				opcode: FrameOpcodes::Binary,
				flag: FrameFlags::Complete,
				length: content.len(),
				frame_id: None,
				content: content.as_bytes().to_vec(),
			})
			.await
			.expect("couldn't send packet");
		framed.flush().await.unwrap();

		let resp = rx.recv().await;
		assert!(matches!(resp, Some(Err(LengthOutOfBounds(_)))));

		framed
			.send(StealthStreamPacket {
				opcode: FrameOpcodes::Binary,
				flag: FrameFlags::Beginning,
				length: content.len(),
				frame_id: Some(FrameIdentifier(Uuid::new_v4())),
				content: content.as_bytes().to_vec(),
			})
			.await
			.expect("couldn't send packet");
		framed.flush().await.unwrap();

		let resp = rx.recv().await;
		assert!(matches!(resp, Some(Err(LengthOutOfBounds(_)))))
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
			frame_id: None,
		};

		let arbitrary_end_frame = StealthStreamPacket {
			opcode: FrameOpcodes::Binary,
			flag: FrameFlags::End,
			length: content.len(),
			content: content.clone(),
			frame_id: Some(FrameIdentifier(Uuid::new_v4())),
		};

		let arbitrary_continuation_frame = StealthStreamPacket {
			opcode: FrameOpcodes::Binary,
			flag: FrameFlags::Continuation,
			length: content.len(),
			content: content.clone(),
			frame_id: Some(FrameIdentifier(Uuid::new_v4())),
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

	#[tokio::test]
	async fn test_interleaved_fragmentation() {
		//tracing_subscriber::fmt().with_max_level(LevelFilter::DEBUG).init();
		let (tx, mut rx) = tokio::sync::mpsc::channel::<PacketResult>(5);
		let address = setup_test_server(tx).await;
		let stream = TcpStream::connect(address).await.expect("couldn't setup TcpClient");
		let (_, owned_write) = stream.into_split();
		let mut framed = FramedWrite::new(owned_write, StealthStreamCodec::default());

		let mut first_packet_content: Vec<u8> = generate_long_string(16).into_bytes();
		let mut second_packet_content: Vec<u8> = generate_long_string(16).into_bytes();
		assert_ne!(first_packet_content, second_packet_content);

		let test_end: Vec<u8> = "END".to_string().into_bytes();

		let first_frame_id = Some(FrameIdentifier(Uuid::new_v4()));
		let second_frame_id = Some(FrameIdentifier(Uuid::new_v4()));

		let first_packet = StealthStreamPacket {
			opcode: FrameOpcodes::Binary,
			flag: FrameFlags::Beginning,
			length: first_packet_content.len(),
			content: first_packet_content.clone(),
			frame_id: first_frame_id,
		};

		let first_end_packet = StealthStreamPacket {
			opcode: FrameOpcodes::Binary,
			flag: FrameFlags::End,
			length: test_end.len(),
			content: test_end.clone(),
			frame_id: first_frame_id,
		};

		let second_packet = StealthStreamPacket {
			opcode: FrameOpcodes::Binary,
			flag: FrameFlags::Beginning,
			length: second_packet_content.len(),
			content: second_packet_content.clone(),
			frame_id: second_frame_id,
		};

		let second_end_packet = StealthStreamPacket {
			opcode: FrameOpcodes::Binary,
			flag: FrameFlags::End,
			length: test_end.len(),
			content: test_end.clone(),
			frame_id: second_frame_id,
		};

		framed.send(first_packet).await.expect("couldn't send first packet");

		framed.send(second_packet).await.expect("couldn't send second packet");

		framed
			.send(first_end_packet)
			.await
			.expect("couldn't send first end packet");

		// Here we test that the message matches the expected content ()
		let resp = rx.recv().await;
		first_packet_content.append(&mut test_end.clone());
		assert!(resp.is_some_and(|v| v.is_ok_and(|v| v.content == first_packet_content)));

		framed
			.send(second_end_packet)
			.await
			.expect("couldn't send second end packet");

		let resp = rx.recv().await;
		second_packet_content.append(&mut test_end.clone());
		assert!(resp.is_some_and(|v| v.is_ok_and(|v| v.content == second_packet_content)));
	}

	fn generate_long_string(length_kb: usize) -> String {
		let length = 1024 * length_kb; // Convert KB to bytes (characters)
		let mut rng = rand::thread_rng();
		(0..length).map(|_| rng.sample(Alphanumeric) as char).collect()
	}
}
