#[cfg(unix)]
use arbitrary::Arbitrary;
use bytes::{Buf, BufMut, BytesMut};
use thiserror::Error;
use tokio_util::codec::{Decoder, Encoder};
#[cfg(test)]
use tracing::debug;

use super::{framing::FrameFlags, HandshakeErrors, StealthStreamMessage};
use crate::protocol::framing::FrameOpcodes;

const MAX: usize = 8 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum StealthStreamPacketErrors {
	#[error("packet missing opcode byte")]
	OpcodeByteMissing,
	#[error("packet contains invalid opco byte: {0}")]
	InvalidOpcodeByte(u8),
	#[error("packet contains invalid flag byte: {0}")]
	InvalidFlagByte(u8),
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
	content: Vec<u8>,
}

impl StealthStreamPacket {
	/// Used internally for fuzzing purposes.
	#[cfg(test)]
	pub(crate) fn new(opcode: u8, length: usize, content: Vec<u8>) -> Self {
		Self {
			opcode: FrameOpcodes::try_from(opcode).unwrap(),
			flag: FrameFlags::Complete,
			length,
			content,
		}
	}

	// FIXME
	pub fn opcode(&self) -> u8 { self.opcode.clone() as u8 }

	pub fn length(&self) -> u16 { self.length as u16 }

	pub fn content(&self) -> &[u8] { &self.content }
}

impl From<StealthStreamMessage> for StealthStreamPacket {
	fn from(message: StealthStreamMessage) -> Self {
		let content = message.serialize_content_bytes();
		Self {
			opcode: FrameOpcodes::try_from(message.opcode()).unwrap(),
			length: content.len(),
			flag: FrameFlags::Complete, // TODO: implement flags,
			content,
		}
	}
}

#[cfg(test)]
impl From<StealthStreamPacket> for Vec<u8> {
	fn from(packet: StealthStreamPacket) -> Self {
		let mut buf = BytesMut::new();

		let length = u32::to_le_bytes(packet.length as u32);
		buf.reserve(1 + 1 + 4 + packet.content.len());
		buf.put_u8(packet.opcode as u8);
		buf.put_u8(packet.flag as u8);
		buf.extend_from_slice(&length);
		buf.extend_from_slice(&packet.content);
		buf.to_vec()
	}
}

/// Codec for the Stealth Stream Protocol.
///
/// Implements the [Decoder] and [Encoder] traits to read and write frames to
/// the underlying stream.
#[derive(Debug)]
pub struct StealthStreamCodec;

impl Decoder for StealthStreamCodec {
	type Error = StealthStreamPacketErrors;
	type Item = StealthStreamPacket;

	// TODO: implement beginning/continuation frames
	fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
		if src.len() < 2 {
			return Ok(None);
		}

		let opcode = FrameOpcodes::try_from(src[0])?;
		let flag = FrameFlags::try_from(src[1])?;
		src.advance(2);

		if src.len() < 2 {
			return Err(StealthStreamPacketErrors::LengthPrefixMissing);
		}

		let length = src.get_u32_le() as usize;
		if length > MAX {
			return Err(StealthStreamPacketErrors::LengthOutOfBounds(length));
		}

		if src.len() < length {
			src.reserve(length - src.len());
			return Ok(None);
		}

		let content = src[0..length].to_vec();
		// Advance the cursor by the length of the buffer.
		// The reason we don't use `length` here is because if the length of the data
		// was less than the length prefix, the cursor would get stuck and subsequent
		// reads would be broken.
		src.advance(src.len());

		#[cfg(test)]
		{
			let test_utf_8 = String::from_utf8_lossy(&content);
			debug!(target: "test", "opcode: {:?}", opcode);
			debug!(target: "test", "length: {:?}", length);
			debug!(target: "test", "flag: {:?}", flag);
			debug!(target: "test", "content: {:?}", content);
			debug!(target: "test", "utf-8: {:?}", test_utf_8);
		}

		let packet = StealthStreamPacket {
			opcode,
			flag,
			length,
			content,
		};

		// Reserve the amount of memory needed for the next header.
		src.reserve(6);

		Ok(Some(packet))
	}
}

impl Encoder<StealthStreamPacket> for StealthStreamCodec {
	type Error = StealthStreamPacketErrors;

	fn encode(&mut self, item: StealthStreamPacket, dst: &mut BytesMut) -> Result<(), Self::Error> {
		// TODO: implement length requirements
		let length = u32::to_le_bytes(item.length as u32);

		// Reserve space for opcode/flag/length prefix + content length
		dst.reserve(1 + 1 + 4 + item.content.len());
		dst.put_u8(item.opcode as u8);
		dst.put_u8(item.flag as u8);

		dst.extend_from_slice(&length);
		dst.extend_from_slice(&item.content);

		Ok(())
	}
}

#[cfg(test)]
mod test {

	use futures_util::{SinkExt, StreamExt};
	use rand::Rng;
	use tokio::{
		io::AsyncWriteExt,
		net::{TcpListener, TcpStream},
		sync::mpsc::Sender,
	};
	use tokio_util::codec::{FramedRead, FramedWrite};
	use tracing::debug;

	use super::StealthStreamCodec;
	use crate::protocol::{
		framing::{FrameFlags, FrameOpcodes},
		StealthStreamPacket, StealthStreamPacketErrors,
	};

	type PacketResult = Result<StealthStreamPacket, StealthStreamPacketErrors>;
	use test_log::test;

	async fn setup_test_server(sender: Sender<PacketResult>) -> String {
		let mut rng = rand::thread_rng();
		let random_port: u16 = rng.gen_range(1000..65535);

		let address = format!("127.0.0.1:{random_port}");
		let listener = TcpListener::bind(&address).await.unwrap();
		tokio::spawn(async move {
			let (socket, _) = listener.accept().await.expect("Failed to accept connections");
			let mut framed = FramedRead::new(socket, StealthStreamCodec);

			while let Some(packet) = framed.next().await {
				let _ = sender.send(packet).await;
			}
			debug!("stream is closed");
		});

		address.to_string()
	}

	#[test(tokio::test)]
	async fn test_basic_binary_send() {
		let (tx, mut rx) = tokio::sync::mpsc::channel::<PacketResult>(5);

		let address = setup_test_server(tx).await;
		let stream = TcpStream::connect(address).await.expect("couldn't setup TcpClient");
		let mut framed = FramedWrite::new(stream, StealthStreamCodec);

		let content: Vec<u8> = "hello".as_bytes().to_vec();

		let packet = StealthStreamPacket {
			opcode: FrameOpcodes::Binary,
			flag: FrameFlags::Complete,
			length: content.len(),
			content: content.clone(),
		};

		// Send the packet
		framed
			.send(packet)
			.await
			.map_err(|e| {
				// Map the error from the codec's error type to a standard error
				// This may involve conversion logic as per your error handling strategy
				eprintln!("Error sending packet: {:?}", e);
				e
			})
			.expect("couldn't send the frame :(");

		let test = rx.recv().await;
		assert!(test.is_some_and(|v| v.is_ok_and(|v| v.content == content)))
	}

	#[test(tokio::test)]
	async fn test_early_eof() {
		let (tx, mut rx) = tokio::sync::mpsc::channel::<PacketResult>(5);
		let address = setup_test_server(tx).await;
		let stream = TcpStream::connect(address).await.expect("couldn't setup TcpClient");
		let mut framed = FramedWrite::new(stream, StealthStreamCodec);

		framed.write_buffer_mut().extend_from_slice(&[0, 1]);
		let mut test = framed.into_inner();
		test.shutdown().await.expect("couldn't shutdown the tcp stream");

		let test = rx.recv().await;
		assert!(test.is_none())
	}
}
