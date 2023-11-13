use futures_util::{SinkExt, StreamExt};
use tokio::{
	net::{
		tcp::{OwnedReadHalf, OwnedWriteHalf},
		TcpStream,
	},
	sync::Mutex,
};
use tokio_util::codec::{FramedRead, FramedWrite};

use super::{StealthStreamCodec, StealthStreamPacket, StealthStreamPacketError};
use crate::protocol::StealthStreamMessage;

#[derive(Debug)]
pub struct StealthStream {
	writer: Mutex<FramedWrite<OwnedWriteHalf, StealthStreamCodec>>,
	reader: Mutex<FramedRead<OwnedReadHalf, StealthStreamCodec>>,
}

impl StealthStream {
	/// Sends a packet to the underlying stream using the FramedWriter.
	pub async fn write(&self, data: StealthStreamPacket) -> Result<(), StealthStreamPacketError> {
		let mut writer = self.writer.lock().await;
		writer.send(data).await
	}

	/// Writes a `Vec<StealthStreamPacket>` to the underlying stream using the
	/// FramedWriter.
	///
	/// This method will use `feed()` to write all the packets to the underlying
	/// stream, and then flush is called once all items have been written.
	pub async fn write_all(&self, data: Vec<StealthStreamPacket>) -> Result<(), StealthStreamPacketError> {
		let mut writer = self.writer.lock().await;
		for packet in data.into_iter() {
			writer.feed(packet).await?;
		}
		writer.flush().await
	}

	/// Reads a [StealthStreamMessage] from the underlying stream.
	///
	/// This method will return `None` if the underlying stream is closed.
	/// Otherwise, it will attempt to read from the stream via `next()`.
	///
	/// Once a packet has been read from the frame reader, it will be
	/// deserialized into a [StealthStreamMessage]. If that was not successful,
	/// this method will return a [StealthStreamPacketError]
	pub async fn read(&self) -> Option<Result<StealthStreamMessage, StealthStreamPacketError>> {
		let next_result = {
			let mut guard = self.reader.lock().await;
			guard.next().await
		};

		if let Some(result) = next_result {
			match result {
				Ok(ref packet) => Some(StealthStreamMessage::from_message(packet)),
				Err(e) => Some(Err(e)),
			}
		} else {
			None
		}
	}

	/// Shuts down the underlying stream.
	pub async fn close(&self) -> Result<(), StealthStreamPacketError> {
		let mut write_half = self.writer.lock().await;
		write_half.close().await?;
		Ok(())
	}

	/// Used internally for fuzzing input.
	#[cfg(test)]
	pub(crate) fn writer(&self) -> &Mutex<FramedWrite<OwnedWriteHalf, StealthStreamCodec>> { &self.writer }

	pub fn reader(&self) -> &Mutex<FramedRead<OwnedReadHalf, StealthStreamCodec>> { &self.reader }
}

impl From<TcpStream> for StealthStream {
	fn from(stream: TcpStream) -> Self {
		let (read_half, write_half) = stream.into_split();
		let framed_reader: FramedRead<OwnedReadHalf, StealthStreamCodec> =
			FramedRead::new(read_half, StealthStreamCodec);
		let framed_writer: FramedWrite<OwnedWriteHalf, StealthStreamCodec> =
			FramedWrite::new(write_half, StealthStreamCodec);

		Self {
			writer: Mutex::new(framed_writer),
			reader: Mutex::new(framed_reader),
		}
	}
}
