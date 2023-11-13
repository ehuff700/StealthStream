use futures_util::{SinkExt, StreamExt};
use tokio::{
	net::{
		tcp::{OwnedReadHalf, OwnedWriteHalf},
		TcpStream,
	},
	sync::Mutex,
};
use tokio_util::codec::{FramedRead, FramedWrite};

use super::{StealthStreamCodec, StealthStreamPacket, StealthStreamPacketErrors};
use crate::protocol::StealthStreamMessage;

#[derive(Debug)]
pub struct StealthStream {
	writer: Mutex<FramedWrite<OwnedWriteHalf, StealthStreamCodec>>,
	reader: Mutex<FramedRead<OwnedReadHalf, StealthStreamCodec>>,
}

impl StealthStream {
	pub async fn write(&self, data: StealthStreamPacket) -> Result<(), StealthStreamPacketErrors> {
		let mut writer = self.writer.lock().await;
		writer.send(data).await
	}

	/// Reads a [StealthStreamMessage] from the underlying stream. // TODO:
	/// update docs
	pub async fn read(&self) -> Option<Result<StealthStreamMessage, StealthStreamPacketErrors>> {
		let mut guard = self.reader.lock().await;
		if let Some(result) = guard.next().await {
			match result {
				Ok(ref packet) => Some(StealthStreamMessage::from_message_v2(packet)),
				Err(e) => Some(Err(e)),
			}
		} else {
			None
		}
	}

	/// Shuts down the underlying stream.
	pub async fn close(&self) {
		let mut write_half = self.writer.lock().await;
		let _ = write_half.flush().await; // FIXME
		let _ = write_half.close().await; // FIXME
		                          // TODO: explore if TcpStream needs to be
		                          // closed as well
	}

	/// Used internally for fuzzing input.
	#[cfg(test)]
	pub(crate) fn write_half(&self) -> &Mutex<FramedWrite<OwnedWriteHalf, StealthStreamCodec>> { &self.writer }
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
