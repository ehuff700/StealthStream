use std::io;

use tokio::{
	io::AsyncWriteExt,
	net::{
		tcp::{OwnedReadHalf, OwnedWriteHalf},
		TcpStream,
	},
	sync::{Mutex, RwLock},
};
use tracing::{debug, trace};

use super::StealthStreamPacket;
use crate::{protocol::StealthStreamMessage, StealthStreamResult};

#[derive(Debug)]
pub struct StealthStream {
	write_half: Mutex<OwnedWriteHalf>,
	read_half: RwLock<OwnedReadHalf>,
}

impl StealthStream {
	/// Writes arbitrary data to the underlying stream.
	pub async fn write(&self, data: StealthStreamPacket) -> io::Result<()> {
		let mut writer = self.write_half.lock().await;
		let content: Vec<u8> = data.into();

		match writer.try_write(&content) {
			Ok(n) => {
				trace!("wrote {} bytes to the stream", n);
				writer.flush().await?;
				Ok(())
			},
			Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
				debug!("Would block??"); // TODO: revisit what this means
				Ok(())
			},
			Err(e) => Err(e),
		}
	}

	/// Reads a [StealthStreamMessage] from the underlying stream.
	pub async fn read(&self) -> StealthStreamResult<StealthStreamMessage> {
		let mut guard = self.read_half.write().await;
		let mut reader = &mut *guard;
		reader.readable().await?;

		let packet = StealthStreamPacket::from_stream(&mut reader).await?;
		StealthStreamMessage::from_message(&packet)
	}

	/// Shuts down the underlying stream.
	pub async fn close(&self) {
		let mut write_half = self.write_half.lock().await;
		write_half.shutdown().await.unwrap();
	}

	/// Used internally for fuzzing input.
	#[cfg(test)]
	pub(crate) fn write_half(&self) -> &Mutex<OwnedWriteHalf> { &self.write_half }
}

impl From<TcpStream> for StealthStream {
	fn from(stream: TcpStream) -> Self {
		let (read_half, write_half) = stream.into_split();
		Self {
			write_half: Mutex::new(write_half),
			read_half: RwLock::new(read_half),
		}
	}
}
