use std::{io, sync::Arc};

use tokio::{
	io::AsyncWriteExt,
	net::{
		tcp::{OwnedReadHalf, OwnedWriteHalf},
		TcpStream,
	},
	sync::{Mutex, RwLock},
};
use tracing::{debug, trace};

use crate::{protocol::StealthStreamMessage, StealthStreamResult};

use super::StealthStreamPacket;

#[derive(Debug, Clone)]
pub struct StealthStream {
	write_half: Arc<Mutex<OwnedWriteHalf>>,
	read_half: Arc<RwLock<OwnedReadHalf>>,
}

impl StealthStream {
	/// Converts a [TcpStream] into a [StealthStream].
	fn from_tcp_stream(stream: TcpStream) -> Self {
		let (read_half, write_half) = stream.into_split();
		Self {
			write_half: Arc::new(Mutex::new(write_half)),
			read_half: Arc::new(RwLock::new(read_half)),
		}
	}

	/// Writes arbitrary data to the underlying stream.
	pub async fn write(&self, data: StealthStreamPacket) -> io::Result<()> {
		let mut writer = self.write_half.lock().await;
		writer.writable().await?;
		let content: Vec<u8> = data.into();

		let write_result = match writer.try_write(&content) {
			Ok(n) => {
				trace!("Wrote {} bytes to the stream", n);
				writer.flush().await?;
				Ok(())
			},
			Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
				debug!("Would block??"); // TODO: revisit what this means
				Ok(())
			},
			Err(e) => Err(e),
		};
		drop(writer);
		write_result
	}

	/// Reads a [StealthStreamMessage] from the underlying stream.
	pub async fn read(&self) -> StealthStreamResult<StealthStreamMessage> {
		let mut reader = self.read_half.write().await;
		reader.readable().await?;
		let packet = StealthStreamPacket::from_stream(&mut *reader).await;
		drop(reader);

		// Return the proper message type with custom message processing applied.
		StealthStreamMessage::from_message(&packet.unwrap()) // TODO: fix this
	}

	/// Shuts down the underlying stream.
	pub async fn close(&self) {
		let mut write_half = self.write_half.lock().await;
		write_half.shutdown().await.unwrap();
	}

	/* Getters */
	pub fn writer(&self) -> &Arc<Mutex<OwnedWriteHalf>> {
		&self.write_half
	}

	pub fn reader(&self) -> &Arc<RwLock<OwnedReadHalf>> {
		&self.read_half
	}
}

impl From<TcpStream> for StealthStream {
	fn from(stream: TcpStream) -> Self {
		Self::from_tcp_stream(stream)
	}
}
