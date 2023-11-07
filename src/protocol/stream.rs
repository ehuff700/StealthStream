use std::{io, sync::Arc};

use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::{
		tcp::{OwnedReadHalf, OwnedWriteHalf},
		TcpStream,
	},
	sync::{Mutex, RwLock},
};
use tracing::{debug, trace};

use crate::{protocol::StealthStreamMessage, StealthStreamResult};

#[derive(Debug, Clone)]
pub struct StealthStream {
	write_half: Arc<Mutex<OwnedWriteHalf>>,
	read_half: Arc<RwLock<OwnedReadHalf>>,
}

impl StealthStream {
	/// Converts a [TcpStream] into a [StealthStream].
	pub fn from_tcp_stream(stream: TcpStream) -> Self {
		let (read_half, write_half) = stream.into_split();
		Self {
			write_half: Arc::new(Mutex::new(write_half)),
			read_half: Arc::new(RwLock::new(read_half)),
		}
	}

	/// Writes arbitrary data to the underlying stream.
	pub async fn write(&self, data: &[u8]) -> io::Result<()> {
		let mut writer = self.write_half.lock().await;
		writer.writable().await?;

		let write_result = match writer.try_write(data) {
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

		// Read the singular opco byte to determine which message this is.
		let mut opcode_buffer = [0u8; 1];
		reader.read_exact(&mut opcode_buffer).await?;
		let opcode = opcode_buffer[0];

		// Read the length buffer to find the length of the message
		let mut length_buffer = [0u8; 2];
		reader.read_exact(&mut length_buffer).await?;

		// Finally, use the length buffer to read the actual message content
		let length = u16::from_be_bytes(length_buffer);
		let mut message_buffer = vec![0u8; length as usize];
		reader.read_exact(&mut message_buffer).await?;

		drop(reader);

		// Return the proper message type with custom message processing applied.
		StealthStreamMessage::from_message(opcode, &message_buffer)
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
