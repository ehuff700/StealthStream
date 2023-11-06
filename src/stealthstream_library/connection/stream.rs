use std::{io, sync::Arc};

use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::{
		tcp::{OwnedReadHalf, OwnedWriteHalf},
		TcpStream,
	},
	sync::Mutex,
};
use tracing::{debug, trace};

use crate::{StealthStreamMessage, StealthStreamResult};

#[derive(Debug, Clone)]
pub struct StealthStream {
	write_half: Arc<Mutex<OwnedWriteHalf>>,
	read_half: Arc<Mutex<OwnedReadHalf>>,
}

impl StealthStream {
	/// Converts a [TcpStream] into a [StealthStream].
	pub fn from_tcp_stream(stream: TcpStream) -> Self {
		let (read_half, write_half) = stream.into_split();
		Self {
			write_half: Arc::new(Mutex::new(write_half)),
			read_half: Arc::new(Mutex::new(read_half)),
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
	pub async fn read(&self) -> StealthStreamResult<Option<StealthStreamMessage>> {
		let mut reader = self.read_half.lock().await;
		reader.readable().await?;

		// Read the singular opco byte to determine which message this is.
		let mut opcode_buffer = [0u8; 1];
		reader.read_exact(&mut opcode_buffer).await?;
		let opcode = opcode_buffer[0];
		let message_type = StealthStreamMessage::from_opcode(opcode)?;

		// Read the length buffer to find the length of the message
		let mut length_buffer = [0u8; 2];
		reader.read_exact(&mut length_buffer).await?;

		// Finally, use the length buffer to read the actual message content
		let length = u16::from_be_bytes(length_buffer);
		let mut message_buffer = vec![0u8; length as usize];
		reader.read_exact(&mut message_buffer).await?;

		drop(reader);

		// Return the proper message, applying any needed processing
		let message = match message_type {
			StealthStreamMessage::Goodbye(_) => {
				let reason = if !message_buffer.is_empty() {
					Some(String::from_utf8(message_buffer)?)
				} else {
					None
				};
				StealthStreamMessage::Goodbye(reason)
			},
			StealthStreamMessage::Message(_) => {
				let message = String::from_utf8(message_buffer)?;
				StealthStreamMessage::Message(message)
			},
			_ => message_type,
		};

		Ok(Some(message))
	}

	/// Called by the server to shutdown the underlying stream.
	pub async fn shutdown_stream(&self) {
		let mut write_half = self.write_half.lock().await;
		write_half.shutdown().await.unwrap();
	}
}
