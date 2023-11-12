use std::{net::SocketAddr, process, sync::Arc};

use tokio::{net::TcpListener, signal, sync::mpsc};
use tracing::{debug, error, info};

use super::{MessageCallback, ServerResult};
use crate::{
	client::RawClient,
	errors::Error,
	protocol::{constants::INVALID_HANDSHAKE, Handshake, StealthStreamMessage, StealthStreamPacketErrors},
};

pub struct Server {
	listener: TcpListener,
	address: SocketAddr,
	poke_delay: u64,
	event_handler: Arc<dyn MessageCallback>,
}

impl Server {
	/// Used internally by the ServerBuilder to create a new [Server] instance.
	pub(super) fn new(
		listener: TcpListener, address: SocketAddr, poke_delay: u64, event_handler: Arc<dyn MessageCallback>,
	) -> Self {
		#[cfg(feature = "signals")] // TODO: implement this properly or not at all?
		tokio::task::spawn({
			async move {
				signal::ctrl_c().await.unwrap();
				info!("Received SIGINT, shutting down gracefully");
				process::exit(0);
			}
		});

		Self {
			listener,
			address,
			poke_delay,
			event_handler,
		}
	}

	/// Listens for incoming connections, blocking the current task.
	///
	/// On connection, client will be created from the [tokio::net::TcpStream]
	/// and [SocketAddr]. This task will be responsible for reading the stream
	/// for the lifecycle of the connection and processing messages.
	pub async fn listen(&self) -> ServerResult<()> {
		loop {
			match self.listener.accept().await {
				Ok((socket, addr)) => {
					debug!("Accepted connection from {:?}", addr);

					let client = Arc::new(RawClient::from_stream(socket, addr));
					self.handle_client(client).await;
				},
				Err(e) => {
					error!("Error accepting connection: {:?}", e);
					return Err(e.into());
				},
			}
		}
	}

	/// Spawns a new read/write task for the provided client, as well as
	/// creating a poke task to keep the connection alive.
	async fn handle_client(&self, client: Arc<RawClient>) {
		let handshake_result = Handshake::start_server_handshake(&client).await;

		if let Err(e) = handshake_result {
			error!("Error handshaking for client: {:?}", e);
			client
				.disconnect_with_reason(INVALID_HANDSHAKE, &e.to_string())
				.await
				.unwrap();
			drop(client);
		} else {
			let delay = self.poke_delay;
			tokio::task::spawn(Self::poke_task(client.clone(), delay));

			let (write_tx, write_rx) = mpsc::channel::<StealthStreamMessage>(100);
			Self::spawn_read_task(&client, write_tx);
			self.spawn_write_task(&client, write_rx);
		}
	}

	/// Pokes the client to keep the connection alive, according to the
	/// configured delay.
	async fn poke_task(client: Arc<RawClient>, delay: u64) -> ServerResult<()> {
		while client.is_connected() {
			client.send(StealthStreamMessage::Poke).await?;
			debug!("Poking connection for {:?}", client.peer_address());
			tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
		}
		Ok(())
	}

	/// Spawns a read task that will read messages from the client and use the
	/// mpsc channel to send them to the write task.
	fn spawn_read_task(client: &Arc<RawClient>, tx: mpsc::Sender<StealthStreamMessage>) {
		tokio::task::spawn({
			let read_client = client.clone();
			async move {
				loop {
					match read_client.recieve().await {
						Ok(message) => {
							if matches!(message, StealthStreamMessage::Goodbye { .. }) {
								read_client.disconnect().await.unwrap();
							}

							// Sends the parsed message to the write task.
							if let Err(e) = tx.send(message).await {
								error!("Error sending message to write task: {:?}", e);
							}
						},
						Err(e) => {
							// TODO: we need to match the error here and figure out what to do with it.
							if let Error::InvalidPacket(StealthStreamPacketErrors::StreamClosed) = e {
								let _ = read_client.disconnect().await; // force disconnect, throwing away any error type
								break;
							} else {
								error!("Error reading from client ({:?}): {:?}", read_client.peer_address(), e);
								// TODO: send the error back to the client here
							}
						},
					};
				}
			}
		});
	}

	/// Spawns a write task that will recieve messages from the mpsc channel and
	/// send them to the callback/event handler.
	fn spawn_write_task(&self, client: &Arc<RawClient>, mut rx: mpsc::Receiver<StealthStreamMessage>) {
		tokio::task::spawn({
			let write_client = client.clone();
			let callback = self.event_handler.clone();

			async move {
				while let Some(message) = rx.recv().await {
					// The callback returns a future which we *must* await
					// otherwise the code inside the callback will effectively be dead.
					callback(message, write_client.clone()).await;
				}
			}
		});
	}

	/* Getters */
	pub fn address(&self) -> SocketAddr { self.address }
}

#[cfg(test)]
mod tests {
	use std::{sync::Arc, time::Duration};

	use rand::Rng;
	use tokio::{io::AsyncWriteExt, net::TcpStream, time::timeout};
	use tracing::info;
	use tracing_subscriber::filter::LevelFilter;

	use super::Server;
	use crate::{
		pin_callback,
		protocol::{StealthStreamMessage, StealthStreamPacket},
		server::{MessageCallback, ServerBuilder},
	};

	macro_rules! server_client_setup {
		() => {{
			let test: Option<Box<dyn MessageCallback>> = None;

			let server = basic_server_setup(test).await;
			let mut client = $crate::client::ClientBuilder::default().build();
			client
				.connect(server.address())
				.await
				.expect("Failed to connect to server");
			(server, client)
		}};
		($callback:block) => {{
			let server = basic_server_setup(Some($callback)).await;
			let mut client = $crate::client::ClientBuilder::default().build();
			client
				.connect(server.address())
				.await
				.expect("Failed to connect to server");
			(server, client)
		}};
		($server_callback:block, $client_callback:block) => {{
			let server = basic_server_setup(Some($server_callback)).await;
			let mut client = $crate::client::ClientBuilder::default()
				.with_event_handler($client_callback)
				.build();
			client
				.connect(server.address())
				.await
				.expect("Failed to connect to server");
			(server, client)
		}};
	}

	async fn basic_server_setup<T>(callback: Option<T>) -> Arc<Server>
	where
		T: MessageCallback,
	{
		let mut rng = rand::thread_rng();
		let random_number: u16 = rng.gen_range(1000..10000);

		let base_server = ServerBuilder::default().port(random_number);

		let server = if let Some(callback) = callback {
			base_server.with_event_handler(callback)
		} else {
			base_server
		};

		let server = server.build().await.expect("Couldn't build server");

		let server = Arc::new(server);

		tokio::task::spawn({
			let task_server = server.clone();
			async move {
				task_server.listen().await.unwrap();
			}
		});

		server
	}

	#[tokio::test]
	async fn test_early_closure() {
		let (tx, mut rx) = tokio::sync::mpsc::channel(5);
		tracing_subscriber::fmt().with_max_level(LevelFilter::DEBUG).init();
		let (server, c) = server_client_setup!({
			move |recieved_message, _| {
				let tx = tx.clone();
				info!("Recieved message: {:?}", recieved_message);
				pin_callback!({
					tx.send(recieved_message).await.unwrap();
				})
			}
		});

		/* send bad message from raw TCP */
		let mut raw_stream = TcpStream::connect(server.address())
			.await
			.expect("couldn't connect to server");
		let handshake = StealthStreamMessage::Handshake {
			version: 1,
			session_id: None,
		};
		let bytes: Vec<u8> = StealthStreamPacket::from(handshake).into();

		raw_stream
			.write_all(&bytes)
			.await
			.expect("couldn't write bytes to stream");

		raw_stream
			.shutdown()
			.await
			.expect("error shutting down the raw TcpStream");

		let raw_stream_result = timeout(Duration::from_millis(500), rx.recv()).await; // This should fall with a "StreamClosed" error
		assert!(raw_stream_result.is_err());

		/* Test Successful Recieve */
		let packet = StealthStreamMessage::Message("test".to_string());
		c.send(packet).await.expect("error sending message");

		let received = rx.recv().await;
		assert!(received.is_some());
	}
}
