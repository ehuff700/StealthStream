use std::{net::SocketAddr, process, sync::Arc};

#[cfg(feature = "tls")]
use rustls::ServerConfig;
use tokio::{net::TcpListener, signal, sync::mpsc};
#[cfg(feature = "tls")]
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info};

use super::{MessageCallback, ServerResult};
use crate::{
	client::RawClient,
	protocol::{constants::INVALID_HANDSHAKE, Handshake, StealthStreamMessage, StealthStreamPacketError},
};

pub struct Server {
	listener: TcpListener,
	address: SocketAddr,
	poke_delay: u64,
	handshake_timeout: u64,
	event_handler: Arc<dyn MessageCallback>,
	#[cfg(feature = "tls")]
	tls_config: Arc<ServerConfig>,
}
impl Server {
	/// Used internally by the ServerBuilder to create a new [Server] instance.
	pub(super) fn new(
		listener: TcpListener, address: SocketAddr, poke_delay: u64, handshake_timeout: u64,
		event_handler: Arc<dyn MessageCallback>, #[cfg(feature = "tls")] server_config: Option<ServerConfig>,
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
			handshake_timeout,
			event_handler,
			#[cfg(feature = "tls")]
			tls_config: Arc::new(server_config.unwrap()),
		}
	}

	/// Listens for incoming connections, blocking the current task.
	///
	/// On connection, client will be created from the [tokio::net::TcpStream]
	/// and [SocketAddr]. This task will be responsible for reading the stream
	/// for the lifecycle of the connection and processing messages.
	pub async fn listen(&self) -> ServerResult<()> {
		#[cfg(feature = "tls")]
		let acceptor = TlsAcceptor::from(self.tls_config.clone());

		loop {
			match self.listener.accept().await {
				Ok((tcp_stream, address)) => {
					debug!("Accepted connection from {:?}", address);

					#[cfg(feature = "tls")]
					let tls_stream = match acceptor.accept(tcp_stream).await {
						Ok(tls_stream) => tls_stream,
						Err(e) => {
							error!("Error accepting TLS connection: {:?}", e);
							continue;
						},
					};

					#[cfg(not(feature = "tls"))]
					let client = Arc::new(RawClient::from_stream(tcp_stream, address));
					#[cfg(feature = "tls")]
					let client = Arc::new(RawClient::from_tls_stream(tls_stream, address));
					self.handle_client(client).await;
				},
				Err(e) => {
					error!("Error accepting connection: {:?}", e);
				},
			};
		}
	}

	/// Spawns a new read/write task for the provided client, as well as
	/// creating a poke task to keep the connection alive.
	async fn handle_client(&self, client: Arc<RawClient>) {
		let timeout = self.handshake_timeout;
		let handshake_result = Handshake::start_server_handshake(&client, timeout).await;

		if let Err(e) = handshake_result {
			error!("Error handshaking for client: {:?}", e);
			let _ = client.disconnect_with_reason(INVALID_HANDSHAKE, &e.to_string()).await;
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
			client.send(StealthStreamMessage::Heartbeat).await?;
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
				while read_client.is_connected() {
					while let Some(read_result) = read_client.receive().await {
						match read_result {
							Ok(message) => {
								if matches!(message, StealthStreamMessage::Goodbye(_)) {
									if let Err(e) = read_client.disconnect().await {
										error!(
											"Error disconnecting client ({:?}): {:?}",
											read_client.peer_address(),
											e
										);
									};
								}

								// Sends the parsed message to the write task.
								if let Err(e) = tx.send(message).await {
									error!("Error sending message to write task: {:?}", e);
								}
							},
							Err(e) => {
								if let StealthStreamPacketError::StreamClosed = e {
									let _ = read_client.disconnect().await; // force disconnect, throwing away any error type
									break;
								} else {
									error!("Error reading from client ({:?}): {:?}", read_client.peer_address(), e);
									let _ = read_client
										.send(StealthStreamMessage::create_error_message(1, &e.to_string()))
										.await;

									// TODO: Review better error codes
									// perchance?
								}
							},
						};
					}
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

	use super::Server;
	use crate::{
		client::ClientBuilder,
		pin_callback,
		protocol::{control_messages::HandshakeData, data_messages::MessageData, StealthStreamMessage},
		server::{MessageCallback, ServerBuilder},
	};

	macro_rules! server_client_setup {
		() => {{
			let test: Option<Box<dyn MessageCallback>> = None;
			let server = basic_server_setup(test).await;

			let mut client = ClientBuilder::default();
			#[cfg(feature = "tls")]
			let mut client = client.skip_certificate_validation(true)

			let mut client = client.build();
			client
				.connect(server.address())
				.await
				.expect("Failed to connect to server");
			(server, client)
		}};
		($callback:block) => {{
			let server = basic_server_setup(Some($callback)).await;
			#[allow(unused_mut)]
			let mut client = ClientBuilder::default();
			#[cfg(feature = "tls")]
			#[allow(unused_mut)]
			let mut client = client.skip_certificate_validation(true);

			let mut client = client.build();
			client
				.connect(server.address())
				.await
				.expect("Failed to connect to server");
			(server, client)
		}};
		($server_callback:block, $client_callback:block) => {{
			let server = basic_server_setup(Some($server_callback)).await;
			#[allow(unused_mut)]
			let mut client = ClientBuilder::default().with_event_handler($client_callback);
			#[cfg(feature = "tls")]
			let mut client = client.skip_certificate_validation(true)

			let mut client = client.build();
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
		#[cfg(feature = "tls")]
		let base_server = base_server
			.cert_file_path("src/test_cert.pem")
			.key_file_path("src/test_key.pem");

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
		/*tracing_subscriber::fmt()
		.with_max_level(tracing_subscriber::filter::LevelFilter::DEBUG)
		.init();*/

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
		let handshake = StealthStreamMessage::Handshake(HandshakeData::new(1, None));
		let mut test = handshake.to_packet();

		let bytes: Vec<u8> = test.pop().unwrap().into();

		raw_stream
			.write_all(&bytes)
			.await
			.expect("couldn't write bytes to stream");

		raw_stream
			.shutdown()
			.await
			.expect("error shutting down the raw TcpStream");

		let raw_stream_result = timeout(Duration::from_millis(500), rx.recv()).await;
		assert!(raw_stream_result.is_err(), "Somehow recieved a successful message?");

		/* Test Successful Recieve */
		let packet = StealthStreamMessage::Message(MessageData::new(b"test", false));
		c.send(packet).await.expect("error sending message");

		let received = rx.recv().await;
		assert!(received.is_some());
	}
}
