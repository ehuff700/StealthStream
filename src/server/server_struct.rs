use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::{
	client::{Client, RawClient},
	errors::{HandshakeErrors, ServerErrors},
	protocol::{StealthStreamMessage, INVALID_HANDSHAKE, SUPPORTED_VERSIONS},
};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{debug, error, info};
use uuid::Uuid;

use super::{MessageCallback, ServerResult};

pub struct Server {
	listener: TcpListener,
	address: SocketAddr,
	poke_delay: u64,
	#[allow(dead_code)]
	clients: HashMap<Uuid, Client>, // TODO: implement this
	event_handler: Arc<dyn MessageCallback>,
}

impl Server {
	/// Used internally by the ServerBuilder to create a new [Server] instance.
	pub(super) fn new(
		listener: TcpListener, address: SocketAddr, poke_delay: u64, event_handler: Arc<dyn MessageCallback>,
	) -> Self {
		Self {
			listener,
			address,
			poke_delay,
			clients: HashMap::new(),
			event_handler,
		}
	}
	/// Listens for incoming connections, blocking the current task.
	///
	/// On connection, client will be created from the [tokio::net::TcpStream] and [SocketAddr]. This task will be responsible for
	/// reading the stream for the lifecycle of the connection and processing messages.
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

	/// Utility function that validates a [StealthStreamMessage::Handshake] message.
	fn validate_handshake(version: u8, session_id: Option<Uuid>) -> Result<(), HandshakeErrors> {
		if !SUPPORTED_VERSIONS.contains(&version) {
			return Err(HandshakeErrors::UnsupportedVersion(version));
		}

		if let Some(session_id) = session_id {
			if session_id.is_nil() || session_id.get_version_num() != 4 {
				return Err(HandshakeErrors::InvalidSessionId(session_id));
			}
		}

		Ok(())
	}

	async fn inititalize_handshake(&self, client: &Arc<RawClient>) -> ServerResult<()> {
		if let StealthStreamMessage::Handshake { version, session_id } = client.recieve().await? {
			debug!("Received version {} handshake from {:?}", version, client.peer_address());
			Self::validate_handshake(version, session_id).map_err(ServerErrors::from)?;

			// TODO: do something with session_id
			info!("Upgraded connection to StealthStream for client {:?}", client.peer_address());
			Ok(())
		} else {
			Err(ServerErrors::InvalidHandshake(HandshakeErrors::SkippedHandshake))?
		}
	}

	/// Spawns a new read/write task for the provided client, as well as creating a poke task to keep the connection alive.
	async fn handle_client(&self, client: Arc<RawClient>) {
		let handshake_result = self.inititalize_handshake(&client).await;

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

			let (write_tx, write_rx) = mpsc::channel::<StealthStreamMessage>(32);
			Self::spawn_read_task(&client, write_tx);
			self.spawn_write_task(&client, write_rx);
		}
	}

	/// Pokes the client to keep the connection alive, according to the configured delay.
	async fn poke_task(client: Arc<RawClient>, delay: u64) -> ServerResult<()> {
		while client.is_connected() {
			client.send(StealthStreamMessage::Poke).await?;
			debug!("Poking connection for {:?}", client.peer_address());
			tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
		}
		Ok(())
	}

	/// Spawns a read task that will read messages from the client and use the mpsc channel to send them to the write task.
	fn spawn_read_task(client: &Arc<RawClient>, tx: mpsc::Sender<StealthStreamMessage>) {
		tokio::task::spawn({
			let read_client = client.clone();
			async move {
				while read_client.is_connected() {
					let result = read_client.recieve().await;
					match result {
						Ok(message) => {
							if let StealthStreamMessage::Goodbye { reason, code } = &message {
								read_client.disconnect().await.unwrap();

								info!(
									"Recieved goodbye message from {:?}. Code: {:?} | Reason: {:?}",
									read_client.peer_address(),
									code,
									reason,
								);
							}

							if let Err(e) = tx.send(message).await {
								error!("Error sending message to write task: {:?}", e);
							}
						},
						Err(e) => {
							error!("Error reading from client: {:?}", e);
							break;
						},
					};
				}
			}
		});
	}

	/// Spawns a write task that will recieve messages from the mpsc channel and write them to the client.
	fn spawn_write_task(&self, client: &Arc<RawClient>, mut rx: mpsc::Receiver<StealthStreamMessage>) {
		tokio::task::spawn({
			let write_client = client.clone();
			let callback = self.event_handler.clone();

			async move {
				while write_client.is_connected() {
					while let Some(message) = rx.recv().await {
						// The callback returns a future which we *must* await
						// otherwise the code inside the callback will effectively be dead.
						callback(message, write_client.clone()).await;
					}
				}
			}
		});
	}

	/* Getters */
	pub fn address(&self) -> SocketAddr {
		self.address
	}
}
