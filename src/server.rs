use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;

use crate::protocol::StealthStreamMessage;
use crate::errors::Error;
use crate::Client;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{debug, error, info};
use uuid::Uuid;

pub type ServerResult<T> = std::result::Result<T, Error>;

/// Type alias used to indicate a pinned and boxed future.
pub type BoxedCallbackFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// This trait is used by the [Server] and [Client] to handle incoming messages.
pub trait MessageCallback:
	Fn(StealthStreamMessage, Arc<Client>) -> BoxedCallbackFuture + Sync + Send + 'static
{
}

impl<F> MessageCallback for F where
	F: Fn(StealthStreamMessage, Arc<Client>) -> BoxedCallbackFuture + Sync + Send + 'static
{
}

/// Utility Struct to build a [Server] as needed
pub struct ServerBuilder {
	/// The Ip Address to bind the server to.
	address: IpAddr,
	/// The port number to bind to
	port: u16,
	/// The delay between each [StealthStreamMessage::Poke] message in ms.
	poke_delay: u64,
	/// The event handler that will be invoked when a [StealthStreamMessage] is received
	event_handler: Option<Arc<dyn MessageCallback>>,
}

impl ServerBuilder {
	fn new() -> Self {
		Self {
			address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
			port: 7007,
			poke_delay: 5000,
			event_handler: None,
		}
	}

	/// Sets the ip address to bind the server to (localhost loopback by default).
	pub fn address(mut self, address: IpAddr) -> Self {
		self.address = address;
		self
	}

	/// Sets the port number to bind to (7007 by default).
	pub fn port(mut self, port: u16) -> Self {
		self.port = port;
		self
	}

	/// Determines the delay between each iteration of the [StealthStreamMessage::Poke] task, in ms.
	///
	/// 5000 ms by default.
	pub fn set_poke_delay(mut self, poke_delay: u64) -> Self {
		self.poke_delay = poke_delay;
		self
	}

	/// Uses the provided event handler to handle [StealthStreamMessage]s.
	pub fn with_event_handler(mut self, event_handler: impl MessageCallback) -> Self {
		self.event_handler = Some(Arc::new(event_handler));
		self
	}

	pub async fn build(self) -> ServerResult<Server> {
		let address = SocketAddr::new(self.address, self.port);
		let listener = TcpListener::bind(address).await?;
		let event_handler = self.event_handler.unwrap_or_else(|| Self::default_event_handler());

		info!("StealthStream server listening on {}", address);
		Ok(Server {
			listener,
			address: SocketAddr::new(self.address, self.port),
			poke_delay: self.poke_delay,
			clients: HashMap::new(),
			event_handler,
		})
	}

	fn default_event_handler() -> Arc<dyn MessageCallback> {
		let handler = |message: StealthStreamMessage, _: Arc<Client>| {
			debug!("Received message: {:?}", message);
			Box::pin(async move {}) as BoxedCallbackFuture
		};
		Arc::new(handler)
	}
}

impl Default for ServerBuilder {
	fn default() -> Self {
		Self::new()
	}
}

pub struct Server {
	listener: TcpListener,
	address: SocketAddr,
	poke_delay: u64,
	#[allow(dead_code)]
	clients: HashMap<Uuid, Client>, // TODO: implement this
	event_handler: Arc<dyn MessageCallback>,
}

impl Server {
	/// Listens for incoming connections, blocking the current task.
	///
	/// On connection, client will be created from the [tokio::net::TcpStream] and [SocketAddr]. This task will be responsible for
	/// reading the stream for the lifecycle of the connection and processing messages.
	pub async fn listen(&self) -> ServerResult<()> {
		loop {
			match self.listener.accept().await {
				Ok((socket, addr)) => {
					debug!("Accepted connection from {:?}", addr);

					let client = Arc::new(Client::from_stream(socket, addr));
					self.handle_client(client).await;
				},
				Err(e) => {
					error!("Error accepting connection: {:?}", e);
					return Err(e.into());
				},
			}
		}
	}

	/// Spawns a new read/write task for the provided client, as well as creating a poke task to keep the connection alive.
	async fn handle_client(&self, client: Arc<Client>) {
		let delay = self.poke_delay;
		tokio::task::spawn(Self::poke_task(client.clone(), delay));

		let (write_tx, write_rx) = mpsc::channel::<StealthStreamMessage>(32);
		Self::spawn_read_task(&client, write_tx);
		self.spawn_write_task(&client, write_rx);
	}

	/// Pokes the client to keep the connection alive, according to the configured delay.
	async fn poke_task(client: Arc<Client>, delay: u64) -> ServerResult<()> {
		while client.is_connected() {
			client.send(StealthStreamMessage::Poke).await?;
			debug!("Poking connection for {:?}", client.address());
			tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
		}
		Ok(())
	}

	/// Spawns a read task that will read messages from the client and use the mpsc channel to send them to the write task.
	fn spawn_read_task(client: &Arc<Client>, tx: mpsc::Sender<StealthStreamMessage>) {
		tokio::task::spawn({
			let read_client = client.clone();
			async move {
				while read_client.is_connected() {
					let result = read_client.recieve().await;
					match result {
						Ok(message) => {
							if let StealthStreamMessage::Goodbye(reason) = &message {
								read_client.socket().close().await;
								read_client.set_connection_state(false);
								info!(
									"Recieved goodbye message from {:?} citing reason: {:?}",
									read_client.address(),
									reason
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
	fn spawn_write_task(&self, client: &Arc<Client>, mut rx: mpsc::Receiver<StealthStreamMessage>) {
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
