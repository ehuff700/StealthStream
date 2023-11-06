use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use crate::connection::Client;
use crate::connection::StealthStreamMessage;
use crate::errors::Error;
use anyhow::anyhow;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{debug, error, info};
use uuid::Uuid;

pub type ServerResult<T> = std::result::Result<T, Error>;

// TODO: implement builder pattern
#[allow(dead_code)]
pub struct ServerBuilder {
	address: IpAddr,
	port: u16,
	poke_delay: u64,
}

pub struct Server {
	listener: TcpListener,
	address: SocketAddr,
	#[allow(dead_code)]
	clients: HashMap<Uuid, Client>, // TODO: implement this
}

impl Server {
	/// Binds the server to the given socket address.
	pub async fn bind<T>(addr: T) -> ServerResult<Self>
	where
		T: ToSocketAddrs,
	{
		let address = addr
			.to_socket_addrs()?
			.next()
			.ok_or(Error::ServerError(anyhow!("Invalid SocketAddress provided").into()))?;

		let listener = TcpListener::bind(address).await?;
		info!("StealthStream server listening on {}", address);

		Ok(Server {
			address,
			listener,
			clients: HashMap::new(),
		})
	}

	/// Listens for incoming connections.
	///
	/// On connection, the callback will be passed to a new tokio task. This task will be responsible for
	/// reading the stream for the lifecycle of the connection and processing messages.
	pub async fn listen<F, Fut>(&self, callback: F) -> ServerResult<()>
	where
		F: Fn(StealthStreamMessage, Arc<Client>) -> Fut + Send + Sync + 'static,
		Fut: Future<Output = ()> + Send + 'static,
	{
		let arced_callback = Arc::new(callback);

		loop {
			match self.listener.accept().await {
				Ok((socket, addr)) => {
					debug!("Accepted connection from {:?}", addr);
					let cloned_callback = arced_callback.clone();
					let client = Arc::new(Client::from_stream(socket, addr));
					// TODO: insert client into hashmap
					tokio::spawn(Self::handle_client(client, cloned_callback));
				},
				Err(e) => {
					error!("Couldn't get client: {:?}", e);
					return Err(e.into());
				},
			}
		}
	}

	/// Handles the client connection by looping over the socket.
	async fn handle_client<F, Fut>(client: Arc<Client>, callback: Arc<F>)
	where
		F: Fn(StealthStreamMessage, Arc<Client>) -> Fut + Send + Sync + 'static,
		Fut: Future<Output = ()> + Send + 'static,
	{
		tokio::task::spawn(Self::poke_task(client.clone()));

		let (write_tx, write_rx) = mpsc::channel::<StealthStreamMessage>(32);
		Self::spawn_read_task(&client, write_tx);
		Self::spawn_write_task(&client, write_rx, callback);
	}

	/// Pokes the client to keep the connection alive.
	async fn poke_task(client: Arc<Client>) -> ServerResult<()> {
		while client.is_connected() {
			client.send(StealthStreamMessage::Poke).await?;
			debug!("Poking connection for {:?}", client.address());
			tokio::time::sleep(std::time::Duration::from_millis(5000)).await;
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
	fn spawn_write_task<F, Fut>(client: &Arc<Client>, mut rx: mpsc::Receiver<StealthStreamMessage>, callback_fn: Arc<F>)
	where
		F: Fn(StealthStreamMessage, Arc<Client>) -> Fut + Send + Sync + 'static,
		Fut: Future<Output = ()> + Send + 'static,
	{
		tokio::task::spawn({
			let write_client = client.clone();
			async move {
				while write_client.is_connected() {
					while let Some(message) = rx.recv().await {
						tokio::task::spawn(callback_fn(message, write_client.clone()));
					}
				}
			}
		});
	}

	/* Getters */
	pub fn addr(&self) -> SocketAddr {
		self.address
	}
}
