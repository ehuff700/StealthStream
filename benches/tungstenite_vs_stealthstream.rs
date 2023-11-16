#![feature(test)]
extern crate test;

use std::sync::Arc;

use futures_util::{future, SinkExt, StreamExt, TryStreamExt};
use rand::Rng;
use stealthstream::{
	self, pin_callback,
	server::{Server, ServerBuilder},
};
use tokio::{
	net::{TcpListener, TcpStream},
	sync::Mutex,
};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use url::Url;

#[allow(dead_code)]
fn generate_long_utf8_string(length: usize) -> String {
	let repeated_char = 'A'; // Replace with the character you want to repeat
	let long_string: String = std::iter::repeat(repeated_char).take(length).collect();
	long_string
}

/// Sets up a simple echo server for stealthstream
async fn setup_stealthstream_server() -> Arc<Server> {
	let mut rng = rand::thread_rng();
	let random_port: u16 = rng.gen_range(1000..=65535);
	let server = ServerBuilder::default()
		.port(random_port)
		.with_event_handler(|msg, client| {
			pin_callback!({
				let _ = client.send(msg).await;
			})
		})
		.build()
		.await
		.unwrap();

	let server = Arc::new(server);

	tokio::task::spawn({
		let task_server = server.clone();
		async move {
			task_server.listen().await.unwrap();
		}
	});
	server
}

/// Sets up a simple echo server for tokio-tungstenite
///
/// Returns the address the echo server is listening on
async fn setup_tokio_tungstenite_server() -> String {
	async fn handle_connection(stream: TcpStream) {
		let ws_stream = tokio_tungstenite::accept_async(stream)
			.await
			.expect("Error during the websocket handshake occurred");

		let (write, read) = ws_stream.split();
		// We should not forward messages other than text or binary.
		read.try_filter(|msg| future::ready(msg.is_text() || msg.is_binary()))
			.forward(write)
			.await
			.expect("Failed to forward messages")
	}

	let mut rng = rand::thread_rng();
	let random_port: u16 = rng.gen_range(1000..=65535);

	let listener = TcpListener::bind(format!("127.0.0.1:{random_port}"))
		.await
		.expect("couldn't setup tokio listener");

	tokio::task::spawn({
		async move {
			while let Ok((stream, _)) = listener.accept().await {
				tokio::spawn(handle_connection(stream));
			}
		}
	});

	format!("127.0.0.1:{random_port}")
}

#[cfg(test)]
mod tests {
	use stealthstream::{client::ClientBuilder, protocol::StealthStreamMessage};
	use test::Bencher;

	use super::*;

	#[bench]
	fn stealthstream_benchmark(b: &mut Bencher) {
		let rt = tokio::runtime::Runtime::new().unwrap();
		let server = rt.block_on(async { setup_stealthstream_server().await });
		let client = rt.block_on(async {
			let mut client = ClientBuilder::default().build();
			client
				.connect(server.address())
				.await
				.expect("couldn't connect to local stealthstream server");
			client
		});

		let inner = client.inner().unwrap();

		b.iter(|| {
			let inner = inner.clone();
			let guard = rt.enter();

			let fut = tokio::task::spawn(async move {
				let _ = inner
					.send(StealthStreamMessage::create_utf8_message("Hello World"))
					.await;
				inner.receive().await;
			});
			drop(guard);
			let _ = rt.block_on(fut);
		})
	}

	#[bench]
	fn tokio_tungstenite_benchmark(b: &mut Bencher) {
		let rt = tokio::runtime::Runtime::new().unwrap();

		let address = rt.block_on(setup_tokio_tungstenite_server());
		let (original_socket, _) = rt.block_on(async {
			connect_async(Url::parse(&format!("ws://{address}")).unwrap())
				.await
				.expect("Failed to connect")
		});

		let socket = Arc::new(Mutex::new(original_socket)); // Wrap the socket in a shared, lockable Arc

		b.iter(|| {
			let socket_clone = Arc::clone(&socket);

			async move {
				let mut ws_socket = socket_clone.lock().await;

				ws_socket
					.send(Message::Text("Hello World".to_string()))
					.await
					.expect("Failed to send message");

				if let Some(msg) = ws_socket.next().await {
					match msg {
						Ok(msg) => {
							assert_eq!(msg, Message::Text("Hello World".to_string()));
						},
						Err(e) => panic!("Error during the websocket communication: {:?}", e),
					}
				}
			}
		});

		rt.block_on(async {
			let _ = socket.lock().await.close(None).await;
		});
	}
}
