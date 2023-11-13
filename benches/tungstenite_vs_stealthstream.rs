use std::{sync::Arc, time::Duration};

use criterion::{criterion_group, criterion_main, Criterion};
use futures_util::{future, SinkExt, StreamExt, TryStreamExt};
use rand::Rng;
use stealthstream::{
	self,
	client::ClientBuilder,
	pin_callback,
	protocol::StealthStreamMessage,
	server::{Server, ServerBuilder},
};
use tokio::{
	net::{TcpListener, TcpStream},
	sync::Mutex,
};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use url::Url;
const TEST_MESSAGE_LENGTH: usize = 10;

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

fn stealthstream_benchmark(c: &mut Criterion) {
	let mut group = c.benchmark_group("Stealthstream Group");
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

	std::thread::sleep(Duration::from_millis(100));

	let inner = client.inner().unwrap().socket();
	let test_message = generate_long_utf8_string(TEST_MESSAGE_LENGTH);

	group.bench_with_input("stealthstream", &test_message, |b, i| {
		b.to_async(&rt).iter(|| async {
			client
				.send(StealthStreamMessage::Message(i.to_string()))
				.await
				.expect("Couldn't send message from client");
			client.receive().await;
		})
	});

	group.bench_function("stealthstream", |b| {
		b.to_async(&rt).iter_batched(
			|| generate_long_utf8_string(TEST_MESSAGE_LENGTH),
			|message| async {
				client
					.send(StealthStreamMessage::Message(message))
					.await
					.expect("Couldn't send message from client");

				{
					let mut guard = inner.reader().lock().await;
					if let Some(msg) = guard.next().await {
						match msg {
							Ok(_) => {},
							Err(e) => panic!("Error during the websocket communication: {:?}", e),
						}
					}
				}

				/*if let Some(Err(e)) = client.inner().unwrap().receive().await {
					panic!("Error recieving message: {:?}", e);
				}*/
				//client.disconnect().await.expect("couldn't disconnect");
			},
			criterion::BatchSize::LargeInput,
		);
	});
	group.finish();
}

fn tokio_tungstenite_benchmark(c: &mut Criterion) {
	let mut group = c.benchmark_group("Tokio Tungstenite Group");
	let rt = tokio::runtime::Runtime::new().unwrap();

	let address = rt.block_on(setup_tokio_tungstenite_server());
	let (original_socket, _) = rt.block_on(async {
		connect_async(Url::parse(&format!("ws://{address}")).unwrap())
			.await
			.expect("Failed to connect")
	});

	let socket = Arc::new(Mutex::new(original_socket)); // Wrap the socket in a shared, lockable Arc

	group.bench_function("tokio_tungstenite", |b| {
		let socket_clone = Arc::clone(&socket);

		b.to_async(&rt).iter_batched(
			|| generate_long_utf8_string(TEST_MESSAGE_LENGTH),
			move |length| {
				let socket_clone = Arc::clone(&socket_clone);

				async move {
					let mut ws_socket = socket_clone.lock().await;

					ws_socket
						.send(Message::Text(length.clone()))
						.await
						.expect("Failed to send message");

					if let Some(msg) = ws_socket.next().await {
						match msg {
							Ok(msg) => {
								assert_eq!(msg, Message::Text(length));
							},
							Err(e) => panic!("Error during the websocket communication: {:?}", e),
						}
					}
				}
			},
			criterion::BatchSize::SmallInput,
		);
	});

	rt.block_on(async {
		let _ = socket.lock().await.close(None).await;
	});

	group.finish();
}

criterion_group!(benches, stealthstream_benchmark, tokio_tungstenite_benchmark);
criterion_main!(benches);
