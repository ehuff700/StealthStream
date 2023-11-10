use std::{net::SocketAddr, sync::Arc};

use criterion::{criterion_group, criterion_main, Criterion};
use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use stealthstream::{
	client::{Client, ClientBuilder},
	protocol::StealthStreamMessage,
	server::{Server, ServerBuilder},
};
use tokio::{
	net::{TcpListener, TcpStream},
	sync::Mutex,
};
use tokio_tungstenite::{accept_async, tungstenite::Message};
use tracing::debug;

fn generate_long_utf8_string(length: usize) -> String {
	let repeated_char = 'A'; // Replace with the character you want to repeat
	let long_string: String = std::iter::repeat(repeated_char).take(length).collect();
	long_string
}

async fn stealthstream_server() -> Arc<Server> {
	let mut rng = rand::thread_rng();
	let random_number: u16 = rng.gen_range(1000..10000);

	let server = ServerBuilder::default()
		.port(random_number)
		.with_event_handler(|_, _| Box::pin(async {}))
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

async fn setup_client(address: SocketAddr) -> Client {
	let mut client = ClientBuilder::default().build();
	client.connect(address).await.unwrap();
	client
}

fn my_protocol_benchmark(c: &mut Criterion) {
	let mut group = c.benchmark_group("Stealthstream Group");
	let rt = tokio::runtime::Runtime::new().unwrap();
	let server = rt.block_on(async { stealthstream_server().await });
	let client = rt.block_on(async { setup_client(server.address()).await });
	group.bench_function("stealthstream", |b| {
		let length = 200;

		b.to_async(&rt).iter_batched(
			|| generate_long_utf8_string(length),
			|message| async {
				client
					.send(StealthStreamMessage::Message(message))
					.await
					.expect("Couldn't send message from client");
			},
			criterion::BatchSize::SmallInput,
		);
	});
	group.finish();
}

async fn handle_connection(stream: TcpStream) {
	if let Ok(ws_stream) = accept_async(stream).await {
		let (_, mut ws_receiver) = ws_stream.split();
		while (ws_receiver.next().await).is_some() {
			debug!("Recieved message: {:?}", ws_receiver)
		}
	}
}

async fn run_server(random_number: u16) -> String {
	// Bind a TCP listener to an address
	let listener = TcpListener::bind(format!("127.0.0.1:{random_number}"))
		.await
		.expect("couldn't setup tokio listener");

	tokio::task::spawn({
		async move {
			while let Ok((stream, _)) = listener.accept().await {
				tokio::spawn(handle_connection(stream));
			}
		}
	});

	format!("127.0.0.1:{random_number}")
}

fn tokio_tungstenite_benchmark(c: &mut Criterion) {
	let mut group = c.benchmark_group("Tokio Tungstenite Group");
	let rt = tokio::runtime::Runtime::new().unwrap();
	let mut rng = rand::thread_rng();
	let random_number: u16 = rng.gen_range(1000..10000);

	let address = rt.block_on(run_server(random_number));

	let stream = rt.block_on(async {
		let (ws_stream, _) = tokio_tungstenite::connect_async(format!("ws://{address}"))
			.await
			.expect("couldn't connect to local tokio tungstenite server");
		Arc::new(Mutex::new(ws_stream))
	});

	let length = 200;

	group.bench_function("tokio_tungstenite", |b| {
		b.to_async(&rt).iter_batched(
			|| generate_long_utf8_string(length),
			|message| async {
				let mut guard = stream.lock().await;
				guard.send(Message::Text(message)).await.unwrap();
			},
			criterion::BatchSize::SmallInput,
		)
	});

	group.finish();
}

criterion_group!(benches, my_protocol_benchmark, tokio_tungstenite_benchmark);
criterion_main!(benches);
