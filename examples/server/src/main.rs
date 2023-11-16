use std::{net::IpAddr, sync::Arc};

use stealthstream::{client::RawClient, pin_callback, protocol::StealthStreamMessage, server::ServerBuilder};
use tracing::{debug, info};
use tracing_subscriber::filter::LevelFilter;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

async fn callback_function(message_type: StealthStreamMessage, client: Arc<RawClient>) {
	debug!("Received message: {}", message_type);
	if let StealthStreamMessage::Message(_) = message_type {
		let _ = client
			.send(StealthStreamMessage::create_utf8_message("Hey from server"))
			.await;
	}
}

#[tokio::main]
async fn main() -> Result<()> {
	tracing_subscriber::fmt().with_max_level(LevelFilter::DEBUG).init();

	#[allow(unused_mut)]
	let mut server = ServerBuilder::default()
		.address("0.0.0.0".parse::<IpAddr>().unwrap())
		.with_event_handler(|message_type, client| {
			pin_callback!({
				callback_function(message_type, client).await;
			})
		});

	#[cfg(feature = "tls")]
	let mut server = server
		.cert_file_path("/Users/ehuff/Documents/VsCodeProjects/TcpTest/stealthstream/examples/server/cert.pem")
		.key_file_path("/Users/ehuff/Documents/VsCodeProjects/TcpTest/stealthstream/examples/server/key.pem");

	let server = server.build().await?;

	info!("StealthStream server listening on {}", server.address());
	server.listen().await?;

	Ok(())
}
