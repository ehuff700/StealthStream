use std::{net::IpAddr, sync::Arc};

use stealthstream::{client::RawClient, protocol::StealthStreamMessage, server::ServerBuilder};
use tracing::{debug, info};
use tracing_subscriber::filter::LevelFilter;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

async fn callback_function(message_type: StealthStreamMessage, client: Arc<RawClient>) {
	if let StealthStreamMessage::Message(message) = message_type {
		debug!("Received message: {:?}", message);
		let _ = client
			.send(StealthStreamMessage::Message("Hey from server".to_string()))
			.await;
	} else if let StealthStreamMessage::Goodbye { code, reason } = message_type {
		debug!("Received goodbye message: {:?} | {:?}", code, reason);
	}
}

#[tokio::main]
async fn main() -> Result<()> {
	tracing_subscriber::fmt().with_max_level(LevelFilter::DEBUG).init();

	let server = ServerBuilder::default()
		.address("0.0.0.0".parse::<IpAddr>().unwrap())
		.with_event_handler(|message_type, client| {
			Box::pin(async {
				callback_function(message_type, client).await;
			})
		})
		.build()
		.await?;
	info!("StealthStream server listening on {}", server.address());
	server.listen().await?;

	Ok(())
}
