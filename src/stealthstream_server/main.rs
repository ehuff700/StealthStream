use std::sync::Arc;

use stealthstream_library::{
	connection::{Client, StealthStreamMessage},
	ServerBuilder,
};
use tracing::debug;
use tracing_subscriber::filter::LevelFilter;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

async fn callback_function(message_type: StealthStreamMessage, client: Arc<Client>) {
	if let StealthStreamMessage::Message(message) = message_type {
		debug!("Received message: {:?}", message);
		let _ = client
			.send(StealthStreamMessage::Message("Hey from server".to_string()))
			.await;
	} else if let StealthStreamMessage::Goodbye(message) = message_type {
		debug!("Received goodbye message: {:?}", message);
	}
}

#[tokio::main]
async fn main() -> Result<()> {
	tracing_subscriber::fmt().with_max_level(LevelFilter::DEBUG).init();

	let server = ServerBuilder::default()
		.with_event_handler(|message_type, client| {
			Box::pin(async {
				callback_function(message_type, client).await;
			})
		})
		.build()
		.await?;

	server.listen().await?;

	Ok(())
}
