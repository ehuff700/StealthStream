use stealthstream::{
	client::ClientBuilder,
	protocol::{MessageData, StealthStreamMessage},
};
use tracing::error;
use tracing_subscriber::filter::LevelFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
	tracing_subscriber::fmt().with_max_level(LevelFilter::DEBUG).init();

	let mut client = ClientBuilder::default().build();
	//client.connect("192.155.94.253:7007").await?;

	client.connect("127.0.0.1:7007").await?;
	client.listen().await?;

	while client.is_connected() {
		if let Err(why) = client
			.send(StealthStreamMessage::Message(MessageData::new("how are you", false)))
			.await
		{
			error!("{}", why);
			break;
		}

		tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
	}

	Ok(())
}
