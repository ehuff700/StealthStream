use serde::{Deserialize, Serialize};
use stealthstream::{
	client::ClientBuilder,
	protocol::{data::AcknowledgeData, StealthStreamMessage},
};
use tracing::{debug, error};
use tracing_subscriber::filter::LevelFilter;
use uuid::Uuid;

#[allow(dead_code)]
#[derive(Deserialize, Serialize, Debug)]
pub struct TestAck {
	string: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
	tracing_subscriber::fmt().with_max_level(LevelFilter::DEBUG).init();

	#[cfg(feature = "tls")]
	let mut client = ClientBuilder::default().skip_certificate_validation(true).build();
	#[cfg(not(feature = "tls"))]
	let mut client = ClientBuilder::default().build();

	//client.connect("192.155.94.253:7007").await?;

	client.connect("127.0.0.1:7007").await?;

	tokio::task::spawn({
		let cloned = client.clone();
		async move {
			// prefer listen_with_ack over listen when you use send_with_ack
			if let Err(e) = cloned.listen_with_ack().await {
				error!("Error listening: {:?}", e);
			}
		}
	});

	let test = client
		.send_with_ack::<TestAck>(AcknowledgeData::new(
			Uuid::new_v4(),
			TestAck {
				string: "test".to_string(),
			},
		))
		.await;

	debug!("test: {:?}", test);

	while client.is_connected() {
		if let Err(why) = client
			.send(StealthStreamMessage::create_utf8_message("how are you"))
			.await
		{
			error!("{}", why);
			break;
		}

		tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
	}

	Ok(())
}
