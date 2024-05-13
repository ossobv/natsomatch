use futures::StreamExt; // needed for sub.next()

use crate::config_parser;
use crate::misc_nats;


pub struct Input {
    sub: async_nats::Subscriber,
}

impl Input {
    pub async fn from_config(input: &config_parser::NatsConfig) -> Result<Input, Box<dyn std::error::Error>> {
        println!("Connecting to NATS (input) {} ...", input.server);
        let nc_in = misc_nats::connect("nats2jetstream-rs-nats-input", &input.server, &input.tls, &input.auth).await?;
        let subscription = nc_in.subscribe(input.subject.clone()).await?;

        println!("Connected to NATS server INPUT+SUB {:?}", nc_in);
        println!("- subscription ({}): {:?}", input.subject, subscription);
        println!("");

        Ok(Input {
            sub: subscription,
        })
    }

    pub async fn next(&mut self) -> Option<async_nats::Message> {
        self.sub.next().await
    }
}
