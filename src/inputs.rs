//use futures_util::stream::stream::StreamExt;
//use futures_util::stream::stream::StreamExt;
//use futures_util::stream::try_stream::TryStreamExt;
use futures::StreamExt;

use crate::config_parser;
use crate::misc_nats;


pub struct Input {
    _config: config_parser::InputConfig,
    _stream: async_nats::jetstream::stream::Stream,
    _consumer: async_nats::jetstream::consumer::PullConsumer,
    messages: async_nats::jetstream::consumer::pull::Stream,
}

impl std::fmt::Debug for Input {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Input {{ ... }}")
    }
}

impl Input {
    pub async fn from_config(input: &config_parser::InputConfig) -> Result<Input, Box<dyn std::error::Error>> {
        let srv = &input.natsconfig;

        println!("Connecting to NATS (input) {} -> {} -> {}...", srv.server, input.stream, input.consumer);
        let nc_in = misc_nats::connect("nats2jetstream-rs-nats-input", &srv.server, &srv.tls, &srv.auth).await?;

        let js = async_nats::jetstream::new(nc_in);
        println!("Connected to NATS+JS (input) with context {:?}", js);

        let stream = js.get_stream(&input.stream).await?;
        println!("Connected to NATS+JS (input) with stream {:?}", stream);

        let consumer: async_nats::jetstream::consumer::PullConsumer =
            stream.get_consumer(&input.consumer).await.unwrap();  // FIXME: poor error handling!
        println!("Connected to NATS (input) with consumer {:?}", consumer);

        let messages = consumer
            .stream()
            .max_messages_per_batch(srv.dev.max_messages_per_batch.into())
            .messages()
            .await?;
        println!("Using development settings {:?}", srv.dev);

        Ok(Input {
            _config: input.clone(),
            _stream: stream,
            _consumer: consumer,
            messages: messages,
        })
    }

    pub async fn next(&mut self) -> Option<Result<async_nats::jetstream::Message, async_nats::error::Error<async_nats::jetstream::consumer::pull::MessagesErrorKind>>> {
        // FIXME: What happens after we return None? Needs checken..
        self.messages.next().await
    }
}
