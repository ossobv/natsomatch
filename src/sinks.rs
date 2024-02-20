use std::error::Error;

use bytes::Bytes;

use crate::config_parser;
use crate::misc_nats;


pub struct Sink {
    jsctx: async_nats::jetstream::context::Context,
}

impl Sink {
    pub async fn from_config(sink: &config_parser::JetStreamConfig) -> Result<Sink, Box<dyn Error>> {
        println!("Connecting to NATS (sink) {} ...", sink.server);
        let nc_out = misc_nats::connect("nats2jetstream-rs-jetstream-sink", &sink.server, &sink.tls).await?;
        let js = async_nats::jetstream::new(nc_out);

        // XXX: move to configparser
        let js_subjects: Vec<String> = sink.subject_any.split(',').map(|s| s.to_string()).collect();

        println!("Setting up JetStream stream {} {:?} ...", sink.name, js_subjects);
        let stream_info = js.get_or_create_stream(async_nats::jetstream::stream::Config {
            name: sink.name.to_string(),
            //max_bytes: 5 * 1024 * 1024 * 1024,
            //storage: StorageType::Memory,
            subjects: js_subjects,
            ..Default::default()
        }).await?;

        println!("Connected to NATS server SINK+JS {:?}", js);
        println!("- stream info: {:?}", stream_info);
        println!("");

        Ok(Sink {
            jsctx: js,
        })
    }

    pub async fn publish_unique<S: async_nats::subject::ToSubject>(
        &self,
        subject: S,
        unique_id: &str,
        payload: Bytes
    ) -> Result<async_nats::jetstream::context::PublishAckFuture, async_nats::jetstream::context::PublishError> {
        // Message headers are used in a variety of JetStream
        // contexts, such de-duplication, auto-purging of
        // messages, metadata from republished messages, and
        // more.
        // https://docs.nats.io/nats-concepts/jetstream/headers
        // If we have a proper ID, this deduplicates messages
        // when we're running multiple importers at the same
        // time.
        let mut headers = async_nats::HeaderMap::new();
        headers.insert(async_nats::header::NATS_MESSAGE_ID, unique_id.as_ref());

        self.jsctx.publish_with_headers(subject, headers, payload).await
    }
}
