use std::error::Error;

use bytes::Bytes;

use crate::config_parser;
use crate::misc_nats;


#[derive(Debug)]
pub struct Sink {
    jsctx: async_nats::jetstream::context::Context,
}

impl Sink {
    pub async fn from_config(sink: &config_parser::SinkConfig) -> Result<Sink, Box<dyn Error>> {
        let srv = &sink.natsconfig;

        println!("Connecting to NATS (sink) {} ...", srv.server);
        let nc_out = misc_nats::connect("nats2jetstream-rs-jetstream-sink", &srv.server, &srv.tls, &srv.auth).await?;
        let js = async_nats::jetstream::new(nc_out);
        println!("Connected to NATS (sink) with JetStream context {:?}", js);

        // NOTE: Right now, we don't care about setting up streams. Let the admin handle that using
        // nats cli commands. Just the jetstream connection should be sufficient for us to start
        // publishing. (The admin should create streams for the subjects as appropriate.)

        Ok(Sink {
            jsctx: js,
        })
    }

    pub async fn publish<S: async_nats::subject::ToSubject>(
        &self,
        subject: S,
        payload: Bytes
    ) -> Result<async_nats::jetstream::context::PublishAckFuture, async_nats::jetstream::context::PublishError> {
        self.jsctx.publish(subject, payload).await
    }

    /*
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
    */
}
