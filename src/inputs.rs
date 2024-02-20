use futures::StreamExt; // needed for sub.next()

use crate::config_parser;
use crate::misc_nats;


///
/// There is no conversion from Box<str> to Subject. Create it with to_subject().
///
trait ToSubject {
    fn to_subject(&self) -> async_nats::subject::Subject;
}
impl ToSubject for Box<str> {
    fn to_subject(&self) -> async_nats::subject::Subject {
        let s: String = (*self).clone().into();
        async_nats::subject::Subject::from(s)
    }
}


pub struct Input {
    sub: async_nats::Subscriber,
}

impl Input {
    pub async fn from_config(input: &config_parser::NatsConfig) -> Result<Input, Box<dyn std::error::Error>> {
        println!("Connecting to NATS (input) {} ...", input.server);
        let nc_in = misc_nats::connect("nats2jetstream-rs-nats-input", &input.server, &input.tls).await?;
        let subscription = nc_in.subscribe(input.subject.to_subject()).await?;

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
