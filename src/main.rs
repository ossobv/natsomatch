use std::env;
use std::result::Result;
use std::str::FromStr; // implements from_str on PathBuf
use std::sync::{Arc, Mutex}; // TokioMutex only needed if we await with lock held
use std::time::{Duration, Instant};

use async_nats::{self, jetstream};
use async_nats::header::NATS_MESSAGE_ID;
use bytes::Bytes;
use futures::StreamExt; // needed for subscription.next()
use tokio::time::sleep;

use nats2jetstream_json::payload_parser;
mod config_parser;


#[cfg(feature = "version-from-env")]
const GIT_VERSION: &str = env!("GIT_VERSION");
#[cfg(not(feature = "version-from-env"))]
const GIT_VERSION: &str = git_version::git_version!();

const STATS_EVERY: u64 = 60;  // show stats every N seconds


///
/// There is no conversion from Box<str> to PathBuf. Create it with to_path_buf().
///
trait ToPathBuf {
    fn to_path_buf(&self) -> std::path::PathBuf;
}
impl ToPathBuf for Box<str> {
    fn to_path_buf(&self) -> std::path::PathBuf {
        std::path::PathBuf::from_str(self).expect("failure converting to std::path::PathBuf")
    }
}

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


struct Stats {
    t0: Instant,
    count: u64,
    prepare_t: Duration,
    publish_t: Duration,
}

impl Stats {
    fn default() -> Stats {
        Stats{
            t0: Instant::now(),
            count: 0,
            prepare_t: Duration::default(),
            publish_t: Duration::default(),
        }
    }

    fn reset(&mut self) -> &Stats {
        // FIXME: dupe code with default()?
        self.t0 = Instant::now();
        self.count = 0;
        self.prepare_t = Duration::default();
        self.publish_t = Duration::default();
        self
    }

    fn inc(&mut self, prepare_t: Duration, publish_t: Duration) -> &Stats {
        self.count += 1;
        self.prepare_t += prepare_t;
        self.publish_t += publish_t;
        self
    }
}

impl std::fmt::Display for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let elapsed = self.t0.elapsed().as_secs();
        let msg_per_sec: f32 = (self.count as f32) / (elapsed as f32);
        let prep_us_per_msg: f32;
        let pub_us_per_msg: f32;
        if self.count > 0 {
            prep_us_per_msg = (self.prepare_t.as_micros() as f32) / (self.count as f32);
            pub_us_per_msg = (self.publish_t.as_micros() as f32) / (self.count as f32);
        } else {
            prep_us_per_msg = 0.0;
            pub_us_per_msg = 0.0;
        }
        write!(
            f, "{}s {}msg {:.1}msg/s {:.3}µs/msg(prep) {:.3}µs/msg(pub)",
            elapsed, self.count, msg_per_sec, prep_us_per_msg, pub_us_per_msg)
    }
}


struct Input {
    sub: async_nats::Subscriber,
}

impl Input {
    async fn from_config(input: &config_parser::NatsConfig) -> Result<Input, Box<dyn std::error::Error>> {
        println!("Connecting to NATS (input) {} ...", input.server);
        let nc_in = connect_nats("nats2jetstream-rs-nats-input", &input.server, &input.tls).await?;
        let subscription = nc_in.subscribe(input.subject.to_subject()).await?;

        println!("Connected to NATS server INPUT+SUB {:?}", nc_in);
        println!("- subscription ({}): {:?}", input.subject, subscription);
        println!("");

        Ok(Input {
            sub: subscription,
        })
    }

    async fn next(&mut self) -> Option<async_nats::Message> {
        self.sub.next().await
    }
}


struct Sink {
    jsctx: async_nats::jetstream::context::Context,
}

impl Sink {
    async fn from_config(sink: &config_parser::JetStreamConfig) -> Result<Sink, Box<dyn std::error::Error>> {
        println!("Connecting to NATS (sink) {} ...", sink.server);
        let nc_out = connect_nats("nats2jetstream-rs-jetstream-sink", &sink.server, &sink.tls).await?;
        let js = jetstream::new(nc_out);

        // XXX: move to configparser
        let js_subjects: Vec<String> = sink.subject_any.split(',').map(|s| s.to_string()).collect();

        println!("Setting up JetStream stream {} {:?} ...", sink.name, js_subjects);
        let stream_info = js.get_or_create_stream(jetstream::stream::Config {
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

    async fn publish_unique<S: async_nats::subject::ToSubject>(
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
        headers.insert(NATS_MESSAGE_ID, unique_id.as_ref());

        self.jsctx.publish_with_headers(subject, headers, payload).await
    }
}


async fn connect_nats(_name: &str, server: &str, maybe_tls: &Option<config_parser::TlsConfig>) -> Result<async_nats::Client, async_nats::ConnectError> {
    let mut options = async_nats::ConnectOptions::new();

    if let Some(tls) = maybe_tls {
        options = options.require_tls(true);
        if let Some(_) = &tls.server_name {
            eprintln!("warning: tls.server_name is not implemented");
        }
        if let Some(ca_file) = &tls.ca_file {
            options = options.add_root_certificates(ca_file.to_path_buf());
        }
        match (&tls.cert_file, &tls.key_file) {
            (Some(cert), Some(key)) => {
                options = options.add_client_certificate(cert.to_path_buf(), key.to_path_buf());
            },
            _ => {},
        }
    }

    return options.connect(server).await;
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Collect command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 || args[1] != "-c" {
        eprintln!("nats2jetstream {}", GIT_VERSION);
        eprintln!("Usage: {} -c <config-file>", args[0]);
        std::process::exit(1);
    }

    let filename = &args[2];

    // Parse the configuration file
    let app_config: config_parser::AppConfig = match config_parser::parse(filename) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error parsing configuration: {}", e);
            std::process::exit(1);
        },
    };

    //println!("Appconfig {app_config:?}");

    let sink = Sink::from_config(&app_config.sink).await?;
    let mut input = Input::from_config(&app_config.input).await?;

    // Stats where we record how we're doing
    let period_stats_1 = Arc::new(Mutex::new(Stats::default()));
    let period_stats_2 = period_stats_1.clone();
    let forever_stats_1 = Arc::new(Mutex::new(Stats::default()));
    let forever_stats_2 = forever_stats_1.clone();

    // Start a background task for periodic updates
    let stats_task = tokio::spawn(async move {
        let sleep_time = Duration::from_secs(STATS_EVERY);
        loop {
            // Async sleep for N seconds
            sleep(sleep_time).await;

            // Get access to the stats and go
            let mut period_stats = period_stats_1.lock().unwrap();
            let forever_stats = forever_stats_1.lock().unwrap();
            eprintln!("info: {} [total], {} [last]", forever_stats, period_stats);
            drop(forever_stats);
            period_stats.reset();
            drop(period_stats);
        }
    });

    // Start the main task
    loop {
        let subject_tpl = app_config.sink.subject_tpl.to_string();
        match input.next().await {
            Some(msg) => {
                // Prepare
                let prep_t0 = Instant::now();
                let attrs: payload_parser::BytesAttributes;
                match payload_parser::BytesAttributes::from_payload(&msg.payload) {
                    Ok(ok) => { attrs = ok; },
                    Err(err) => { eprintln!("payload error: {}; {:?}", err, msg.payload); continue; },
                }
                let unique_id = attrs.get_unique_id();
                let subject = subject_tpl.replace("{section}", attrs.get_section());
                let prep_td = prep_t0.elapsed();

                // Publish
                let pub_t0 = Instant::now();
                match sink.publish_unique(subject, &unique_id, msg.payload).await {
                    Ok(_maybe_ack) => {},
                    Err(err) => { eprintln!("publish error: {}; {}", err, unique_id); continue; },
                }
                let pub_td = pub_t0.elapsed();

                // Stats
                let mut period_stats = period_stats_2.lock().unwrap();
                period_stats.inc(prep_td, pub_td);
                drop(period_stats);

                let mut forever_stats = forever_stats_2.lock().unwrap();
                forever_stats.inc(prep_td, pub_td);
                drop(forever_stats);
            }
            None => {
                eprintln!("err??");
                break
            }
        }
    }

    // XXX: does this work? is this needed?
    stats_task.abort();

    Ok(())
}
