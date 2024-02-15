use std::env;
use std::result::Result;
use std::sync::{Arc, Mutex}; // TokioMutex only needed if we await with lock held
use std::time::{Duration, Instant};

use async_nats::{self, jetstream};
use futures::StreamExt; // needed for subscription.next()
use tokio::time::sleep;

mod config_parser;
use self::config_parser::{AppConfig, TlsConfig, parse};


const GIT_VERSION: &str = git_version::git_version!();
const STATS_EVERY: u64 = 60;  // show stats every N seconds


struct Stats {
    t0: Instant,
    pub_count: u64,
    pub_duration: Duration,
}

impl Stats {
    fn default() -> Stats {
        Stats{t0: Instant::now(), pub_count: 0, pub_duration: Duration::default()}
    }

    fn reset(&mut self) -> &Stats {
        // FIXME: dupe code with default()?
        self.t0 = Instant::now();
        self.pub_count = 0;
        self.pub_duration = Duration::default();
        self
    }

    fn inc_pub(&mut self, pub_duration: Duration) -> &Stats {
        self.pub_count += 1;
        self.pub_duration += pub_duration;
        self
    }
}

impl std::fmt::Display for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let elapsed = self.t0.elapsed().as_secs();
        let msg_per_sec: f32 = (self.pub_count as f32) / (elapsed as f32);
        let us_per_msg: f32;
        if self.pub_count > 0 {
            us_per_msg = (self.pub_duration.as_micros() as f32) / (self.pub_count as f32);
        } else {
            us_per_msg = 0.0;
        }
        write!(
            f, "{}s {}msg {:.3}msg/s {:.3}µs/msg(pub)",
            elapsed, self.pub_count, msg_per_sec, us_per_msg)
    }
}


async fn connect_nats(_name: &str, server: &str, maybe_tls: &Option<TlsConfig>) -> Result<async_nats::Client, async_nats::ConnectError> {
    let mut options = async_nats::ConnectOptions::new();

    if let Some(tls) = maybe_tls {
        options = options.require_tls(true);
        if let Some(_) = &tls.server_name {
            eprintln!("warning: tls.server_name is not implemented");
        }
        if let Some(ca_file) = &tls.ca_file {
            options = options.add_root_certificates(ca_file.into());
        }
        match (&tls.cert_file, &tls.key_file) {
            (Some(cert), Some(key)) => {
                options = options.add_client_certificate(cert.into(), key.into());
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
    let app_config: AppConfig = match parse(filename) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error parsing configuration: {}", e);
            std::process::exit(1);
        },
    };

    //println!("Appconfig {app_config:?}");

    let nc_out = connect_nats(
        "nats2jetstream-rs-jetstream-sink",
        &app_config.sink.server,
        &app_config.sink.tls).await?;
    let js = jetstream::new(nc_out);

    // XXX: move to configparser
    let js_subjects: Vec<String> = app_config.sink.subjects
        .split(',').map(|s| s.to_string()).collect();

    let stream_info = js.get_or_create_stream(jetstream::stream::Config {
        name: app_config.sink.name,
        //max_bytes: 5 * 1024 * 1024 * 1024,
        //storage: StorageType::Memory,
        subjects: js_subjects,
        ..Default::default()
    }).await?;

    println!("Connected to NATS server SINK+JS {:?}", js);
    println!("- stream info: {:?}", stream_info);
    println!("");

    let nc_in = connect_nats(
        "nats2jetstream-rs-nats-input",
        &app_config.input.server,
        &app_config.input.tls).await?;
    let mut subscription = nc_in.subscribe(app_config.input.subject.clone()).await?;

    println!("Connected to NATS server INPUT+SUB {:?}", nc_in);
    println!("- subscription ({}): {:?}", app_config.input.subject, subscription);
    println!("");

    // Read message from NATS-subscription, publish to NATS-JetStream
    let _max_timeout = Duration::from_secs(1);

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
        match subscription.next().await {
            Some(msg) => {
                let pub_t0 = Instant::now();
                let _maybe_ack = js.publish(app_config.sink.subjects.clone(), msg.payload).await?;
                let pub_td = pub_t0.elapsed();

                let mut period_stats = period_stats_2.lock().unwrap();
                period_stats.inc_pub(pub_td);
                drop(period_stats);

                let mut forever_stats = forever_stats_2.lock().unwrap();
                forever_stats.inc_pub(pub_td);
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
