use std::env;
use std::error::Error;
use std::result::Result;
use std::sync::{Arc, Mutex}; // TokioMutex only needed if we await with lock held
use std::time::{Duration, Instant};

use tokio::time::sleep;

use nats2jetstream_json::payload_parser;

// Either here or in lib.. depending on whether this is a lib or an app.
mod config_parser;
mod inputs;
mod misc_nats;
mod sinks;
mod stats;


#[cfg(feature = "version-from-env")]
const GIT_VERSION: &str = env!("GIT_VERSION");
#[cfg(not(feature = "version-from-env"))]
const GIT_VERSION: &str = git_version::git_version!();

const STATS_EVERY: u64 = 60;  // show stats every N seconds


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
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

    let sink = sinks::Sink::from_config(&app_config.sink).await?;
    let mut input = inputs::Input::from_config(&app_config.input).await?;

    // Stats where we record how we're doing
    let period_stats_1 = Arc::new(Mutex::new(stats::Stats::default()));
    let period_stats_2 = period_stats_1.clone();
    let forever_stats_1 = Arc::new(Mutex::new(stats::Stats::default()));
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
