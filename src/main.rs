use std::env;
use std::error::Error;
use std::net::SocketAddr;
use std::result::Result;
use std::sync::{Arc, Mutex}; // TokioMutex only needed if we await with lock held
use std::time::{Duration, Instant};

use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::time::sleep;

use nats2jetstream_json::payload_parser;

// Either here or in lib.. depending on whether this is a lib or an app.
mod config_parser;
mod healthz;
mod inputs;
mod misc_nats;
mod sinks;
mod stats;


#[cfg(feature = "version-from-env")]
const GIT_VERSION: &str = env!("GIT_VERSION");
#[cfg(not(feature = "version-from-env"))]
const GIT_VERSION: &str = git_version::git_version!();

const STATS_EVERY: u64 = 60;  // show stats every N seconds

const HEALTHZ_BINDADDR: &str = "0.0.0.0:3000";



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

    // Stats where we record how we're doing (lock order: forever<period)
    let forever_stats_stats = Arc::new(Mutex::new(stats::Stats::new()));
    let forever_stats_healthz = forever_stats_stats.clone();
    let forever_stats_io = forever_stats_stats.clone();
    let period_stats_stats = Arc::new(Mutex::new(stats::Stats::new()));
    let period_stats_healthz = period_stats_stats.clone();
    let period_stats_io = period_stats_stats.clone();

    // Start a background task for periodic updates
    let stats_task = tokio::spawn(async move {
        let sleep_time = Duration::from_secs(STATS_EVERY);
        loop {
            // Async sleep for N seconds
            sleep(sleep_time).await;

            // Get access to the stats and go
            let forever_stats = forever_stats_stats.lock().expect("Lock forever_stats_stats fail");
            let mut period_stats = period_stats_stats.lock().expect("Lock period_stats_stats fail");
            eprintln!("info: {} [total], {} [last]", forever_stats, period_stats);
            drop(forever_stats);
            period_stats.reset();
            drop(period_stats);
        }
    });

    // Start a background tasks for healthz handling
    let healthz_bindaddr = HEALTHZ_BINDADDR.parse::<SocketAddr>().expect("Invalid healthz address");
    let healthz_listener = TcpListener::bind(healthz_bindaddr).await?;
    let healthz_task = tokio::spawn(async move {
        let svc = healthz::HealthzService::create(period_stats_healthz, forever_stats_healthz);
        loop {
            let (stream, _) = healthz_listener.accept().await.expect("Accept healthz error");
            let io = TokioIo::new(stream);
            let svc_clone = svc.clone();
            tokio::task::spawn(async move {
                if let Err(err) = http1::Builder::new().serve_connection(io, svc_clone).await {
                    println!("Failed to serve connection: {:?}", err);
                }
            });
        }
    });

    // Start the main task
    loop {
        let subject_tpl = app_config.sink.subject_tpl.to_string();
        match input.next().await {
            Some(msg) => {
                // Prepare
                let prep_t0 = Instant::now();
                let attrs = match payload_parser::BytesAttributes::from_payload(&msg.payload) {
                    Ok(ok) => { ok },
                    Err(err) => { eprintln!("payload error: {}; {:?}", err, msg.payload); continue; },
                };
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
                let mut forever_stats = forever_stats_io.lock().expect("Lock forever_stats_io fail");
                forever_stats.inc(prep_td, pub_td);
                drop(forever_stats);

                let mut period_stats = period_stats_io.lock().expect("Lock period_stats_io fail");
                period_stats.inc(prep_td, pub_td);
                drop(period_stats);
            }
            None => {
                eprintln!("err??");
                break
            }
        }
    }

    // XXX: does these work? is this needed?
    healthz_task.abort();
    stats_task.abort();

    Ok(())
}
