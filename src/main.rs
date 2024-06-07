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
use nats2jetstream_match::log_matcher;

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


/// Waits for a signal that requests a graceful shutdown, like SIGTERM
/// or SIGINT.
#[cfg(unix)]
async fn wait_for_signal_impl() {
    use tokio::signal::unix::{signal, SignalKind};

    // Infos here:
    // https://www.gnu.org/software/libc/manual/html_node/Termination-Signals.html
    let mut signal_terminate = signal(SignalKind::terminate()).unwrap();
    let mut signal_interrupt = signal(SignalKind::interrupt()).unwrap();

    tokio::select! {
        _ = signal_terminate.recv() => {
            eprintln!("Received SIGTERM.");
            std::process::exit(0);
        },
        _ = signal_interrupt.recv() => {
            eprintln!("Received SIGINT.");
            std::process::exit(0);
        }
    };
}


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

    // Start a background task for fast stoppage
    tokio::spawn(async move { wait_for_signal_impl().await; });

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
        while let Some(Ok(msg)) = input.next().await {
            // Prepare/parse
            let prep_t0 = Instant::now();
            let (msg, src_acker) = msg.split(); // split, so we can steal msg.payload
            let attrs = match payload_parser::BytesAttributes::from_payload(&msg.payload) {
                Ok(ok) => { ok },
                Err(err) => { eprintln!("error decoding payload: {}; {:?}", err, msg.payload); continue; },
            };
            let match_ = match log_matcher::Match::from_attributes(&attrs) {
                Ok(ok) => { ok },
                Err(err) => { eprintln!("error matching payload: {}; {:?}; {:?}", err, attrs, msg.payload); continue; },
            };
            let prep_td = prep_t0.elapsed();

            // Publish
            // FIXME: publishing should be done in a separate handler so we can continue
            // parsing the others asynchronously? Useful if we'd publish to multiple locations.
            let pub_t0 = Instant::now();
            let dst_acker = match sink.publish(match_.subject.clone(), msg.payload).await {
                Ok(maybe_ack) => { maybe_ack },
                Err(err) => { eprintln!("error on publish(1) of subject {}: {}", match_.subject, err); continue; },
            };
            match dst_acker.await { // try acking the dest
                Ok(_) => { src_acker.ack().await.unwrap(); /* ack the source; FIXME error handling */ },
                // FIXME: When publish(2) fails, it might be because there is no stream and we
                // cannot get an ack. Should we auto-create the stream?
                Err(err) => { eprintln!("error on publish(2) of subject {}: {}", match_.subject, err); break; },
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

        // FIXME: We get here at least on publish(2)-fail. Not sure
        // when/if/how input.next().await can fail.
        eprintln!("FIXME: When do we get out of the iterator loop?");

        let forever_stats = forever_stats_io.lock().expect("Lock forever_stats_io fail");
        let count = forever_stats.get_count();
        drop(forever_stats);
        if count > 0 {  // really just to silence clippy..
            break;
        }

    }
    eprintln!("nats2jetstream shutting down...");

    // XXX: does these work? is this needed?
    healthz_task.abort();
    stats_task.abort();

    Ok(())
}
