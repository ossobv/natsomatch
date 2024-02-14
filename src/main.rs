use std::env;
use std::io::ErrorKind::TimedOut;
use std::result::Result;
use std::time::{Duration, Instant};

use nats::{self, jetstream};

mod config_parser;
use self::config_parser::{AppConfig, TlsConfig, parse};

fn connect_nats(name: &str, server: &str, maybe_tls: &Option<TlsConfig>) -> Result<nats::Connection, std::io::Error> {
    let mut options = nats::Options::new();

    options = options.with_name(name);

    if let Some(tls) = maybe_tls {
        options = options.tls_required(true);
        if let Some(_) = &tls.server_name {
            eprintln!("warning: tls.server_name is not implemented");
        }
        if let Some(ca_file) = &tls.ca_file {
            options = options.add_root_certificate(ca_file);
        }
        match (&tls.cert_file, &tls.key_file) {
            (Some(cert), Some(key)) => {
                options = options.client_cert(cert, key);
            },
            _ => {},
        }
    }

    return options.connect(server);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Collect command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 || args[1] != "-c" {
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
        &app_config.sink.tls)?;
    let js = jetstream::new(nc_out);

    // XXX: move to configparser
    let js_subjects: Vec<String> = app_config.sink.subjects
        .split(',').map(|s| s.to_string()).collect();

    let stream_info = js.add_stream(jetstream::StreamConfig {
        name: app_config.sink.name,
        //max_bytes: 5 * 1024 * 1024 * 1024,
        //storage: StorageType::Memory,
        subjects: js_subjects,
        ..Default::default()
    })?;

    println!("Connected to NATS server SINK+JS {:?}", js);
    println!("- stream info: {:?}", stream_info);
    println!("");

    let nc_in = connect_nats(
        "nats2jetstream-rs-nats-input",
        &app_config.input.server,
        &app_config.input.tls)?;
    let subscription = nc_in.subscribe(&app_config.input.subject)?;

    println!("Connected to NATS server INPUT+SUB {:?}", nc_in);
    println!("- subscription ({}): {:?}", app_config.input.subject, subscription);
    println!("");

    let mut stat_items = 0;
    let mut stat_publish_time = Duration::default();
    let mut stat_t0 = Instant::now();

    // Read message from NATS-subscription, publish to NATS-JetStream
    let max_timeout = Duration::from_secs(1);

    loop {
        let maybe_msg = subscription.next_timeout(max_timeout);

        if let Ok(msg) = maybe_msg {
            // Handle publish
            let publish_t0 = Instant::now();
            let maybe_ack = js.publish(&app_config.sink.subjects, msg.data);
            let publish_td = publish_t0.elapsed();

            match maybe_ack {
                Ok(ack) => {
                    // XXX: what is ack.domain?
                    if ack.duplicate {
                        eprintln!("dupe in jetstream write: {}", ack.sequence);
                    } else {
                        //eprintln!("published {}", ack.sequence);
                    }
                },
                Err(error) => {
                    eprintln!("error in jetstream write: {}", error);
                },
            }

            // Handle stats
            stat_items += 1;
            stat_publish_time += publish_td;
        } else if let Err(err) = maybe_msg {
            if err.kind() != TimedOut {
                eprintln!("err?? {:?}", err);
                break
            }
        }

        // Show stats
        let elapsed = stat_t0.elapsed().as_secs();
        if elapsed >= 10 {
            let msg_per_sec: f32 = (stat_items as f32) / (elapsed as f32);
            let pubt_per_msg: f32;
            if stat_items > 0 {
                pubt_per_msg = (stat_publish_time.as_millis() as f32) / (stat_items as f32);
            } else {
                pubt_per_msg = 0.0;
            }

            eprintln!(
                "info: {} items, {} secs, {:.3} msg/sec, {:.3} msec/msg (pub)",
                stat_items, elapsed, msg_per_sec, pubt_per_msg);

            // Reset counters
            stat_items = 0;
            stat_publish_time = Duration::default();
            stat_t0 = Instant::now();
        }
    }

    Ok(())
}
