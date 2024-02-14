use std::env;
use std::result::Result;

use nats;

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

    println!("Appconfig {app_config:?}");

    let nc_out = connect_nats(
        "nats2jetstream-rs-jetstream-sink",
        &app_config.sink.server,
        &app_config.sink.tls)?;

    let js = nats::jetstream::new(nc_out);
    let res = js.add_stream("teststream")?; //, ["test1"])?; // <-- brokenness...

    println!("Connected to NATS server SINK+JS {:?} res {:?}", &js, &res);

    let nc_in = connect_nats(
        "nats2jetstream-rs-nats-input",
        &app_config.input.server,
        &app_config.input.tls)?;
    let subscription = nc_in.subscribe(&app_config.input.subject)?;

    println!("Connected to NATS server INPUT+SUB {:?} subject {}", &subscription, &app_config.input.subject);

    // Process incoming messages
    while let Some(msg) = subscription.next() {
        let payload = String::from_utf8_lossy(&msg.data);
        println!("Received message: {}", payload);
        break
    }

    Ok(())
}
