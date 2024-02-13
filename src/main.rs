use std::env;
use std::result::Result;

use nats;

mod config_parser;
use self::config_parser::{AppConfig, parse};

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

    let nc_out = nats::Options::new()
        .with_name("nats2jetstream-rs-sink")
        .tls_required(true)
        .add_root_certificate("./nats_ca.crt")
        .client_cert("./nats_client.crt", "./nats_client.key")
        .connect("nats://nats.example.com:4222")?;
        //.connect("nats://10.91.131.89:4222")?;

    let js = nats::jetstream::new(nc_out);
    js.add_stream("teststream")?; //, ["test1"])?; // <-- brokenness...

    println!("Connected to NATS server SINK+JS {:?}", js);

    //let nats_tls = app_config.nats.tls?
    let nc_in = nats::Options::new()
        .with_name("nats2jetstream-rs-input")
        .tls_required(true)
        .add_root_certificate(app_config.nats.tls.ca_file)
        .client_cert(app_config.nats.tls.cert_file, app_config.nats.tls.cert_key)
        .connect("nats://nats.example.com:4222")?;
        //.connect("nats://10.91.131.89:4222")?;

    println!("Connected to NATS server INPUT {:?}", nc_in);

    // Subscribe to a subject
    let subject = "default.nats.vector";
    let subscription = nc_in.subscribe(subject)?;

    println!("Subscribed to subject '{}'", subject);

    // Process incoming messages
    while let Some(msg) = subscription.next() {
        let payload = String::from_utf8_lossy(&msg.data);
        println!("Received message: {}", payload);
    }

    Ok(())
}
