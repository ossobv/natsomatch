use std::fs;

use toml::Value;


#[derive(Debug)]
struct NatsConfig {
    server: Option<String>,
    subject: Option<String>,
    pub tls: Option<TlsConfig>,
}

#[derive(Debug)]
struct JetStreamConfig {
    server: Option<String>,
    name: Option<String>,
    subjects: Option<String>,
    pub tls: Option<TlsConfig>,
}

#[derive(Debug)]
struct TlsConfig {
    server_name: Option<String>,
    ca_file: Option<String>,
    cert_file: Option<String>,
    key_file: Option<String>,
}

#[derive(Debug)]
pub struct AppConfig {
    pub nats: NatsConfig,
    pub jetstream: JetStreamConfig,
}


fn parse_input_config(config: &Value) -> NatsConfig {
    let input_section = &config["input"]["my_nats"];

    let server: Option<String>;
    let subject: Option<String>;

    match input_section.get("nats") {
        Some(nats) => {
            server = nats.get("server").and_then(|value| value.as_str()).map(String::from);
            subject = nats.get("subject").and_then(|value| value.as_str()).map(String::from);
        },
        None => {
            server = None;
            subject = None;
        },
    };

    let tls = input_section.get("tls").map(|tls_section| parse_tls_config(tls_section));

    NatsConfig {
        server,
        subject,
        tls,
    }
}

fn parse_sink_config(config: &Value) -> JetStreamConfig {
    let sink_section = &config["sink"]["my_jetstream"];

    let server: Option<String>;
    let name: Option<String>;
    let subjects: Option<String>;

    match sink_section.get("jetstream") {
        Some(jetstream) => {
            server = jetstream.get("server").and_then(|value| value.as_str()).map(String::from);
            name = jetstream.get("name").and_then(|value| value.as_str()).map(String::from);
            // XXX: should this be an array?
            subjects = jetstream.get("subjects").and_then(|value| value.as_str()).map(String::from);
        },
        None => {
            server = None;
            name = None;
            subjects = None;
        },
    };

    let tls = sink_section.get("tls").map(|tls_section| parse_tls_config(tls_section));

    JetStreamConfig {
        server,
        name,
        subjects,
        tls,
    }
}

fn parse_tls_config(tls_section: &Value) -> TlsConfig {
    let server_name = tls_section["server_name"].as_str().map(String::from);
    let ca_file = tls_section["ca_file"].as_str().map(String::from);
    let cert_file = tls_section["cert_file"].as_str().map(String::from);
    let key_file = tls_section["key_file"].as_str().map(String::from);

    TlsConfig {
        server_name,
        ca_file,
        cert_file,
        key_file,
    }
}

pub fn parse(filename: &str) -> Result<AppConfig, String> {
    // Read the configuration file
    let config_str: String = match fs::read_to_string(filename) {
        Ok(data) => data,
        Err(e) => return Err(format!("Error opening TOML: {}", e)),
    };

    // Parse the configuration (TOML trait)
    let config: Value = match config_str.parse() {
        Ok(parsed) => parsed,
        Err(e) => return Err(format!("Error parsing TOML: {}", e)),
    };

    // Parse and extract configuration values
    let nats_config = parse_input_config(&config);
    let jetstream_config = parse_sink_config(&config);

    // Create and return the AppConfig struct
    let app_config = AppConfig {
        nats: nats_config,
        jetstream: jetstream_config,
    };

    Ok(app_config)
}
