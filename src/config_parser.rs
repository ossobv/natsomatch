use std::fs;

use toml::Value;


pub static MISSING_VALUE: &str = "";

#[derive(Debug)]
pub struct NatsConfig {
    pub server: String,
    pub subject: String,
    pub tls: Option<TlsConfig>,
}

#[derive(Debug)]
pub struct JetStreamConfig {
    pub server: String,
    pub name: String,
    pub subjects: String,
    pub tls: Option<TlsConfig>,
}

#[derive(Debug)]
pub struct TlsConfig {
    pub server_name: Option<String>,
    pub ca_file: Option<String>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
}

#[derive(Debug)]
pub struct AppConfig {
    pub input: NatsConfig,      // should be more inputs
    pub sink: JetStreamConfig,  // should be more sinks
}


fn parse_input_config(config: &Value) -> NatsConfig {
    let input_section = &config["input"]["my_nats"];

    let server: String;
    let subject: String;

    match input_section.get("nats") {
        Some(nats) => {
            server = nats.get("server").and_then(|v| v.as_str()).unwrap_or(MISSING_VALUE).to_string();
            subject = nats.get("subject").and_then(|v| v.as_str()).unwrap_or(MISSING_VALUE).to_string();
        },
        None => {
            server = MISSING_VALUE.to_string();
            subject = MISSING_VALUE.to_string();
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

    let server: String;
    let name: String;
    let subjects: String;

    match sink_section.get("jetstream") {
        Some(jetstream) => {
            server = jetstream.get("server").and_then(|v| v.as_str()).unwrap_or(MISSING_VALUE).to_string();
            name = jetstream.get("name").and_then(|v| v.as_str()).unwrap_or(MISSING_VALUE).to_string();
            // XXX: should this be an array?
            subjects = jetstream.get("subjects").and_then(|v| v.as_str()).unwrap_or(MISSING_VALUE).to_string();
        },
        None => {
            server = MISSING_VALUE.to_string();
            name = MISSING_VALUE.to_string();
            subjects = MISSING_VALUE.to_string();
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
    let server_name = tls_section.get("server_name").and_then(|v| v.as_str()).map(String::from);
    let ca_file = tls_section.get("ca_file").and_then(|v| v.as_str()).map(String::from);
    let cert_file = tls_section.get("cert_file").and_then(|v| v.as_str()).map(String::from);
    let key_file = tls_section.get("key_file").and_then(|v| v.as_str()).map(String::from);

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
        input: nats_config,
        sink: jetstream_config,
    };

    Ok(app_config)
}
