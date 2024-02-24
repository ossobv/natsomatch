use std::fs;

use toml::Value;


static MISSING_VALUE: &str = "";

#[derive(Debug)]
pub struct NatsConfig {
    pub server: Box<str>,
    pub subject: Box<str>,
    pub tls: Option<TlsConfig>,
}

#[derive(Debug)]
pub struct JetStreamConfig {
    pub server: Box<str>,
    pub name: Box<str>,
    pub subject_any: Box<str>,
    pub subject_tpl: Box<str>,
    pub tls: Option<TlsConfig>,
}

#[derive(Debug)]
pub struct TlsConfig {
    pub server_name: Option<Box<str>>,
    pub ca_file: Option<Box<str>>,
    pub cert_file: Option<Box<str>>,
    pub key_file: Option<Box<str>>,
}

#[derive(Debug)]
pub struct AppConfig {
    pub input: NatsConfig,      // should be more inputs
    pub sink: JetStreamConfig,  // should be more sinks
}


fn as_box_str(input: &str) -> Box<str> {
    //String::from(input).into()        // Which of
    //input.to_string().into()          // these three
    input.to_owned().into_boxed_str()   // is better?
}

fn parse_input_config(config: &Value) -> NatsConfig {
    let input_section = &config["input"]["my_nats"];

    let server: Box<str>;
    let subject: Box<str>;

    match input_section.get("nats") {
        Some(nats) => {
            server = nats.get("server").and_then(|v| v.as_str()).unwrap_or(MISSING_VALUE).into();
            subject = nats.get("subject").and_then(|v| v.as_str()).unwrap_or(MISSING_VALUE).into();
        },
        None => {
            server = MISSING_VALUE.into();
            subject = MISSING_VALUE.into();
        },
    };

    let tls = input_section.get("tls").map(|tls_section| parse_tls_config(tls_section));

    NatsConfig {
        server: server,
        subject: subject,
        tls: tls,
    }
}

fn parse_sink_config(config: &Value) -> JetStreamConfig {
    let sink_section = &config["sink"]["my_jetstream"];

    let server: Box<str>;
    let name: Box<str>;
    let subject_tpl: Box<str>;

    match sink_section.get("jetstream") {
        Some(jetstream) => {
            server = jetstream.get("server").and_then(|v| v.as_str()).unwrap_or(MISSING_VALUE).into();
            name = jetstream.get("name").and_then(|v| v.as_str()).unwrap_or(MISSING_VALUE).into();
            subject_tpl = jetstream.get("subject_tpl").and_then(|v| v.as_str()).unwrap_or(MISSING_VALUE).into();
        },
        None => {
            server = MISSING_VALUE.into();
            name = MISSING_VALUE.into();
            subject_tpl = MISSING_VALUE.into();
        },
    };

    let tls = sink_section.get("tls").map(|tls_section| parse_tls_config(tls_section));

    // Copy the "abc.{def}" template and turn into "abc.*"
    let mut subject_any_str: String = subject_tpl.clone().into();
    if let Some(index) = subject_any_str.find('{') {
        subject_any_str.replace_range(index.., "*");
    }
    let subject_any: Box<str> = subject_any_str.into_boxed_str();

    JetStreamConfig {
        server: server,
        name: name,
        subject_any: subject_any,
        subject_tpl: subject_tpl,
        tls: tls,
    }
}

fn parse_tls_config(tls_section: &Value) -> TlsConfig {
    let server_name = tls_section.get("server_name").and_then(|v| v.as_str()).map(as_box_str);
    let ca_file = tls_section.get("ca_file").and_then(|v| v.as_str()).map(as_box_str);
    let cert_file = tls_section.get("cert_file").and_then(|v| v.as_str()).map(as_box_str);
    let key_file = tls_section.get("key_file").and_then(|v| v.as_str()).map(as_box_str);

    TlsConfig {
        server_name: server_name,
        ca_file: ca_file,
        cert_file: cert_file,
        key_file: key_file,
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
