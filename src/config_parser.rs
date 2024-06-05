use std::fs;

use toml::Value;


static MISSING_VALUE: &str = "";

#[derive(Clone)]
#[derive(Debug)]
pub struct DevConfig {
    pub max_messages_per_batch: usize,
}

#[derive(Clone)]
#[derive(Debug)]
pub struct NatsAuth {
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Clone)]
#[derive(Debug)]
pub struct TlsConfig {
    pub server_name: Option<String>,
    pub ca_file: Option<String>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
}

#[derive(Clone)]
#[derive(Debug)]
pub struct NatsConfig {
    pub server: String,
    pub auth: Option<NatsAuth>,
    pub tls: Option<TlsConfig>,
    pub dev: DevConfig,
}

#[derive(Clone)]
#[derive(Debug)]
pub struct InputConfig {
    pub natsconfig: NatsConfig,
    pub stream: String,
    pub consumer: String,
}

#[derive(Debug)]
pub struct SinkConfig {
    pub natsconfig: NatsConfig,
}

#[derive(Debug)]
pub struct AppConfig {
    pub input: InputConfig,
    pub sink: SinkConfig,
}


fn parse_nats_config(config: &Value, section: &str) -> NatsConfig {
    let input_section = &config[section];

    let server: String;
    let auth: Option<NatsAuth>;

    match input_section.get("nats") {
        Some(nats) => {
            server = nats.get("server").and_then(|v| v.as_str()).unwrap_or(MISSING_VALUE).to_string();
            auth = nats.get("auth").map(parse_auth_config);
        },
        None => {
            server = MISSING_VALUE.into();
            auth = None::<NatsAuth>;
        },
    };

    let tls = input_section.get("tls").map(parse_tls_config);
    let dev = parse_dev_config(input_section.get("dev"));

    NatsConfig {
        server,
        auth,
        tls,
        dev,
    }
}

fn parse_input_config(config: &Value) -> InputConfig {
    let natsconfig = parse_nats_config(config, "input");

    let stream: String;
    let consumer: String;

    let input_section = &config["input"];
    match input_section.get("nats") {
        Some(nats) => {
            stream = nats.get("stream").and_then(|v| v.as_str()).unwrap_or(MISSING_VALUE).to_string();
            consumer = nats.get("consumer").and_then(|v| v.as_str()).unwrap_or(MISSING_VALUE).to_string();
        },
        None => {
            stream = MISSING_VALUE.into();
            consumer = MISSING_VALUE.into();
        },
    };

    InputConfig {
        natsconfig,
        stream,
        consumer,
    }
}

fn parse_sink_config(config: &Value) -> SinkConfig {
    let natsconfig = parse_nats_config(config, "sink");

    SinkConfig {
        natsconfig,
    }
}

fn parse_auth_config(auth_section: &Value) -> NatsAuth {
    let username = auth_section.get("username").and_then(|v| v.as_str()).map(String::from);
    let password = auth_section.get("password").and_then(|v| v.as_str()).map(String::from);

    NatsAuth {
        username,
        password,
    }
}

fn parse_dev_config(dev_section: Option<&Value>) -> DevConfig {
    let mut max_messages_per_batch: usize = 100;

    if let Some(dev_section) = dev_section {
        let n: i64 = dev_section.get("max_messages_per_batch").and_then(|v| v.as_integer()).unwrap_or(0);
        max_messages_per_batch = if 1 <= n && n <= 100_000 { n.try_into().unwrap() } else { 100 };
    }

    DevConfig {
        max_messages_per_batch,
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

fn parse_string(config_str: String) -> Result<AppConfig, String> {
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

pub fn parse(filename: &str) -> Result<AppConfig, String> {
    // Read the configuration file
    let config_str: String = match fs::read_to_string(filename) {
        Ok(data) => data,
        Err(e) => return Err(format!("Error opening TOML: {}", e)),
    };

    parse_string(config_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    static SAMPLE_CONF: &str = r#"
        [input]
        # Input source
        nats.server = 'nats://10.20.30.40:4222'
        # Server certificate validation (tls.server_name is not working)
        tls.server_name = 'nats.local'
        tls.ca_file = './nats_ca.crt'
        # Client certificate
        tls.cert_file = './nats_client.crt'
        tls.key_file = './nats_client.key'
        # Select manually made consumer from stream
        nats.stream = 'bulk_unfiltered'
        nats.consumer = 'bulk_unfiltered_consumer'

        [sink]
        # Output target
        nats.server = 'nats://nats.example.com:4222'
        nats.auth = { username = 'derek', password = 's3cr3t!' }
        # Server certificate validation (tls.server_name is not working)
        tls.ca_file = '/etc/ssl/certs/ca-certificates.crt'
        # Client certificate
        #tls.cert_file = './nats_client.crt'
        #tls.key_file = './nats_client.key'
        # No need to set jetstream name or subjects. The subject generation is
        # hardcoded for now, based on the message.
    "#;

    #[test]
    fn test_sample() {
        let maybe_conf = parse_string(SAMPLE_CONF.into());
        match maybe_conf {
            Ok(conf) => {
                let in_srv = conf.input.natsconfig;
                let in_auth = in_srv.auth;
                let in_tls = in_srv.tls.unwrap();
                assert_eq!(in_srv.server, "nats://10.20.30.40:4222".to_owned());
                assert!(in_auth.is_none());
                assert_eq!(in_tls.server_name.unwrap(), "nats.local".to_owned());
                assert_eq!(in_tls.ca_file.unwrap(), "./nats_ca.crt".to_owned());
                assert_eq!(in_tls.cert_file.unwrap(), "./nats_client.crt".to_owned());
                assert_eq!(in_tls.key_file.unwrap(), "./nats_client.key".to_owned());
                assert_eq!(conf.input.stream, "bulk_unfiltered".to_owned());
                assert_eq!(conf.input.consumer, "bulk_unfiltered_consumer".to_owned());

                let sn_srv = conf.sink.natsconfig;
                let sn_auth = sn_srv.auth.unwrap();
                let sn_tls = sn_srv.tls.unwrap();
                assert_eq!(sn_srv.server, "nats://nats.example.com:4222".to_owned());
                assert_eq!(sn_auth.username.unwrap(), "derek".to_owned());
                assert_eq!(sn_auth.password.unwrap(), "s3cr3t!".to_owned());
                assert_eq!(sn_tls.ca_file.unwrap(), "/etc/ssl/certs/ca-certificates.crt".to_owned());
                assert!(sn_tls.cert_file.is_none());
                assert!(sn_tls.key_file.is_none());
            }
            Err(_) => {
                assert!(false);
            }
        }
    }
}
