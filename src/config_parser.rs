use std::fs;

use toml::Value;


static MISSING_VALUE: &str = "";

#[derive(Debug)]
pub struct NatsAuth {
    pub username: Option<Box<str>>,
    pub password: Option<Box<str>>,
}

#[derive(Debug)]
pub struct NatsConfig {
    pub server: Box<str>,
    pub auth: Option<NatsAuth>,
    pub subject: Box<str>,
    pub tls: Option<TlsConfig>,
}

#[derive(Debug)]
pub struct JetStreamConfig {
    pub server: Box<str>,
    pub auth: Option<NatsAuth>,
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
    let auth: Option<NatsAuth>;
    let subject: Box<str>;

    match input_section.get("nats") {
        Some(nats) => {
            server = nats.get("server").and_then(|v| v.as_str()).unwrap_or(MISSING_VALUE).into();
            auth = nats.get("auth").map(|auth_section| parse_auth_config(auth_section));
            subject = nats.get("subject").and_then(|v| v.as_str()).unwrap_or(MISSING_VALUE).into();
        },
        None => {
            server = MISSING_VALUE.into();
            auth = None::<NatsAuth>;
            subject = MISSING_VALUE.into();
        },
    };

    let tls = input_section.get("tls").map(|tls_section| parse_tls_config(tls_section));

    NatsConfig {
        server: server,
        auth: auth,
        subject: subject,
        tls: tls,
    }
}

fn parse_sink_config(config: &Value) -> JetStreamConfig {
    let sink_section = &config["sink"]["my_jetstream"];

    let server: Box<str>;
    let auth: Option<NatsAuth>;
    let name: Box<str>;
    let subject_tpl: Box<str>;

    match sink_section.get("jetstream") {
        Some(jetstream) => {
            server = jetstream.get("server").and_then(|v| v.as_str()).unwrap_or(MISSING_VALUE).into();
            auth = jetstream.get("auth").map(|auth_section| parse_auth_config(auth_section));
            name = jetstream.get("name").and_then(|v| v.as_str()).unwrap_or(MISSING_VALUE).into();
            subject_tpl = jetstream.get("subject_tpl").and_then(|v| v.as_str()).unwrap_or(MISSING_VALUE).into();
        },
        None => {
            server = MISSING_VALUE.into();
            auth = None::<NatsAuth>;
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
        auth: auth,
        name: name,
        subject_any: subject_any,
        subject_tpl: subject_tpl,
        tls: tls,
    }
}

fn parse_auth_config(auth_section: &Value) -> NatsAuth {
    let username = auth_section.get("username").and_then(|v| v.as_str()).map(as_box_str);
    let password = auth_section.get("password").and_then(|v| v.as_str()).map(as_box_str);

    NatsAuth {
        username: username,
        password: password,
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

pub fn parse_string(config_str: String) -> Result<AppConfig, String> {
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
        [input.my_nats]
        # Input source
        nats.server = 'nats://10.20.30.40:4222'
        nats.subject = 'NS.log.vector-in'
        # Server certificate validation (tls.server_name is not working)
        tls.server_name = 'nats.local'
        tls.ca_file = './nats_ca.crt'
        # Client certificate
        tls.cert_file = './nats_client.crt'
        tls.key_file = './nats_client.key'

        [sink.my_jetstream]
        # Output target
        jetstream.server = 'nats://nats.example.com:4222'
        jetstream.auth = { username = 'derek', password = 's3cr3t!' }
        jetstream.name = 'bulk'
        jetstream.subject_tpl = 'bulk.section.{section}'
        # Server certificate validation (tls.server_name is not working)
        tls.ca_file = '/etc/ssl/certs/ca-certificates.crt'
    "#;

    #[test]
    fn test_sample() {
        let maybe_conf = parse_string(SAMPLE_CONF.into());
        match maybe_conf {
            Ok(conf) => {
                let in_tls = conf.input.tls.unwrap();
                assert_eq!(conf.input.server, "nats://10.20.30.40:4222".to_owned().into_boxed_str());
                assert!(conf.input.auth.is_none());
                assert_eq!(conf.input.subject, "NS.log.vector-in".to_owned().into_boxed_str());
                assert_eq!(in_tls.server_name.unwrap(), "nats.local".to_owned().into_boxed_str());
                assert_eq!(in_tls.ca_file.unwrap(), "./nats_ca.crt".to_owned().into_boxed_str());
                assert_eq!(in_tls.cert_file.unwrap(), "./nats_client.crt".to_owned().into_boxed_str());
                assert_eq!(in_tls.key_file.unwrap(), "./nats_client.key".to_owned().into_boxed_str());

                let sn_auth = conf.sink.auth.unwrap();
                let sn_tls = conf.sink.tls.unwrap();
                assert_eq!(conf.sink.server, "nats://nats.example.com:4222".to_owned().into_boxed_str());
                assert_eq!(sn_auth.username.unwrap(), "derek".to_owned().into_boxed_str());
                assert_eq!(sn_auth.password.unwrap(), "s3cr3t!".to_owned().into_boxed_str());
                assert_eq!(conf.sink.subject_tpl, "bulk.section.{section}".to_owned().into_boxed_str());
                assert_eq!(sn_tls.ca_file.unwrap(), "/etc/ssl/certs/ca-certificates.crt".to_owned().into_boxed_str());
                assert!(sn_tls.cert_file.is_none());
                assert!(sn_tls.key_file.is_none());
            }
            Err(_) => {
                assert!(false);
            }
        }
    }
}
