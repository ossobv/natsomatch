use std::str::FromStr; // implements from_str on PathBuf

use crate::config_parser;


///
/// There is no conversion from Box<str> to PathBuf. Create it with to_path_buf().
///
trait ToPathBuf {
    fn to_path_buf(&self) -> std::path::PathBuf;
}
impl ToPathBuf for Box<str> {
    fn to_path_buf(&self) -> std::path::PathBuf {
        std::path::PathBuf::from_str(self).expect("failure converting to std::path::PathBuf")
    }
}


pub async fn connect(_name: &str, server: &str, maybe_tls: &Option<config_parser::TlsConfig>) -> Result<async_nats::Client, async_nats::ConnectError> {
    let mut options = async_nats::ConnectOptions::new();

    if let Some(tls) = maybe_tls {
        options = options.require_tls(true);
        if let Some(_) = &tls.server_name {
            eprintln!("warning: tls.server_name is not implemented");
        }
        if let Some(ca_file) = &tls.ca_file {
            options = options.add_root_certificates(ca_file.to_path_buf());
        }
        match (&tls.cert_file, &tls.key_file) {
            (Some(cert), Some(key)) => {
                options = options.add_client_certificate(cert.to_path_buf(), key.to_path_buf());
            },
            _ => {},
        }
    }

    return options.connect(server).await;
}
