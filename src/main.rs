use discret::{base64_encode, generate_x509_certificate, hash, Beacon};
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::fs;
///
/// Provides a basic implementation of a server that allows Discret peers to find each others on Internet
///
///
use std::{error::Error, ops::Deref, path::Path};
use tokio::sync::Notify;

#[tokio::main]
async fn main() {
    init_log();

    match start_beacon().await {
        Ok(hash) => {
            info!("Beacon Sarted with certificate hash: '{hash}'");
            let notify = Notify::new();
            notify.notified().await;
        }
        Err(e) => error!("{e}"),
    }
}

#[derive(Deserialize, Serialize)]
struct Certificate {
    der: Vec<u8>,
    pks_der: Vec<u8>,
}

#[derive(Deserialize)]
struct Configuration {
    //the ipv4 listenning port
    port: u16,
}
impl Default for Configuration {
    fn default() -> Self {
        Self { port: 4264 }
    }
}

fn init_log() {
    fs::create_dir_all("logs").unwrap();

    let log_config = "log4rs.yml";
    let log_path = Path::new(log_config);
    if !log_path.exists() {
        let default_config = "refresh_rate: 30 seconds
appenders:
  stdout:
    kind: console
  file:
    kind: rolling_file
    path: logs/beacon.log
    policy:
      trigger:
        kind: size
        limit: 10 mb
      roller:
        kind: fixed_window
        pattern: logs/beacon_{}.gz
        count: 5
        base: 1
    encoder:
      pattern: \"{d} - {m}{n}\"
root:
  level: info
  appenders:
    - file";

        fs::write(log_path, default_config).unwrap();
    }
    log4rs::init_file(log_config, Default::default()).unwrap();
}

async fn start_beacon() -> Result<String, Box<dyn Error>> {
    let cert_path = Path::new("cert_der.bin");
    let (cert, cert_hash) = if cert_path.exists() {
        let bin_cert = fs::read(cert_path)?;
        let cert: Certificate = bincode::deserialize(&bin_cert)?;
        let cert_hash = hash(&cert.der);
        let cert_hash = base64_encode(&cert_hash);
        (cert, cert_hash)
    } else {
        let certificate = generate_x509_certificate("discret_beacon");

        let der: Vec<u8> = certificate.cert.der().deref().to_vec();
        let pks_der: Vec<u8> = certificate.key_pair.serialize_der();
        let cert = Certificate { der, pks_der };
        let cert_hash = hash(&cert.der);
        let cert_hash = base64_encode(&cert_hash);

        let serialised = bincode::serialize(&cert)?;
        fs::write(cert_path, serialised)?;
        (cert, cert_hash)
    };
    fs::write("certificate_hash.txt", &cert_hash)?;

    let conf_path = Path::new("Beacon.conf.toml");
    if !conf_path.exists() {
        let default_conf = "# The IPV4 listening port
# Default value: 4264
port = 4264

";
        fs::write(conf_path, default_conf)?;
    }
    let conf_data = fs::read_to_string("Beacon.conf.toml")?;
    let conf: Configuration = toml::from_str(&conf_data)?;

    Beacon::start(conf.port, cert.der.clone(), cert.pks_der.clone(), false)?;
    Ok(cert_hash)
}
