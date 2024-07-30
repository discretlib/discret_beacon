use discret::{base64_encode, generate_x509_certificate, hash, Beacon, LogService};
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::fs;
///
/// Provides a basic implementation of a server that allows Discret peers to find each others on Internet
///
///
use std::{error::Error, ops::Deref, path::Path};
pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"h3"];
#[tokio::main]
async fn main() {
    init_log();
    let log_service: LogService = LogService::start();
    let mut logs = log_service.subcribe().await;

    match start_beacon(log_service).await {
        Ok(hash) => {
            info!("Beacon Sarted with certificate hash: '{hash}'");

            while let Ok(log) = logs.recv().await {
                match log {
                    discret::Log::Info(_, msg) => {
                        info!("{msg}");
                    }
                    discret::Log::Error(_, src, msg) => {
                        error!("source: {src} message: {msg}")
                    }
                }
            }
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
    ipv4_port: u16,

    //the ipv6 listenning port
    ipv6_port: u16,

    //the number of read buffers
    num_buffers: usize,
}
impl Default for Configuration {
    fn default() -> Self {
        Self {
            ipv4_port: 4264,
            ipv6_port: 4266,
            num_buffers: 10,
        }
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

async fn start_beacon(log_service: LogService) -> Result<String, Box<dyn Error>> {
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
ipv4_port = 4264

# The IPV6 listening port
# Default value: 4264
ipv6_port = 4266

# The number of read buffers
# Default value: 32
num_buffers = 32
";
        fs::write(conf_path, default_conf)?;
    }
    let conf_data = fs::read_to_string("Beacon.conf.toml")?;
    let conf: Configuration = toml::from_str(&conf_data)?;

    Beacon::start(
        conf.ipv4_port,
        conf.ipv6_port,
        cert.der.clone(),
        cert.pks_der.clone(),
        log_service,
        conf.num_buffers,
    )?;
    Ok(cert_hash)
}
