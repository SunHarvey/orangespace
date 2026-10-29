use crate::{Binding, NodeId};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{fmt, net::IpAddr, path::PathBuf};
use thiserror::Error;
use uuid::Uuid;

/// Intentionally does not implement Serialize or reveal fields through Debug.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelSettings {
    /// Must match the sandbox's binding for this configuration.
    pub node_id: NodeId,
    pub endpoint_ip: IpAddr,
    pub endpoint_port: u16,
    pub tls_server_name: String,
    /// Optional explicit trust anchor for private nodes/testing; hostname
    /// verification remains enabled. Never equivalent to insecure=true.
    pub certificate_path: Option<PathBuf>,
    pub tuic_uuid: Uuid,
    tuic_password: String,
    pub socks_port: u16,
    socks_username: String,
    socks_password: String,
}

impl fmt::Debug for TunnelSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelSettings")
            .field("endpoint_ip", &self.endpoint_ip)
            .field("endpoint_port", &self.endpoint_port)
            .field("credentials", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ConfigError {
    #[error("tunnel settings node_id does not match the sandbox node binding")]
    NodeMismatch,
    #[error("ports must be nonzero")]
    InvalidPort,
    #[error("TLS server name must be an explicit DNS name without whitespace")]
    InvalidServerName,
    #[error("empty or short tunnel credentials")]
    InvalidCredentials,
}

pub fn sing_box_config(binding: Binding, settings: &TunnelSettings) -> Result<Value, ConfigError> {
    if settings.node_id != binding.node_id {
        return Err(ConfigError::NodeMismatch);
    }
    if settings.endpoint_port == 0 || settings.socks_port == 0 {
        return Err(ConfigError::InvalidPort);
    }
    if settings.tls_server_name.is_empty()
        || settings.tls_server_name.len() > 253
        || settings.tls_server_name.parse::<IpAddr>().is_ok()
        || settings.tls_server_name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(ConfigError::InvalidServerName);
    }
    if settings.tuic_password.len() < 16
        || settings.socks_password.len() < 16
        || settings.socks_username.is_empty()
    {
        return Err(ConfigError::InvalidCredentials);
    }
    let tag = format!("sandbox-{}-{}", binding.sandbox_id, binding.generation);
    let mut config = json!({
        "log": { "level": "error", "timestamp": true },
        "inbounds": [{ "type": "socks", "tag": "broker-only", "listen": "127.0.0.1",
            "listen_port": settings.socks_port,
            "users": [{ "username": settings.socks_username, "password": settings.socks_password }] }],
        "outbounds": [{ "type": "tuic", "tag": tag, "server": settings.endpoint_ip.to_string(),
            "server_port": settings.endpoint_port, "uuid": settings.tuic_uuid,
            "password": settings.tuic_password, "congestion_control": "cubic",
            "udp_relay_mode": "native", "zero_rtt_handshake": false,
            "tls": { "enabled": true, "server_name": settings.tls_server_name, "insecure": false } }],
        "route": { "final": tag }
    });
    if let Some(path) = &settings.certificate_path {
        config["outbounds"][0]["tls"]["certificate_path"] = json!(path);
    }
    Ok(config)
}
