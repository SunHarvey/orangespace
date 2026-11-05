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
    /// Service-owned immutable trust snapshot, delivered only through helper stdin.
    #[serde(default)]
    pub certificate: Option<String>,
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
    #[error("TLS identity must be an explicit DNS name or the endpoint's canonical IP address")]
    InvalidServerName,
    #[error("empty or short tunnel credentials")]
    InvalidCredentials,
}

/// Selected by the trusted local supervisor, not by node credentials or a
/// browser readiness flag. Existing callers retain the SOCKS-only default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalProxyProtocol {
    Socks,
    AuthenticatedMixed,
}

pub fn sing_box_config(binding: Binding, settings: &TunnelSettings) -> Result<Value, ConfigError> {
    sing_box_config_for_protocol(binding, settings, LocalProxyProtocol::Socks)
}

pub fn sing_box_config_for_protocol(
    binding: Binding,
    settings: &TunnelSettings,
    protocol: LocalProxyProtocol,
) -> Result<Value, ConfigError> {
    if settings.node_id != binding.node_id {
        return Err(ConfigError::NodeMismatch);
    }
    if settings.endpoint_port == 0 || settings.socks_port == 0 {
        return Err(ConfigError::InvalidPort);
    }
    let invalid_identity = match settings.tls_server_name.parse::<IpAddr>() {
        Ok(identity) => {
            identity != settings.endpoint_ip || identity.to_string() != settings.tls_server_name
        }
        Err(_) => {
            // Do not reinterpret malformed numeric IPs as DNS identities.
            settings
                .tls_server_name
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
                || settings.tls_server_name.split('.').any(|label| {
                    label.is_empty()
                        || label.len() > 63
                        || label.starts_with('-')
                        || label.ends_with('-')
                        || !label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
        }
    };
    if settings.tls_server_name.is_empty()
        || settings.tls_server_name.len() > 253
        || invalid_identity
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
    if protocol == LocalProxyProtocol::AuthenticatedMixed {
        config["inbounds"][0]["type"] = json!("mixed");
        config["inbounds"][0]["set_system_proxy"] = json!(false);
    }
    if let Some(certificate) = &settings.certificate {
        config["outbounds"][0]["tls"]["certificate"] = json!(certificate);
    }
    if let Some(path) = &settings.certificate_path {
        config["outbounds"][0]["tls"]["certificate_path"] = json!(path);
    }
    Ok(config)
}
