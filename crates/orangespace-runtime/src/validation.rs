use orangespace_core::{Binding, NodeId, SandboxId, TunnelId, UserId};
use serde::Deserialize;
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WireBinding {
    user_id: String,
    sandbox_id: String,
    node_id: String,
    generation: u64,
    tunnel_id: String,
}
fn canonical_id(value: &str) -> Result<Uuid, ()> {
    let id = Uuid::parse_str(value).map_err(|_| ())?;
    if id.is_nil() || id.to_string() != value {
        return Err(());
    }
    Ok(id)
}
impl WireBinding {
    pub(crate) fn binding(&self) -> Result<Binding, ()> {
        if self.generation == 0 || self.generation > 9_007_199_254_740_991 {
            return Err(());
        }
        Ok(Binding {
            user_id: UserId(canonical_id(&self.user_id)?),
            sandbox_id: SandboxId(canonical_id(&self.sandbox_id)?),
            node_id: NodeId(canonical_id(&self.node_id)?),
            generation: self.generation,
            tunnel_id: TunnelId(canonical_id(&self.tunnel_id)?),
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Lease {
    #[serde(deserialize_with = "schema2")]
    lease_schema: u8,
    pub(crate) remaining_ttl_ms: u64,
    user_id: String,
    sandbox_id: String,
    node_id: String,
    generation: u64,
    tunnel_id: String,
    pub(crate) expires_at: u64,
    pub(crate) endpoint_ip: std::net::IpAddr,
    pub(crate) endpoint_port: u16,
    pub(crate) tls_server_name: String,
    pub(crate) tuic_uuid: String,
    pub(crate) tuic_password: String,
    pub(crate) probe_host: String,
    pub(crate) probe_port: u16,
    pub(crate) probe_request: String,
    pub(crate) probe_response: String,
}
impl Lease {
    pub(crate) fn validate(&self, binding: Binding) -> Result<(), ()> {
        if self.binding()? != binding
            || self.lease_schema != 2
            || self.expires_at == 0
            || self.expires_at > MAX_EXACT
            || self.remaining_ttl_ms == 0
            || self.remaining_ttl_ms > 30000
            || self.probe_host != "127.0.0.1"
            || self.probe_port == 0
            || !probe_secret(&self.probe_request)
            || !probe_secret(&self.probe_response)
            || self.probe_request == self.probe_response
            || self.tuic_password.len() < 16
            || self.tuic_password.len() > 256
            || self.tuic_password.chars().any(char::is_control)
            || self.tuic_password == self.probe_request
            || self.tuic_password == self.probe_response
            || canonical_id(&self.tuic_uuid)? == binding.user_id.0
        {
            return Err(());
        }
        let settings = self.settings(
            binding,
            1,
            "validation",
            "validation-only-not-a-real-secret",
        )?;
        orangespace_core::tunnel::sing_box_config(binding, &settings).map_err(|_| ())?;
        Ok(())
    }
    pub(crate) fn settings(
        &self,
        binding: Binding,
        port: u16,
        user: &str,
        password: &str,
    ) -> Result<orangespace_core::tunnel::TunnelSettings, ()> {
        serde_json::from_value(
            serde_json::json!({"node_id":binding.node_id,"endpoint_ip":self.endpoint_ip,
            "endpoint_port":self.endpoint_port,"tls_server_name":self.tls_server_name,
            "tuic_uuid":self.tuic_uuid,"tuic_password":self.tuic_password,
            "socks_port":port,"socks_username":user,"socks_password":password}),
        )
        .map_err(|_| ())
    }
    fn binding(&self) -> Result<Binding, ()> {
        WireBinding {
            user_id: self.user_id.clone(),
            sandbox_id: self.sandbox_id.clone(),
            node_id: self.node_id.clone(),
            generation: self.generation,
            tunnel_id: self.tunnel_id.clone(),
        }
        .binding()
    }
}
fn schema2<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u8, D::Error> {
    let value = u8::deserialize(d)?;
    if value != 2 {
        return Err(serde::de::Error::custom("invalid schema"));
    }
    Ok(value)
}
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Request {
    Start {
        #[serde(rename = "schema", deserialize_with = "schema2")]
        _schema: u8,
        budget: Budget,
        binding: WireBinding,
        lease: Box<Lease>,
    },
    Probe {
        #[serde(rename = "schema", deserialize_with = "schema2")]
        _schema: u8,
        binding: WireBinding,
        budget: Budget,
    },
    Close {
        #[serde(rename = "schema", deserialize_with = "schema2")]
        _schema: u8,
        binding: WireBinding,
    },
    Renew {
        #[serde(rename = "schema", deserialize_with = "schema2")]
        _schema: u8,
        binding: WireBinding,
        expires_at: u64,
        budget: Budget,
    },
    Poll {
        #[serde(rename = "schema", deserialize_with = "schema2")]
        _schema: u8,
    },
}
#[cfg(test)]
pub(crate) fn now_secs() -> Result<u64, ()> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| ())
}
#[cfg(test)]
pub(crate) fn parse_start(bytes: &[u8]) -> Result<(Binding, Lease), ()> {
    match serde_json::from_slice::<Request>(bytes).map_err(|_| ())? {
        Request::Start {
            binding,
            lease,
            budget,
            ..
        } => {
            let b = binding.binding()?;
            lease.validate(b)?;
            budget.validate_at(clock_ms()?)?;
            if budget.remaining_ttl_ms != lease.remaining_ttl_ms {
                return Err(());
            }
            Ok((b, *lease))
        }
        _ => Err(()),
    }
}

fn probe_secret(s: &str) -> bool {
    s.len() == 43
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

pub(crate) const MAX_EXACT: u64 = 9_007_199_254_740_991;
#[cfg(target_os = "linux")]
pub(crate) const CLOCK: &str = "linux-clock-monotonic-ms-v1";
#[cfg(windows)]
pub(crate) const CLOCK: &str = "windows-gettickcount64-ms-v1";
#[cfg(not(any(target_os = "linux", windows)))]
pub(crate) const CLOCK: &str = "unsupported";

// OS clock epoch shared with the privileged C++ caller, never Rust Instant.
pub(crate) fn clock_ms() -> Result<u64, ()> {
    #[cfg(target_os = "linux")]
    {
        #[repr(C)]
        struct Timespec {
            sec: std::ffi::c_long,
            nsec: std::ffi::c_long,
        }
        unsafe extern "C" {
            fn clock_gettime(clock: std::ffi::c_int, value: *mut Timespec) -> std::ffi::c_int;
        }
        let mut value = Timespec { sec: 0, nsec: 0 };
        // SAFETY: Linux CLOCK_MONOTONIC=1; writable native timespec layout.
        if unsafe { clock_gettime(1, &mut value) } != 0
            || value.sec < 0
            || !(0..1_000_000_000).contains(&value.nsec)
        {
            return Err(());
        }
        let ms = (value.sec as u64)
            .checked_mul(1000)
            .and_then(|v| v.checked_add(value.nsec as u64 / 1_000_000))
            .ok_or(())?;
        if ms > MAX_EXACT {
            return Err(());
        }
        Ok(ms)
    }
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetTickCount64() -> u64;
        }
        // SAFETY: takes no parameters and has no caller preconditions.
        let ms = unsafe { GetTickCount64() };
        if ms > MAX_EXACT {
            return Err(());
        }
        Ok(ms)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        Err(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Budget {
    clock: String,
    request_started_ms: u64,
    pub(crate) remaining_ttl_ms: u64,
    pub(crate) deadline_ms: u64,
}
impl Budget {
    pub(crate) fn validate_at(&self, now: u64) -> Result<(), ()> {
        if self.clock != CLOCK
            || CLOCK == "unsupported"
            || self.request_started_ms > now
            || self.request_started_ms > MAX_EXACT
            || self.remaining_ttl_ms == 0
            || self.remaining_ttl_ms > 30000
            || self.deadline_ms > MAX_EXACT
            || self.deadline_ms <= now
            || self.request_started_ms.checked_add(self.remaining_ttl_ms) != Some(self.deadline_ms)
        {
            return Err(());
        }
        Ok(())
    }
}
