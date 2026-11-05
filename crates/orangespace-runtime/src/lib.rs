//! Private service-owned helper runtime. No browser authorization is produced.
//! Protected installation/hash/ancestor ACL verification belongs to the service.
// Keep both C ABI surfaces in one Rust archive, rather than linking two std copies.
use orangespace_core::{
    Binding,
    helper::{HelperSupervisor, TrustedExecutable},
    tunnel::LocalProxyProtocol,
};
pub use orangespace_https::{
    OsHttpsBytes, OsHttpsRequest, OsHttpsTransferRequest, os_https_request_v1, os_https_transfer_v1,
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    time::Duration,
};
mod validation;
use validation::*;
mod proof;
use proof::*;

#[derive(Clone, Copy, Debug)]
enum Error {
    Invalid,
    FailedClosed,
}
// Successful replies carry their original authorization fence privately through
// output serialization. It is never reconstructed from server wall timestamps.
struct Publication {
    binding: Binding,
    deadline: u64,
    observation_deadline: Option<u64>,
}
#[derive(serde::Serialize)]
#[serde(transparent)]
struct Reply {
    value: Value,
    #[serde(skip)]
    publication: Option<Publication>,
}
impl std::ops::Deref for Reply {
    type Target = Value;
    fn deref(&self) -> &Value {
        &self.value
    }
}
impl From<Value> for Reply {
    fn from(value: Value) -> Self {
        Self {
            value,
            publication: None,
        }
    }
}
struct Active {
    expires_at: u64,
    deadline: u64,
}
// Only the privileged caller's successfully validated node renewal can reach
// this operation. Equal absolute expiry is idempotent, never extra lease time.
fn renew_deadline(active: &Active, expiry: u64, budget: &Budget, now: u64) -> Result<u64, Error> {
    budget.validate_at(now).map_err(|_| Error::Invalid)?;
    if now >= active.deadline || expiry == 0 || expiry > MAX_EXACT {
        return Err(Error::Invalid);
    }
    let advance = expiry
        .checked_sub(active.expires_at)
        .and_then(|v| v.checked_mul(1000))
        .ok_or(Error::Invalid)?;
    let limit = active
        .deadline
        .checked_add(advance)
        .filter(|v| *v <= MAX_EXACT)
        .ok_or(Error::Invalid)?;
    let deadline = budget.deadline_ms.min(limit);
    if deadline <= now {
        return Err(Error::Invalid);
    }
    Ok(deadline)
}

// Bounded by the active binding cap; never serialized or persisted. No TUIC secret.
struct ProbeContext {
    channel_taken: bool,
    channel_deadline: u64,
    channel_ttl: u64,
    proof_at: Option<u64>,
    port: u16,
    user: String,
    password: String,
    probe_port: u16,
    probe_request: String,
    probe_response: String,
}
// Explicitly scrub owned transient authentication bytes. This does not claim
// physical erasure of preexisting allocator/serde copies elsewhere in core.
fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: each byte is exclusively borrowed and remains live.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}
impl Drop for ProbeContext {
    fn drop(&mut self) {
        for value in [
            &mut self.user,
            &mut self.password,
            &mut self.probe_request,
            &mut self.probe_response,
        ] {
            // SAFETY: zero bytes are valid UTF-8; no length/capacity change.
            unsafe { wipe(value.as_mut_vec()) };
        }
    }
}
struct Runtime {
    trusted_ca: Option<String>,
    supervisor: HelperSupervisor,
    timeout: Duration,
    active: HashMap<Binding, Active>,
    probes: HashMap<Binding, ProbeContext>,
    pending_exits: Vec<Value>,
    attempts: usize,
    history: HashMap<orangespace_core::SandboxId, (orangespace_core::UserId, u64)>,
    tunnels: std::collections::HashSet<orangespace_core::TunnelId>,
    #[cfg(test)]
    test_certificate: Option<PathBuf>,
}
impl Runtime {
    #[cfg(test)]
    fn new(path: PathBuf, timeout: Duration) -> Result<Self, ()> {
        Self::new_with_local_proxy(path, timeout, LocalProxyProtocol::Socks)
    }
    fn new_with_local_proxy(
        path: PathBuf,
        timeout: Duration,
        protocol: LocalProxyProtocol,
    ) -> Result<Self, ()> {
        if timeout.is_zero() || timeout > Duration::from_secs(30) {
            return Err(());
        }
        Ok(Self {
            trusted_ca: None,
            supervisor: HelperSupervisor::new_with_local_proxy(
                TrustedExecutable::acknowledge_protected_installation(path).map_err(|_| ())?,
                timeout,
                protocol,
            )
            .map_err(|_| ())?,
            timeout,
            active: HashMap::new(),
            probes: HashMap::new(),
            pending_exits: Vec::new(),
            attempts: 0,
            history: HashMap::new(),
            tunnels: std::collections::HashSet::new(),
            #[cfg(test)]
            test_certificate: None,
        })
    }
    fn dispatch(&mut self, bytes: &[u8]) -> Result<Reply, Error> {
        if bytes.len() > 65536 {
            return Err(Error::Invalid);
        }
        match serde_json::from_slice::<Request>(bytes).map_err(|_| Error::Invalid)? {
            Request::Start {
                binding,
                lease,
                budget,
                ..
            } => {
                let b = binding.binding().map_err(|_| Error::Invalid)?;
                lease.validate(b).map_err(|_| Error::Invalid)?;
                budget
                    .validate_at(clock_ms().map_err(|_| Error::FailedClosed)?)
                    .map_err(|_| Error::Invalid)?;
                if budget.remaining_ttl_ms != lease.remaining_ttl_ms {
                    return Err(Error::Invalid);
                }
                if self.attempts >= 4096 || self.active.len() + self.pending_exits.len() >= 64 {
                    return Err(Error::Invalid);
                }
                self.start(b, *lease, budget)
            }
            Request::Probe {
                binding, budget, ..
            } => {
                let b = binding.binding().map_err(|_| Error::Invalid)?;
                self.probe(b, budget)
            }
            Request::Close { binding, .. } => {
                let b = binding.binding().map_err(|_| Error::Invalid)?;
                if !self.active.contains_key(&b) {
                    return Err(Error::Invalid);
                }
                self.supervisor.close(b).map_err(|_| Error::FailedClosed)?;
                self.active.remove(&b);
                self.probes.remove(&b);
                Ok(json!({"ok":true,"binding":b,"running":false}).into())
            }
            Request::Renew {
                binding,
                expires_at,
                budget,
                ..
            } => {
                let b = binding.binding().map_err(|_| Error::Invalid)?;
                let old_deadline = self.active.get(&b).ok_or(Error::Invalid)?.deadline;
                let deadline = renew_deadline(
                    self.active.get(&b).ok_or(Error::Invalid)?,
                    expires_at,
                    &budget,
                    clock_ms().map_err(|_| Error::FailedClosed)?,
                )?;
                if let Some(exit) = self.supervisor.poll(b).map_err(|_| Error::FailedClosed)? {
                    self.active.remove(&b);
                    self.probes.remove(&b);
                    self.pending_exits.push(json!({"binding":b,"pid":exit.pid}));
                    return Err(Error::Invalid);
                }
                let active = self.active.get_mut(&b).ok_or(Error::Invalid)?;
                let checked_deadline = renew_deadline(
                    active,
                    expires_at,
                    &budget,
                    clock_ms().map_err(|_| Error::FailedClosed)?,
                )?
                .min(deadline);
                active.expires_at = expires_at;
                active.deadline = checked_deadline;
                Ok(Reply {
                    value: json!({"ok":true,"binding":b,"expires_at":expires_at}),
                    publication: Some(Publication {
                        binding: b,
                        deadline: checked_deadline.min(old_deadline),
                        observation_deadline: None,
                    }),
                })
            }
            Request::Poll { .. } => {
                let mut exited = std::mem::take(&mut self.pending_exits);
                for exit in self
                    .supervisor
                    .reap_exits()
                    .map_err(|_| Error::FailedClosed)?
                {
                    self.active.remove(&exit.binding);
                    self.probes.remove(&exit.binding);
                    exited.push(json!({"binding":exit.binding,"pid":exit.pid}));
                }
                let now = clock_ms().map_err(|_| Error::FailedClosed)?;
                let expired: Vec<_> = self
                    .active
                    .iter()
                    .filter_map(|(&b, a)| (now >= a.deadline).then_some(b))
                    .collect();
                for b in expired {
                    let exit = self.supervisor.close(b).map_err(|_| Error::FailedClosed)?;
                    self.active.remove(&b);
                    self.probes.remove(&b);
                    exited.push(json!({"binding":b,"pid":exit.pid}));
                }
                Ok(json!({"ok":true,"exited":exited}).into())
            }
        }
    }
    fn start(&mut self, b: Binding, lease: Lease, budget: Budget) -> Result<Reply, Error> {
        if self.active.keys().any(|x| x.sandbox_id == b.sandbox_id)
            || self
                .history
                .get(&b.sandbox_id)
                .is_some_and(|(user, generation)| *user != b.user_id || b.generation <= *generation)
            || self.tunnels.contains(&b.tunnel_id)
        {
            return Err(Error::Invalid);
        }
        let reservation = TcpListener::bind("127.0.0.1:0").map_err(|_| Error::FailedClosed)?;
        let port = reservation
            .local_addr()
            .map_err(|_| Error::FailedClosed)?
            .port();
        let user = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let password = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        // Own secrets under cleanup before any fallible preparation or spawn.
        let mut context = ProbeContext {
            channel_taken: false,
            channel_deadline: budget.deadline_ms,
            channel_ttl: budget.remaining_ttl_ms,
            proof_at: None,
            port,
            user,
            password,
            probe_port: lease.probe_port,
            probe_request: lease.probe_request.clone(),
            probe_response: lease.probe_response.clone(),
        };
        let mut settings = lease
            .settings(b, port, &context.user, &context.password)
            .map_err(|_| Error::Invalid)?;
        settings.certificate = self.trusted_ca.clone();
        #[cfg(test)]
        {
            settings.certificate_path = self.test_certificate.clone();
        }
        let now = clock_ms().map_err(|_| Error::FailedClosed)?;
        budget.validate_at(now).map_err(|_| Error::Invalid)?;
        let lease_deadline = budget.deadline_ms;
        let deadline = lease_deadline.min(
            now.checked_add(self.timeout.as_millis() as u64)
                .ok_or(Error::Invalid)?,
        );
        let stdin_deadline = stdin_io_deadline(deadline).map_err(|_| Error::Invalid)?;
        // std cannot transfer a reserved listener to sing-box. Release directly
        // before spawn; a port squatter cannot forge the independent node proof.
        drop(reservation);
        self.attempts += 1;
        self.history.insert(b.sandbox_id, (b.user_id, b.generation));
        self.tunnels.insert(b.tunnel_id);
        let pid = self
            .supervisor
            .start_until(b, &settings, stdin_deadline)
            .map_err(|_| Error::FailedClosed)?;
        let proof = Self::forward_proof(b, &context, deadline);
        let proof_at = clock_ms().map_err(|_| Error::FailedClosed)?;
        let exited = self
            .supervisor
            .poll(b)
            .map_err(|_| Error::FailedClosed)?
            .is_some();
        let verified = proof.is_ok()
            && !exited
            && clock_ms().map_err(|_| Error::FailedClosed)? < lease_deadline;
        if verified {
            context.proof_at = Some(proof_at);
            self.probes.insert(b, context);
            self.active.insert(
                b,
                Active {
                    expires_at: lease.expires_at,
                    deadline: lease_deadline,
                },
            );
        } else if !exited {
            // No failed-proof child survives publication. ABI errors invalidate
            // the whole supervisor rather than falsely claiming successful reap.
            self.supervisor.close(b).map_err(|_| Error::FailedClosed)?;
        }
        Ok(Reply {
            value: json!({"ok":verified,"binding":b,"process_started":true,"tunnel_authenticated":verified,"forwarding_verified":verified,"running":verified,"pid":pid,"socks_port":port}),
            publication: verified.then_some(Publication {
                binding: b,
                deadline: lease_deadline,
                observation_deadline: None,
            }),
        })
    }
    fn publish(&mut self, publication: Option<Publication>) -> Result<(), Error> {
        let Some(p) = publication else {
            return Ok(());
        };
        let b = p.binding;
        let active = self.active.get(&b).ok_or(Error::Invalid)?;
        let deadline = p.deadline.min(active.deadline);
        if let Some(exit) = self.supervisor.poll(b).map_err(|_| Error::FailedClosed)? {
            self.active.remove(&b);
            self.probes.remove(&b);
            self.pending_exits.push(json!({"binding":b,"pid":exit.pid}));
            return Err(Error::Invalid);
        }
        let now = clock_ms().map_err(|_| Error::FailedClosed)?;
        if now >= deadline {
            let exit = self.supervisor.close(b).map_err(|_| Error::FailedClosed)?;
            self.active.remove(&b);
            self.probes.remove(&b);
            self.pending_exits.push(json!({"binding":b,"pid":exit.pid}));
            return Err(Error::Invalid);
        }
        if p.observation_deadline.is_some_and(|d| now >= d) {
            // Observation timeout is not lease expiry: preserve this healthy helper.
            return Err(Error::Invalid);
        }
        Ok(())
    }
    fn probe(&mut self, b: Binding, budget: Budget) -> Result<Reply, Error> {
        let now = clock_ms().map_err(|_| Error::FailedClosed)?;
        budget.validate_at(now).map_err(|_| Error::Invalid)?;
        let negative = |reason,
                        process_alive,
                        lease_deadline,
                        expires_at|
         -> Result<Reply, Error> {
            Ok(json!({"ok":false,"binding":b,"process_alive":process_alive,
                "forwarding_verified":false,"observed_at_ms":clock_ms().map_err(|_| Error::FailedClosed)?,
                "lease_deadline_ms":lease_deadline,"expires_at":expires_at,"reason":reason}).into())
        };
        let Some(active) = self.active.get(&b) else {
            return negative("not_active", false, 0u64, 0u64);
        };
        let lease_deadline = active.deadline;
        let expires_at = active.expires_at;
        let deadline = lease_deadline.min(budget.deadline_ms).min(
            now.checked_add(self.timeout.as_millis() as u64)
                .ok_or(Error::Invalid)?,
        );
        // Keep exact-root cleanup and fail-closed errors in the existing local fence.
        if let Err(error) = self.publish(Some(Publication {
            binding: b,
            deadline: lease_deadline,
            observation_deadline: None,
        })) {
            return match error {
                Error::Invalid if !self.active.contains_key(&b) => negative(
                    if clock_ms().map_err(|_| Error::FailedClosed)? >= lease_deadline {
                        "expired"
                    } else {
                        "helper_stopped"
                    },
                    false,
                    0,
                    0,
                ),
                error => Err(error),
            };
        }
        let context = self.probes.get(&b).ok_or(Error::Invalid)?;
        let verified = Self::forward_proof(b, context, deadline).is_ok();
        let proof_at = clock_ms().map_err(|_| Error::FailedClosed)?;
        if let Err(error) = self.publish(Some(Publication {
            binding: b,
            deadline: lease_deadline,
            observation_deadline: None,
        })) {
            return match error {
                Error::Invalid if !self.active.contains_key(&b) => negative(
                    if clock_ms().map_err(|_| Error::FailedClosed)? >= lease_deadline {
                        "expired"
                    } else {
                        "helper_stopped"
                    },
                    false,
                    0,
                    0,
                ),
                error => Err(error),
            };
        }
        let observed_at = clock_ms().map_err(|_| Error::FailedClosed)?;
        self.probes.get_mut(&b).ok_or(Error::Invalid)?.proof_at =
            (verified && observed_at < deadline).then_some(proof_at);
        if !verified || observed_at >= deadline {
            return negative("probe_failed", true, lease_deadline, expires_at);
        }
        Ok(Reply {
            value: json!({"ok":true,"binding":b,"process_alive":true,"forwarding_verified":true,
                "observed_at_ms":observed_at,"lease_deadline_ms":lease_deadline,
                "expires_at":expires_at,"reason":"verified"}),
            publication: Some(Publication {
                binding: b,
                deadline: lease_deadline,
                observation_deadline: Some(deadline),
            }),
        })
    }
    fn forward_proof(b: Binding, context: &ProbeContext, deadline: u64) -> Result<(), ()> {
        let address = std::net::SocketAddr::from(([127, 0, 0, 1], context.port));
        let stream = loop {
            let left = remaining(deadline).map_err(|_| ())?;
            match TcpStream::connect_timeout(&address, left.min(Duration::from_millis(100))) {
                Ok(stream) => break stream,
                Err(_) => std::thread::sleep(left.min(Duration::from_millis(10))),
            }
        };
        let mut stream = DeadlineStream { stream, deadline };
        stream.write_all(&[5, 1, 2]).map_err(|_| ())?;
        let mut reply = [0; 2];
        stream.read_exact(&mut reply).map_err(|_| ())?;
        if reply != [5, 2] {
            return Err(());
        }
        let user = &context.user;
        let password = &context.password;
        let mut auth = ffi::SecretBuffer::new();
        let mut writer = io::Cursor::new(&mut auth.0[..]);
        writer.write_all(&[1, user.len() as u8]).map_err(|_| ())?;
        writer.write_all(user.as_bytes()).map_err(|_| ())?;
        writer.write_all(&[password.len() as u8]).map_err(|_| ())?;
        writer.write_all(password.as_bytes()).map_err(|_| ())?;
        let length = writer.position() as usize;
        stream.write_all(&auth.0[..length]).map_err(|_| ())?;
        stream.read_exact(&mut reply).map_err(|_| ())?;
        if reply != [1, 0] {
            return Err(());
        }
        let mut connect = vec![5, 1, 0, 1, 127, 0, 0, 1];
        connect.extend_from_slice(&context.probe_port.to_be_bytes());
        stream.write_all(&connect).map_err(|_| ())?;
        let mut head = [0; 4];
        stream.read_exact(&mut head).map_err(|_| ())?;
        if head[..3] != [5, 0, 0] {
            return Err(());
        }
        let size = match head[3] {
            1 => 4,
            4 => 16,
            3 => {
                let mut n = [0];
                stream.read_exact(&mut n).map_err(|_| ())?;
                if n[0] == 0 {
                    return Err(());
                }
                n[0] as usize
            }
            _ => return Err(()),
        };
        let mut bound = vec![0; size + 2];
        stream.read_exact(&mut bound).map_err(|_| ())?;
        let request = format!(
            "POST /v1/tunnels/{}/probe HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-OrangeSpace-Probe: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            b.tunnel_id, context.probe_port, context.probe_request
        );
        stream.write_all(request.as_bytes()).map_err(|_| ())?;
        verify_http(&mut stream, b, &context.probe_response)
    }
}
fn stdin_io_deadline(deadline: u64) -> io::Result<std::time::Instant> {
    // Pair conservatively: sample Instant BEFORE computing remaining common OS
    // time. Preparation/scheduling after either sample cannot restart the I/O
    // budget. The original common deadline remains the authorization fence.
    let sampled = std::time::Instant::now();
    sampled
        .checked_add(remaining(deadline)?)
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "helper start deadline"))
}
fn remaining(deadline: u64) -> io::Result<Duration> {
    clock_ms()
        .ok()
        .and_then(|now| deadline.checked_sub(now))
        .filter(|v| *v > 0)
        .map(Duration::from_millis)
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "proof deadline"))
}
struct DeadlineStream {
    stream: TcpStream,
    deadline: u64,
}
impl DeadlineStream {
    fn remaining(&self) -> io::Result<Duration> {
        remaining(self.deadline)
    }
}
impl Read for DeadlineStream {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(b)
    }
}
impl Write for DeadlineStream {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}
mod ffi;
pub use ffi::{
    os_runtime_call, os_runtime_free, os_runtime_new, os_runtime_new_with_ca_v1,
    os_runtime_new_with_local_proxy_v1, os_runtime_take_local_channel_v1,
};

#[cfg(test)]
mod tests;
