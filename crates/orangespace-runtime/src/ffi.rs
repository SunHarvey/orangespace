use super::{Error, LocalProxyProtocol, Runtime};
use std::{
    collections::HashMap,
    ffi::c_void,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

pub const BUFFER_CAPACITY: usize = 65536;

// Dedicated final serialization storage: no secret-bearing DOM, String, Vec,
// reallocating writer, or clone. Construct before borrowing credentials.
pub(super) struct SecretBuffer(pub(super) [u8; 4096]);
impl SecretBuffer {
    pub(super) fn new() -> Self {
        Self([0; 4096])
    }
}
impl Drop for SecretBuffer {
    fn drop(&mut self) {
        super::wipe(&mut self.0);
    }
}
#[derive(serde::Serialize)]
struct LocalChannel<'a> {
    schema: u8,
    binding: orangespace_core::Binding,
    host: &'static str,
    port: u16,
    username: &'a str,
    password: &'a str,
    clock: &'static str,
    request_started_ms: u64,
    remaining_ttl_ms: u64,
    deadline_ms: u64,
    proof_observed_at_ms: u64,
}
// Valid fixed-shape binding input and successful delivery allocate nothing.
// Borrowing also rejects escaped ID strings rather than creating scratch owners.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalBinding<'a> {
    user_id: &'a str,
    sandbox_id: &'a str,
    node_id: &'a str,
    generation: u64,
    tunnel_id: &'a str,
}
impl LocalBinding<'_> {
    fn binding(&self) -> Result<orangespace_core::Binding, Error> {
        use orangespace_core::{Binding, NodeId, SandboxId, TunnelId, UserId};
        fn id(value: &str) -> Result<uuid::Uuid, Error> {
            let id = uuid::Uuid::parse_str(value).map_err(|_| Error::Invalid)?;
            let mut canonical = [0; 36];
            if id.is_nil() || id.hyphenated().encode_lower(&mut canonical) != value {
                return Err(Error::Invalid);
            }
            Ok(id)
        }
        if self.generation == 0 || self.generation > super::MAX_EXACT {
            return Err(Error::Invalid);
        }
        Ok(Binding {
            user_id: UserId(id(self.user_id)?),
            sandbox_id: SandboxId(id(self.sandbox_id)?),
            node_id: NodeId(id(self.node_id)?),
            generation: self.generation,
            tunnel_id: TunnelId(id(self.tunnel_id)?),
        })
    }
}
fn channel_fence(runtime: &mut Runtime, b: orangespace_core::Binding) -> Result<(), Error> {
    let c = runtime.probes.get(&b).ok_or(Error::Invalid)?;
    let channel_deadline = c.channel_deadline;
    if c.channel_taken {
        return Err(Error::Invalid);
    }
    let proof = c.proof_at.ok_or(Error::Invalid)?;
    let deadline = runtime.active.get(&b).ok_or(Error::Invalid)?.deadline;
    // A renewed helper may outlive the original channel grant. Reject a late
    // take without cancelling that separately renewed forwarding owner.
    runtime.publish(Some(super::Publication {
        binding: b,
        deadline,
        observation_deadline: Some(channel_deadline.min(proof.saturating_add(3000))),
    }))
}

/// Once-only Service-owned copy; does not authenticate a Service or browser.
/// # Safety
/// Caller must authenticate/authorize Service and exact root IPC independently.
/// Caller owns bounded input/output ranges, without overlap, and must scrub
/// the successful output after protected delivery. No output is written on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn os_runtime_take_local_channel_v1(
    handle: *mut c_void,
    binding: *const u8,
    len: usize,
    out: *mut u8,
    capacity: usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if binding.is_null() || out.is_null() || len == 0 || len > 4096 {
            return -1;
        }
        if capacity < 4096 {
            return -2;
        }
        let slot = match with_registry(|r| r.slots.get(&handle.addr()).cloned()) {
            Ok(Some(slot)) => slot,
            Ok(None) => return -3,
            Err(()) => return -4,
        };
        // SAFETY: caller guarantees this bounded readable range.
        let input = unsafe { std::slice::from_raw_parts(binding, len) };
        let result = with_slot(&slot, |runtime| {
            let wire: LocalBinding<'_> =
                serde_json::from_slice(input).map_err(|_| Error::Invalid)?;
            let b = wire.binding()?;
            channel_fence(runtime, b)?;
            let mut storage = SecretBuffer::new();
            let c = runtime.probes.get(&b).ok_or(Error::Invalid)?;
            let value = LocalChannel {
                schema: 2,
                binding: b,
                host: "127.0.0.1",
                port: c.port,
                username: &c.user,
                password: &c.password,
                clock: super::CLOCK,
                request_started_ms: c.channel_deadline - c.channel_ttl,
                remaining_ttl_ms: c.channel_ttl,
                deadline_ms: c.channel_deadline,
                proof_observed_at_ms: c.proof_at.ok_or(Error::Invalid)?,
            };
            let mut writer = std::io::Cursor::new(&mut storage.0[..]);
            serde_json::to_writer(&mut writer, &value).map_err(|_| Error::Invalid)?;
            let length = writer.position() as usize;
            // The final exact child/deadline/proof fence is AFTER serialization.
            channel_fence(runtime, b)?;
            // No fallible allocation/serialization remains. Commit + copy stay
            // inside the slot lock, so close/free/take cannot race publication.
            runtime
                .probes
                .get_mut(&b)
                .ok_or(Error::Invalid)?
                .channel_taken = true;
            // SAFETY: caller supplies >=4096 non-overlapping writable bytes.
            unsafe {
                std::ptr::copy_nonoverlapping(storage.0.as_ptr(), out, length);
            }
            Ok(length as i32)
        });
        result.unwrap_or_else(|code| code)
    }))
    .unwrap_or(-4)
}
type Slot = Arc<Mutex<Option<Runtime>>>;
struct Registry {
    next: usize,
    slots: HashMap<usize, Slot>,
}
static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
fn registry() -> &'static Mutex<Registry> {
    REGISTRY.get_or_init(|| {
        Mutex::new(Registry {
            next: 65536,
            slots: HashMap::new(),
        })
    })
}
fn with_registry<T>(f: impl FnOnce(&mut Registry) -> T) -> Result<T, ()> {
    match registry().lock() {
        Ok(mut r) => Ok(f(&mut r)),
        Err(e) => {
            let mut r = e.into_inner();
            let slots: Vec<_> = r.slots.drain().map(|(_, s)| s).collect();
            drop(r);
            for slot in slots {
                invalidate(&slot);
            }
            Err(())
        }
    }
}
fn invalidate(slot: &Slot) {
    let mut guard = slot.lock().unwrap_or_else(|p| p.into_inner());
    drop(guard.take());
}
fn with_slot<T>(slot: &Slot, f: impl FnOnce(&mut Runtime) -> Result<T, Error>) -> Result<T, i32> {
    let mut guard = match slot.lock() {
        Ok(g) => g,
        Err(p) => {
            drop(p.into_inner().take());
            return Err(-4);
        }
    };
    let Some(runtime) = guard.as_mut() else {
        return Err(-3);
    };
    // Catch while retaining the mutex guard. Panic/fatal errors remove and drop
    // the supervisor before returning; no poisoned, half-mutated runtime revives.
    match catch_unwind(AssertUnwindSafe(|| f(runtime))) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(Error::Invalid)) => Err(-1),
        Ok(Err(Error::FailedClosed)) | Err(_) => {
            drop(guard.take());
            Err(-4)
        }
    }
}

/// Construct a PRIVATE service-owned runtime after protected-install validation.
///
/// # Safety
/// `path` must refer to `path_len` readable bytes for this call. The privileged
/// caller must validate the pinned executable/hash and protect all installation
/// ancestors/dependencies/trust roots for the entire runtime lifetime.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn os_runtime_new(
    path: *const u8,
    path_len: usize,
    timeout_ms: u32,
) -> *mut c_void {
    // SAFETY: caller supplies the documented readable path.
    unsafe { construct(path, path_len, timeout_ms, None, LocalProxyProtocol::Socks) }
}
unsafe fn construct(
    path: *const u8,
    path_len: usize,
    timeout_ms: u32,
    trusted_ca: Option<String>,
    protocol: LocalProxyProtocol,
) -> *mut c_void {
    catch_unwind(AssertUnwindSafe(|| {
        if path.is_null()
            || path_len == 0
            || path_len > 32768
            || timeout_ms == 0
            || timeout_ms > 30000
        {
            return std::ptr::null_mut();
        }
        // SAFETY: caller guarantees the bounded readable path range.
        let bytes = unsafe { std::slice::from_raw_parts(path, path_len) };
        let Ok(path) = std::str::from_utf8(bytes) else {
            return std::ptr::null_mut();
        };
        if path.as_bytes().contains(&0) {
            return std::ptr::null_mut();
        }
        let Ok(mut runtime) = Runtime::new_with_local_proxy(
            path.into(),
            Duration::from_millis(timeout_ms.into()),
            protocol,
        ) else {
            return std::ptr::null_mut();
        };
        runtime.trusted_ca = trusted_ca;
        with_registry(|r| {
            if r.slots.len() >= 64 {
                return std::ptr::null_mut();
            }
            let Some(next) = r.next.checked_add(1) else {
                return std::ptr::null_mut();
            };
            let id = r.next;
            r.next = next;
            r.slots.insert(id, Arc::new(Mutex::new(Some(runtime))));
            // Non-dereferenceable monotonic token, never an allocated object.
            std::ptr::without_provenance_mut(id)
        })
        .unwrap_or(std::ptr::null_mut())
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// Construct with a bounded immutable application-private CA PEM snapshot.
/// No system trust mutation, insecure mode, path trust, or retry fallback.
/// Invalid PEM is rejected by the helper before any forwarding is accepted.
///
/// # Safety
/// Same installation/path requirements as `os_runtime_new`; `ca` must be
/// readable for `ca_len` bytes for this call only. The privileged caller must
/// obtain CA exclusively from its protected, identity-matched static catalog.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn os_runtime_new_with_ca_v1(
    path: *const u8,
    path_len: usize,
    timeout_ms: u32,
    ca: *const u8,
    ca_len: usize,
) -> *mut c_void {
    if ca.is_null() || ca_len == 0 {
        return std::ptr::null_mut();
    }
    // SAFETY: same caller-owned ranges; legacy requires a nonempty CA.
    unsafe { os_runtime_new_with_local_proxy_v1(path, path_len, timeout_ms, ca, ca_len, 0) }
}

/// Trusted immutable protocol: 0 SOCKS, 1 authenticated HTTP/CONNECT + SOCKS.
/// Null CA with zero length retains normal system trust; otherwise same CA validation.
/// # Safety
/// Same protected installation and readable ranges as `os_runtime_new_with_ca_v1`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn os_runtime_new_with_local_proxy_v1(
    path: *const u8,
    path_len: usize,
    timeout_ms: u32,
    ca: *const u8,
    ca_len: usize,
    protocol: u32,
) -> *mut c_void {
    catch_unwind(AssertUnwindSafe(|| {
        let protocol = match protocol {
            0 => LocalProxyProtocol::Socks,
            1 => LocalProxyProtocol::AuthenticatedMixed,
            _ => return std::ptr::null_mut(),
        };
        if ca.is_null() && ca_len == 0 {
            // SAFETY: forwarded path requirements are identical.
            return unsafe { construct(path, path_len, timeout_ms, None, protocol) };
        }
        if ca.is_null() || ca_len == 0 || ca_len > BUFFER_CAPACITY {
            return std::ptr::null_mut();
        }
        // SAFETY: caller guarantees bounded readable input.
        let bytes = unsafe { std::slice::from_raw_parts(ca, ca_len) };
        let Ok(pem) = std::str::from_utf8(bytes) else {
            return std::ptr::null_mut();
        };
        if pem.contains('\0')
            || !pem.trim_start().starts_with("-----BEGIN CERTIFICATE-----")
            || !pem.trim_end().ends_with("-----END CERTIFICATE-----")
        {
            return std::ptr::null_mut();
        }
        let snapshot = pem.to_owned();
        // Configure trust before publishing any registry token.
        // SAFETY: forwarded path preconditions are identical.
        unsafe { construct(path, path_len, timeout_ms, Some(snapshot), protocol) }
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// Dispatch bounded JSON; outputs contain no local/API/TUIC/probe credentials.
///
/// # Safety
/// Request must be readable for `len` bytes, and output writable for at least
/// 65536 bytes, without overlap, throughout this call. Handles are opaque
/// non-dereferenceable tokens; malformed/stale tokens are safely rejected.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn os_runtime_call(
    handle: *mut c_void,
    request: *const u8,
    len: usize,
    out: *mut u8,
    capacity: usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // Preflight BEFORE parsing or looking up/mutating any runtime.
        if capacity < BUFFER_CAPACITY {
            return -2;
        }
        if request.is_null() || out.is_null() || len == 0 || len > BUFFER_CAPACITY {
            return -1;
        }
        let slot = match with_registry(|r| r.slots.get(&handle.addr()).cloned()) {
            Ok(Some(s)) => s,
            Ok(None) => return -3,
            Err(()) => return -4,
        };
        // SAFETY: caller guarantees the bounded readable request range.
        let bytes = unsafe { std::slice::from_raw_parts(request, len) };
        let response = with_slot(&slot, |runtime| {
            let value = runtime.dispatch(bytes)?;
            encode_reply(runtime, value)
        });
        match response {
            Ok(bytes) => {
                // SAFETY: caller guarantees a non-overlapping writable output.
                unsafe {
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
                }
                bytes.len() as i32
            }
            Err(code) => code,
        }
    }))
    .unwrap_or(-4)
}

pub(super) fn encode_reply(runtime: &mut Runtime, value: super::Reply) -> Result<Vec<u8>, Error> {
    let bytes = serde_json::to_vec(&value.value).map_err(|_| Error::FailedClosed)?;
    if bytes.len() > BUFFER_CAPACITY {
        return Err(Error::FailedClosed);
    }
    runtime.publish(value.publication)?;
    Ok(bytes)
}

/// Invalidate token and synchronously drop its supervisor. Safe for null,
/// unknown and repeated handles; waits for in-flight serialized operations.
#[unsafe(no_mangle)]
pub extern "C" fn os_runtime_free(handle: *mut c_void) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Ok(Some(slot)) = with_registry(|r| r.slots.get(&handle.addr()).cloned()) {
            // Keep the registry entry until shutdown completes: a second free
            // must wait on the same slot, not return while the child still runs.
            invalidate(&slot);
            let _ = with_registry(|r| r.slots.remove(&handle.addr()));
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    fn slot() -> Slot {
        Arc::new(Mutex::new(Some(
            Runtime::new(std::env::current_exe().unwrap(), Duration::from_millis(100)).unwrap(),
        )))
    }
    #[test]
    fn caught_panic_invalidates_runtime_and_cannot_resume_mutated_state() {
        let slot = slot();
        let result: Result<(), i32> =
            with_slot(&slot, |_| panic!("injected nonsecret runtime panic"));
        assert_eq!(result, Err(-4));
        assert!(slot.lock().unwrap().is_none());
        assert_eq!(with_slot(&slot, |_| Ok(())), Err(-3));
    }
    #[test]
    fn poisoned_runtime_lock_drops_supervisor_instead_of_recovering_state() {
        let slot = slot();
        let other = slot.clone();
        assert!(
            std::thread::spawn(move || {
                let _guard = other.lock().unwrap();
                panic!("injected nonsecret lock poison");
            })
            .join()
            .is_err()
        );
        assert_eq!(with_slot(&slot, |_| Ok(())), Err(-4));
        match slot.lock() {
            Err(poison) => assert!(poison.into_inner().is_none()),
            Ok(_) => panic!("poison unexpectedly cleared"),
        };
    }
    #[test]
    fn repeated_concurrent_free_waits_for_inflight_runtime_operation() {
        let path = std::env::current_exe().unwrap();
        let path = path.to_str().unwrap();
        let h = unsafe { os_runtime_new(path.as_ptr(), path.len(), 100) };
        assert!(!h.is_null());
        let id = h.addr();
        let slot = with_registry(|r| r.slots.get(&id).cloned())
            .unwrap()
            .unwrap();
        let held = slot.lock().unwrap();
        let first =
            std::thread::spawn(move || os_runtime_free(std::ptr::without_provenance_mut(id)));
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let pending =
                with_registry(|r| !r.slots.contains_key(&id) || Arc::strong_count(&slot) >= 3)
                    .unwrap();
            if pending {
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let second = std::thread::spawn(move || {
            os_runtime_free(std::ptr::without_provenance_mut(id));
            tx.send(()).unwrap();
        });
        let premature = rx.recv_timeout(Duration::from_millis(50)).is_ok();
        drop(held);
        first.join().unwrap();
        second.join().unwrap();
        assert!(
            !premature,
            "second free returned before inflight runtime operation released"
        );
    }
}
