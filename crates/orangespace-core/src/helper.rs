//! Portable, polling supervision of foreground per-sandbox sing-box helpers.
//!
//! This module owns real child processes, not network readiness. A service must
//! periodically call `reap_exits`, invalidate the exact returned Binding in its
//! router, and fail closed on lifecycle errors. It must authenticate/authorize
//! bindings and obtain settings from protected configuration before `start`.
//! Use one supervisor for a service's sandbox namespace; generation/tunnel-ID
//! tombstones last for this instance only. Persistent generations belong to the
//! service/router, not this process manager.
//!
//! Children receive only fixed public arguments and piped JSON stdin; both
//! output streams are discarded. No credentials are written to files or env.
//! The executable must remain in the foreground, must not delegate stdin or
//! daemonize, and must not process network configuration until stdin is delivered.
//! Windows assigns each helper to a fresh unnamed, non-inheritable kill-on-close
//! Job with an active-process limit of one before delivering stdin. Only this
//! trusted foreground helper's ordinary child creation is denied, not browser
//! multiprocess operation or arbitrary brokered/delegated process creation.
//! This narrowly relies on the protected installed sing-box stdin contract:
//! spawn and Job assignment are NOT an atomic suspended or restricted-identity
//! launch. A crash in that pre-assignment window is not covered. Linux supervises
//! only the immediate Child. Neither route implements restricted browser
//! identity, WFP, DNS containment or a browser permit.
//! Windows retains the actual root identity and permits only one successful
//! assignment per Job, even after root exit. Stop/poll waits for that process
//! object's signal, without PID snapshots or finite history-counter inference.
//! This is a trusted-helper policy, not an untrusted-code security boundary.
//! The existing browser gate is deliberately independent.
//! Timeouts bound pipe-delivery/stop waiting, not OS spawn latency or scheduling.
//! Drop kills all children, polls within one shared timeout, then transfers any
//! uninterruptible children to background waiters for eventual reaping.

use crate::{
    Binding, SandboxId, TunnelId, UserId,
    tunnel::{TunnelSettings, sing_box_config},
};
use std::{
    collections::{HashMap, HashSet},
    ffi::OsString,
    io::{self, Write},
    path::PathBuf,
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

/// Explicit deployment trust precondition, NOT a hash/signature/ACL verifier.
///
/// Before calling the constructor the privileged installer/service must verify
/// the approved executable (e.g. pinned release hash/signature) and prevent
/// untrusted writes/replacements of it, its parent directories, DLLs/libraries,
/// and trust anchors for the entire supervisor lifetime. A user-selected path
/// is not authorization. Portable std cannot establish these guarantees.
/// The constructor only checks/canonicalizes an absolute regular-file path;
/// it does not close a replacement race without that deployment precondition.
pub struct TrustedExecutable {
    path: PathBuf,
    arguments: Vec<OsString>,
}
impl TrustedExecutable {
    /// Acknowledge the deployment guarantees on `TrustedExecutable`; this is
    /// intentionally not an untrusted request/configuration deserialization API.
    pub fn acknowledge_protected_installation(path: PathBuf) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "helper path must be absolute",
            ));
        }
        let path = path.canonicalize()?;
        if !path.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "helper must be a regular file",
            ));
        }
        Ok(Self {
            path,
            arguments: vec!["run".into(), "--config".into(), "stdin".into()],
        })
    }
}
#[derive(Debug)]
pub struct HelperExit {
    pub binding: Binding,
    pub pid: u32,
    pub status: ExitStatus,
}
struct OwnedHelper {
    child: Child,
    #[cfg(windows)]
    job: helper_job_win::Job,
}
impl std::ops::Deref for OwnedHelper {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.child
    }
}
impl std::ops::DerefMut for OwnedHelper {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}
impl OwnedHelper {
    fn kill(&mut self) -> io::Result<()> {
        #[cfg(windows)]
        let job_result = self.job.terminate();
        let child_result = self.child.kill();
        #[cfg(windows)]
        return job_result.and(child_result);
        #[cfg(not(windows))]
        child_result
    }
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = self.child.try_wait()?;
        #[cfg(windows)]
        if status.is_some() {
            // Child's exit status and the separately retained actual root
            // handle must both report exit before removing this binding.
            self.job.terminate()?;
            if !self.job.root_exited()? {
                return Ok(None);
            }
        }
        Ok(status)
    }
}

/// Exclusive lifecycle owner. Active sandbox identities cannot be overwritten;
/// close/reap is required before a strictly newer generation with a fresh tunnel
/// ID can start. Sandbox ownership is retained after close for this lifetime.
pub struct HelperSupervisor {
    executable: TrustedExecutable,
    timeout: Duration,
    active: HashMap<Binding, OwnedHelper>,
    history: HashMap<SandboxId, (UserId, u64)>,
    tunnels: HashSet<TunnelId>,
}
impl HelperSupervisor {
    /// `timeout` must be within (0, 300 seconds]; it applies independently to
    /// stdin delivery and forced stop. A failed start may spend both budgets.
    pub fn new(executable: TrustedExecutable, timeout: Duration) -> io::Result<Self> {
        if timeout.is_zero() || timeout > Duration::from_secs(300) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "helper timeout must be within (0, 300s]",
            ));
        }
        Ok(Self {
            executable,
            timeout,
            active: HashMap::new(),
            history: HashMap::new(),
            tunnels: HashSet::new(),
        })
    }
    /// Spawn a distinct process and deliver a validated, node-matched config.
    /// Success means only stdin delivery, NOT TUIC connectivity or readiness.
    /// Once spawning is attempted the generation and tunnel ID are consumed,
    /// even if spawning/delivery fails. No restart or fallback is automatic.
    pub fn start(&mut self, binding: Binding, settings: &TunnelSettings) -> io::Result<u32> {
        if binding.generation == 0
            || self
                .active
                .keys()
                .any(|b| b.sandbox_id == binding.sandbox_id)
            || self
                .history
                .get(&binding.sandbox_id)
                .is_some_and(|(user, generation)| {
                    *user != binding.user_id || binding.generation <= *generation
                })
            || self.tunnels.contains(&binding.tunnel_id)
        {
            return Err(io::Error::other("unsafe helper binding reuse"));
        }
        let config = sing_box_config(binding, settings)
            .map_err(|_| io::Error::other("invalid helper configuration"))?;
        let bytes = serde_json::to_vec(&config)
            .map_err(|_| io::Error::other("cannot encode helper configuration"))?;
        if bytes.len() > 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "helper configuration exceeds 1 MiB",
            ));
        }
        // Reserve before spawning: even failed attempts cannot revive a binding.
        self.history
            .insert(binding.sandbox_id, (binding.user_id, binding.generation));
        self.tunnels.insert(binding.tunnel_id);
        let mut command = Command::new(&self.executable.path);
        command
            .args(&self.executable.arguments)
            .current_dir(self.executable.path.parent().unwrap())
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // Winsock provider initialization requires SystemRoot. Do not copy a
        // potentially attacker-controlled inherited value; query Windows.
        #[cfg(windows)]
        command.env("SystemRoot", windows_system_root()?);
        #[cfg(windows)]
        let mut job = helper_job_win::Job::new()?;
        let child = command.spawn()?;
        #[cfg(windows)]
        let assignment = job.assign(&child);
        let mut child = OwnedHelper {
            child,
            #[cfg(windows)]
            job,
        };
        #[cfg(windows)]
        if let Err(error) = assignment {
            // Own the failed child before cleanup; no config writer or secret
            // delivery exists yet. Keep ownership on a stop timeout/error.
            self.active.insert(binding, child);
            let _ = self.close(binding);
            return Err(io::Error::new(error.kind(), "helper job assignment failed"));
        }
        let mut stdin = child.stdin.take().unwrap();
        let pid = child.id();
        self.active.insert(binding, child);
        // A pipe write can block forever if the helper stops reading. Keep the
        // child supervised before starting delivery and bound the caller wait.
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let writer = thread::Builder::new()
            .name("helper-config".into())
            .spawn(move || {
                let result = stdin.write_all(&bytes);
                drop(stdin); // EOF, never a credential-bearing temporary file.
                let _ = tx.send(result);
            });
        let delivery = match writer {
            Ok(_) => match rx.recv_timeout(self.timeout) {
                Ok(result) => result,
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "helper stdin delivery timed out",
                )),
            },
            Err(error) => Err(error),
        };
        if let Err(error) = delivery {
            // On an OS-level stop timeout retain the child in active; never
            // allow another generation to overlap it. Drop retries cleanup.
            let _ = self.close(binding);
            return Err(io::Error::new(error.kind(), "helper stdin delivery failed"));
        }
        Ok(pid)
    }
    /// Query/reap only the exact owned binding; stale or forged contexts fail
    /// without touching a newer helper. None means not observed exited, not ready.
    pub fn poll(&mut self, binding: Binding) -> io::Result<Option<HelperExit>> {
        let child = self
            .active
            .get_mut(&binding)
            .ok_or_else(|| io::Error::other("unknown helper binding"))?;
        let pid = child.id();
        if let Some(status) = child.try_wait()? {
            self.active.remove(&binding);
            Ok(Some(HelperExit {
                binding,
                pid,
                status,
            }))
        } else {
            Ok(None)
        }
    }
    /// Poll from the service event loop. No exit event is accepted from an
    /// untrusted caller: binding, PID and status come from the owned Child.
    pub fn reap_exits(&mut self) -> io::Result<Vec<HelperExit>> {
        let mut exits = Vec::new();
        for (&binding, child) in &mut self.active {
            if let Some(status) = child.try_wait()? {
                exits.push(HelperExit {
                    binding,
                    pid: child.id(),
                    status,
                });
            }
        }
        // Commit removals only after all polls succeed, avoiding lost events
        // if a later OS wait fails. Child caches already-reaped exit statuses.
        for exit in &exits {
            self.active.remove(&exit.binding);
        }
        Ok(exits)
    }
    /// Force-stop and reap the exact child, without a helper-specific graceful
    /// shutdown protocol. Timeout/error retains ownership, preventing overlap;
    /// the caller must fail closed and retry close/reap (Drop also retries).
    pub fn close(&mut self, binding: Binding) -> io::Result<HelperExit> {
        let child = self
            .active
            .get_mut(&binding)
            .ok_or_else(|| io::Error::other("unknown helper binding"))?;
        child.kill()?;
        let start = Instant::now();
        loop {
            if let Some(exit) = self.poll(binding)? {
                return Ok(exit);
            }
            if start.elapsed() >= self.timeout {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "helper did not exit",
                ));
            }
            thread::sleep(Duration::from_millis(2));
        }
    }
}

#[cfg(windows)]
fn windows_system_root() -> io::Result<OsString> {
    use std::os::windows::ffi::OsStringExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetWindowsDirectoryW(buffer: *mut u16, size: u32) -> u32;
    }
    let mut buffer = vec![0u16; 32768];
    // SAFETY: buffer is writable for the supplied number of UTF-16 units.
    let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    if length >= buffer.len() {
        return Err(io::Error::other(
            "Windows directory exceeds supported length",
        ));
    }
    Ok(OsString::from_wide(&buffer[..length]))
}

impl Drop for HelperSupervisor {
    fn drop(&mut self) {
        // Kill all first; one wedged process must not delay stopping siblings.
        for child in self.active.values_mut() {
            let _ = child.kill();
        }
        let start = Instant::now();
        while !self.active.is_empty() && start.elapsed() < self.timeout {
            self.active
                .retain(|_, child| !matches!(child.try_wait(), Ok(Some(_))));
            if !self.active.is_empty() {
                thread::sleep(Duration::from_millis(2));
            }
        }
        // Do not block Drop indefinitely on an uninterruptible OS process.
        // Retain ownership in a waiter so eventual exits are still reaped.
        for (_, mut child) in self.active.drain() {
            thread::spawn(move || {
                let _ = child.kill();
                let _ = child.wait();
            });
        }
    }
}

#[cfg(windows)]
#[path = "helper_job_win.rs"]
mod helper_job_win;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NodeId, SandboxId, TunnelId, UserId};
    use std::io::Read;

    pub(super) fn binding() -> Binding {
        Binding {
            user_id: UserId::new(),
            sandbox_id: SandboxId::new(),
            node_id: NodeId::new(),
            generation: 1,
            tunnel_id: TunnelId::new(),
        }
    }

    pub(super) fn settings(b: Binding, mode: &str) -> TunnelSettings {
        serde_json::from_value(serde_json::json!({
            "node_id": b.node_id, "endpoint_ip": "127.0.0.1", "endpoint_port": 443,
            "tls_server_name": "helper.example.test", "tuic_uuid": uuid::Uuid::new_v4(),
            "tuic_password": "test-secret-not-in-argv", "socks_port": 19080,
            "socks_username": mode, "socks_password": "other-secret-not-in-env"
        }))
        .unwrap()
    }

    fn supervisor() -> HelperSupervisor {
        let mut executable =
            TrustedExecutable::acknowledge_protected_installation(std::env::current_exe().unwrap())
                .unwrap();
        executable.arguments = vec![
            "--exact".into(),
            "helper::tests::controlled_helper_child".into(),
            "--nocapture".into(),
        ];
        HelperSupervisor::new(executable, Duration::from_secs(2)).unwrap()
    }

    fn running(supervisor: &mut HelperSupervisor, b: Binding) -> (u32, std::net::TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut settings = settings(b, "stay");
        settings.socks_port = listener.local_addr().unwrap().port();
        let pid = supervisor.start(b, &settings).unwrap();
        let start = Instant::now();
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    assert!(
                        start.elapsed() < Duration::from_secs(5),
                        "child never initialized"
                    );
                    assert!(
                        supervisor.poll(b).unwrap().is_none(),
                        "child failed its secret/config checks"
                    );
                    thread::sleep(Duration::from_millis(2));
                }
                Err(e) => panic!("accept: {e}"),
            }
        };
        // Windows can inherit the listener's nonblocking mode on accept;
        // set_read_timeout alone does not restore blocking reads.
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut ack = [0];
        stream.read_exact(&mut ack).unwrap();
        assert_eq!(ack, [1]);
        (pid, stream)
    }

    // Re-executes this test binary, no shell or platform-specific commands.
    #[test]
    fn controlled_helper_child() {
        if !std::env::args().any(|a| a == "--exact") {
            return;
        }
        let mut bytes = Vec::new();
        std::io::stdin().read_to_end(&mut bytes).unwrap();
        let config: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(!std::env::args().any(|a| a.contains("secret")));
        assert!(std::env::var_os("ORANGESPACE_TEST_SECRET").is_none());
        #[cfg(windows)]
        assert_eq!(
            std::env::var_os("SystemRoot"),
            Some(windows_system_root().unwrap())
        );
        assert_eq!(
            config["outbounds"][0]["password"],
            "test-secret-not-in-argv"
        );
        println!("{}", config); // Must be discarded by the supervisor.
        eprintln!("{}", config);
        if config["inbounds"][0]["users"][0]["username"] == "exit" {
            std::process::exit(23);
        }
        let port = config["inbounds"][0]["listen_port"].as_u64().unwrap() as u16;
        let mut stream =
            std::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).unwrap();
        stream.write_all(&[1]).unwrap();
        let mut discard = Vec::new();
        let _ = stream.read_to_end(&mut discard);
    }

    fn assert_stream_terminated(stream: &mut std::net::TcpStream) {
        // TerminateProcess can produce WSAECONNRESET, whereas Unix usually
        // produces EOF. A read timeout is never accepted as termination.
        match stream.read(&mut [0]) {
            Ok(0) => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
            result => panic!("child connection still open: {result:?}"),
        }
    }

    fn assert_reaped(pid: u32) {
        // Socket EOF/reset is evidence of termination; Linux additionally
        // verifies there is no zombie. Windows has no /proc equivalent in std.
        #[cfg(target_os = "linux")]
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "helper is still alive or zombie"
        );
        #[cfg(not(target_os = "linux"))]
        let _ = pid;
    }

    #[test]
    fn real_failure_is_reaped_and_stale_exit_cannot_remove_replacement() {
        let mut supervisor = supervisor();
        let old = binding();
        let sibling = Binding {
            user_id: old.user_id,
            node_id: NodeId::new(),
            ..binding()
        };
        let (_sibling_pid, _sibling_stream) = running(&mut supervisor, sibling);
        let pid = supervisor.start(old, &settings(old, "exit")).unwrap();
        let start = Instant::now();
        let event = loop {
            let mut exits = supervisor.reap_exits().unwrap();
            if let Some(exit) = exits.pop() {
                assert!(exits.is_empty());
                break exit;
            }
            assert!(start.elapsed() < Duration::from_secs(5));
            thread::sleep(Duration::from_millis(2));
        };
        assert_eq!(event.binding, old);
        assert_eq!(event.pid, pid);
        assert_eq!(event.status.code(), Some(23), "fixture must really execute");
        assert_reaped(pid);
        assert!(supervisor.poll(sibling).unwrap().is_none());
        let next = Binding {
            generation: 2,
            node_id: NodeId::new(),
            tunnel_id: TunnelId::new(),
            ..old
        };
        let (next_pid, _next_stream) = running(&mut supervisor, next);
        for stale in [
            event.binding,
            Binding {
                user_id: UserId::new(),
                ..next
            },
            Binding {
                node_id: old.node_id,
                ..next
            },
            Binding {
                generation: 1,
                ..next
            },
            Binding {
                tunnel_id: old.tunnel_id,
                ..next
            },
        ] {
            assert!(supervisor.poll(stale).is_err());
            assert!(supervisor.close(stale).is_err());
        }
        assert!(supervisor.reap_exits().unwrap().is_empty());
        assert!(supervisor.poll(next).unwrap().is_none());
        assert_eq!(supervisor.close(next).unwrap().pid, next_pid);
        supervisor.close(sibling).unwrap();
    }

    #[test]
    fn environment_scrub_probe() {
        if std::env::var_os("ORANGESPACE_TEST_SECRET").is_none() {
            return;
        }
        let mut supervisor = supervisor();
        let b = binding();
        let (_, _stream) = running(&mut supervisor, b);
        supervisor.close(b).unwrap();
    }

    #[test]
    fn child_credentials_never_escape_via_environment_or_output() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "helper::tests::environment_scrub_probe",
                "--nocapture",
            ])
            .env("ORANGESPACE_TEST_SECRET", "inherited-secret-forbidden")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "nested fixture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        for bytes in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(bytes);
            assert!(!text.contains("test-secret-not-in-argv"));
            assert!(!text.contains("other-secret-not-in-env"));
            assert!(!text.contains("inherited-secret-forbidden"));
        }
    }

    #[test]
    fn spawn_failure_consumes_binding_and_bad_node_settings_never_spawn() {
        let mut supervisor = supervisor();
        let b = binding();
        let mut wrong_node = settings(b, "stay");
        wrong_node.node_id = NodeId::new();
        assert!(supervisor.start(b, &wrong_node).is_err());
        assert!(supervisor.active.is_empty());
        assert!(supervisor.history.is_empty());
        supervisor.executable.path = std::env::current_exe()
            .unwrap()
            .with_file_name("missing-controlled-helper");
        assert!(supervisor.start(b, &settings(b, "stay")).is_err());
        assert!(supervisor.active.is_empty());
        assert!(supervisor.start(b, &settings(b, "stay")).is_err());
        assert_eq!(
            supervisor.history.get(&b.sandbox_id),
            Some(&(b.user_id, b.generation))
        );
    }

    #[test]
    fn close_reaps_a_child_that_exited_before_stop() {
        let mut supervisor = supervisor();
        let b = binding();
        let pid = supervisor.start(b, &settings(b, "exit")).unwrap();
        thread::sleep(Duration::from_millis(150));
        let exit = supervisor.close(b).unwrap();
        assert_eq!(exit.status.code(), Some(23));
        assert_reaped(pid);
    }

    #[test]
    fn oversized_config_is_rejected_before_spawning() {
        let mut supervisor = supervisor();
        let b = binding();
        let huge = settings(b, &"x".repeat(2 * 1024 * 1024));
        let result = supervisor.start(b, &huge);
        if result.is_ok() {
            supervisor.close(b).unwrap();
        }
        assert!(result.is_err(), "secret-bearing config must be bounded");
        assert!(supervisor.active.is_empty());
        assert!(
            !supervisor.history.contains_key(&b.sandbox_id),
            "validation occurs before reserving/spawning"
        );
    }

    #[test]
    fn controlled_helper_never_reads_stdin() {
        if !std::env::args().any(|a| a == "--exact") {
            return;
        }
        thread::sleep(Duration::from_millis(700));
    }

    #[test]
    fn stdin_delivery_timeout_is_bounded_and_child_is_cleaned() {
        let mut supervisor = supervisor();
        supervisor.timeout = Duration::from_millis(50);
        supervisor.executable.arguments[1] =
            "helper::tests::controlled_helper_never_reads_stdin".into();
        let b = binding();
        let mut settings = settings(b, &"x".repeat(512 * 1024));
        settings.socks_port = 19081;
        let start = Instant::now();
        let result = supervisor.start(b, &settings);
        assert!(result.is_err());
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "blocked stdin must not hang the caller"
        );
        assert!(
            supervisor.active.is_empty(),
            "failed delivery must kill and reap the spawned child"
        );
        assert!(
            supervisor.start(b, &settings).is_err(),
            "failed generation is consumed"
        );
    }

    #[test]
    fn dropping_supervisor_terminates_and_reaps_live_children() {
        let mut supervisor = supervisor();
        let (pid, mut stream) = running(&mut supervisor, binding());
        let start = Instant::now();
        drop(supervisor);
        assert!(start.elapsed() < Duration::from_secs(3));
        assert_stream_terminated(&mut stream);
        assert_reaped(pid);
    }

    #[test]
    fn executable_requires_absolute_regular_installed_path_and_finite_timeout() {
        assert!(
            TrustedExecutable::acknowledge_protected_installation(PathBuf::from(
                "untrusted-helper"
            ))
            .is_err()
        );
        assert!(
            TrustedExecutable::acknowledge_protected_installation(std::env::current_dir().unwrap())
                .is_err()
        );
        assert!(
            TrustedExecutable::acknowledge_protected_installation(
                std::env::current_dir().unwrap().join("no-such-helper")
            )
            .is_err()
        );
        let executable =
            TrustedExecutable::acknowledge_protected_installation(std::env::current_exe().unwrap())
                .unwrap();
        assert!(HelperSupervisor::new(executable, Duration::ZERO).is_err());
        let executable =
            TrustedExecutable::acknowledge_protected_installation(std::env::current_exe().unwrap())
                .unwrap();
        assert!(HelperSupervisor::new(executable, Duration::from_secs(301)).is_err());
    }

    #[test]
    fn rejects_active_sandbox_reuse_and_consumed_generations() {
        let mut supervisor = supervisor();
        let a = binding();
        supervisor.start(a, &settings(a, "stay")).unwrap();
        let occupied = Binding {
            generation: 2,
            tunnel_id: TunnelId::new(),
            ..a
        };
        let duplicate = supervisor.start(occupied, &settings(occupied, "stay"));
        // Clean every spawned process even on the RED path.
        for (_, mut child) in supervisor.active.drain() {
            let _ = child.kill();
            let _ = child.wait();
        }
        assert!(duplicate.is_err(), "active helper must not be overwritten");

        let next = Binding {
            generation: 2,
            tunnel_id: TunnelId::new(),
            ..a
        };
        supervisor.start(next, &settings(next, "stay")).unwrap();
        for forged in [
            Binding {
                node_id: NodeId::new(),
                ..next
            },
            Binding {
                user_id: UserId::new(),
                ..next
            },
            Binding {
                generation: 3,
                tunnel_id: TunnelId::new(),
                ..next
            },
        ] {
            let result = supervisor.start(forged, &settings(forged, "stay"));
            if result.is_ok() {
                supervisor.close(forged).unwrap();
            }
            assert!(
                result.is_err(),
                "one process per sandbox, including across users"
            );
        }
        supervisor.close(next).unwrap();
        for reused in [
            a,
            next,
            Binding {
                generation: 3,
                ..next
            },
            Binding {
                user_id: UserId::new(),
                generation: 3,
                tunnel_id: TunnelId::new(),
                ..next
            },
        ] {
            let result = supervisor.start(reused, &settings(reused, "stay"));
            if result.is_ok() {
                supervisor.close(reused).unwrap();
            }
            assert!(
                result.is_err(),
                "closed generations, tunnel IDs and sandbox owners cannot be reused"
            );
        }
    }

    #[test]
    fn independent_real_helpers_close_and_reap() {
        let mut supervisor = supervisor();
        let a = binding();
        let b = Binding {
            user_id: a.user_id,
            node_id: a.node_id,
            ..binding()
        };
        let (a_pid, mut a_stream) = running(&mut supervisor, a);
        let (b_pid, _b_stream) = running(&mut supervisor, b);
        assert_ne!(a_pid, b_pid);
        assert!(supervisor.poll(a).unwrap().is_none());
        assert!(supervisor.poll(b).unwrap().is_none());
        let exit = supervisor.close(a).unwrap();
        assert_eq!(exit.binding, a);
        assert_eq!(exit.pid, a_pid);
        assert_stream_terminated(&mut a_stream);
        assert_reaped(a_pid);
        assert!(supervisor.poll(b).unwrap().is_none());
        supervisor.close(b).unwrap();
        assert!(supervisor.active.is_empty());
    }
}
