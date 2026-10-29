//! Opt-in real-runtime integration. It validates supervisor -> sing-box stdin
//! configuration and independent authenticated SOCKS listeners, NOT TUIC egress,
//! general process-tree containment, Windows WFP, DNS, or a browser launch permit.
//! The Windows crash fixture observes the real helper's stable process handle.
use orangespace_core::helper::{HelperSupervisor, TrustedExecutable};
use orangespace_core::tunnel::TunnelSettings;
use orangespace_core::{Binding, NodeId, SandboxId, TunnelId, UserId};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::Command,
    time::{Duration, Instant},
};

fn port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn settings(node: NodeId, port: u16, password: &str) -> TunnelSettings {
    serde_json::from_value(serde_json::json!({
        "node_id": node, "endpoint_ip": "127.0.0.1", "endpoint_port": 443,
        "tls_server_name": "unused-loopback.example.test",
        "tuic_uuid": uuid::Uuid::new_v4(), "tuic_password": "fixture-only-tuic-secret",
        "socks_port": port, "socks_username": "fixture", "socks_password": password
    }))
    .unwrap()
}
fn binding() -> Binding {
    Binding {
        user_id: UserId::new(),
        sandbox_id: SandboxId::new(),
        node_id: NodeId::new(),
        generation: 1,
        tunnel_id: TunnelId::new(),
    }
}
fn wait_listener(supervisor: &mut HelperSupervisor, binding: Binding, port: u16) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            supervisor.poll(binding).unwrap().is_none(),
            "real helper exited before listening"
        );
        if TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(100),
        )
        .is_ok()
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "real helper did not create SOCKS listener"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn authenticate(port: u16, password: &str) -> bool {
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_secs(2),
    )
    .unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream.write_all(&[5, 1, 2]).unwrap();
    let mut reply = [0; 2];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(reply, [5, 2], "SOCKS must require username/password");
    let user = b"fixture";
    let mut request = vec![1, user.len() as u8];
    request.extend(user);
    request.push(password.len() as u8);
    request.extend(password.as_bytes());
    stream.write_all(&request).unwrap();
    stream.read_exact(&mut reply).unwrap();
    reply == [1, 0]
}
fn listener_closed(port: u16) -> bool {
    TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_millis(200),
    )
    .is_err()
}

// Fixture-only probe: the caller supplies an archive-verified runtime. Poll
// before reading stdout so a hung/noisy version process cannot block the test.
fn bounded_version_output(
    child: &mut std::process::Child,
    timeout: Duration,
) -> std::io::Result<std::process::Output> {
    let started = Instant::now();
    let result = (|| loop {
        if started.elapsed() >= timeout {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "runtime version probe timed out",
            ));
        }
        if let Some(status) = child.try_wait()? {
            let mut stdout = Vec::new();
            if let Some(pipe) = child.stdout.take() {
                pipe.take(4097).read_to_end(&mut stdout)?;
            }
            if stdout.len() > 4096 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "runtime version output exceeded fixture limit",
                ));
            }
            return Ok(std::process::Output {
                status,
                stdout,
                stderr: Vec::new(),
            });
        }
        std::thread::sleep(Duration::from_millis(10));
    })();
    if result.is_err() {
        // kill may race with a natural exit; wait still reaps that exact child.
        let _ = child.kill();
        child.wait()?;
        drop(child.stdout.take());
    }
    result
}

#[test]
fn version_probe_timeout_kills_and_reaps_child() {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "version_probe_child", "--ignored", "--nocapture"])
        .env("ORANGESPACE_VERSION_PROBE_CHILD", "sleep")
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    let error = bounded_version_output(&mut child, Duration::ZERO).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(child.try_wait().unwrap().is_some(), "child was not reaped");
}

#[test]
fn version_probe_collects_successful_output() {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "version_probe_child", "--ignored", "--nocapture"])
        .env("ORANGESPACE_VERSION_PROBE_CHILD", "version")
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let output = bounded_version_output(&mut child, Duration::from_secs(5)).unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("sing-box version 1.14.4")
    );
    assert!(child.try_wait().unwrap().is_some());
}

#[test]
#[ignore = "subprocess fixture only"]
fn version_probe_child() {
    let Ok(mode) = std::env::var("ORANGESPACE_VERSION_PROBE_CHILD") else {
        return; // A broad --ignored run is not a subprocess invocation.
    };
    match mode.as_str() {
        "sleep" => std::thread::sleep(Duration::from_secs(60)),
        "version" => println!("sing-box version 1.14.4"),
        _ => panic!("invalid subprocess fixture mode"),
    }
}

fn verified_real_runtime() -> Option<std::path::PathBuf> {
    // Broad --ignored runs without the explicit opt-in must not spawn anything.
    let binary = std::env::var_os("ORANGESPACE_TEST_SING_BOX")?;
    let binary = std::path::PathBuf::from(binary).canonicalize().unwrap();
    let mut version_child = Command::new(&binary)
        .arg("version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let version = bounded_version_output(&mut version_child, Duration::from_secs(5)).unwrap();
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8(version.stdout).unwrap().lines().next(),
        Some("sing-box version 1.14.4")
    );
    Some(binary)
}

#[test]
#[ignore = "requires ORANGESPACE_TEST_SING_BOX pointing to verified official sing-box 1.14.4"]
fn real_sing_box_stdin_authentication_and_independent_lifecycle() {
    let Some(binary) = verified_real_runtime() else {
        return;
    };
    // The invoking test runner checks the official archive SHA-256 first. This
    // acknowledgement is a test-fixture trust precondition, not a production
    // hash/signature verifier and cannot produce any browser authorization.
    let executable = TrustedExecutable::acknowledge_protected_installation(binary).unwrap();
    let mut supervisor = HelperSupervisor::new(executable, Duration::from_secs(2)).unwrap();
    let a = binding();
    let b = Binding {
        user_id: a.user_id,
        ..binding()
    };
    let pa = port();
    let mut pb = port();
    while pb == pa {
        pb = port();
    }
    let sa = settings(a.node_id, pa, "fixture-A-password");
    let sb = settings(b.node_id, pb, "fixture-B-password");
    let pid_a = supervisor.start(a, &sa).unwrap();
    let pid_b = supervisor.start(b, &sb).unwrap();
    assert_ne!(pid_a, pid_b);
    wait_listener(&mut supervisor, a, pa);
    wait_listener(&mut supervisor, b, pb);
    assert!(authenticate(pa, "fixture-A-password"));
    assert!(authenticate(pb, "fixture-B-password"));
    assert!(
        !authenticate(pb, "fixture-A-password"),
        "another sandbox's credentials must fail"
    );
    assert_eq!(supervisor.close(a).unwrap().pid, pid_a);
    assert!(listener_closed(pa), "closed helper retained its listener");
    assert!(supervisor.poll(b).unwrap().is_none());
    assert!(
        authenticate(pb, "fixture-B-password"),
        "closing A disrupted B"
    );
    drop(supervisor);
    assert!(
        listener_closed(pb),
        "drop did not close real helper listener"
    );
}

#[cfg(windows)]
mod windows_crash {
    use super::*;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::{
        Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::{
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
            },
            Threading::{
                OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
                WaitForSingleObject,
            },
        },
    };

    // Fixture safety net, NOT the production Job under test. No active-process
    // limit or breakaway: the supervisor and descendants inherit this outer Job.
    // Keep its sole non-inheritable handle until AFTER success signal assertions;
    // earlier cleanup would counterfeit production crash-cleanup evidence.
    struct FixtureJob(OwnedHandle);
    impl FixtureJob {
        fn new() -> Self {
            // SAFETY: null attributes/name make an unnamed, non-inheritable Job.
            let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            assert!(
                !raw.is_null(),
                "CreateJobObjectW: {}",
                std::io::Error::last_os_error()
            );
            // SAFETY: newly owned valid handle, closed exactly once.
            let job = Self(unsafe { OwnedHandle::from_raw_handle(raw) });
            // SAFETY: this information structure permits all-zero initialization.
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            // SAFETY: buffer and size match the selected information class.
            assert_ne!(
                unsafe {
                    SetInformationJobObject(
                        job.0.as_raw_handle(),
                        JobObjectExtendedLimitInformation,
                        (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                        std::mem::size_of_val(&limits) as u32,
                    )
                },
                0,
                "SetInformationJobObject: {}",
                std::io::Error::last_os_error()
            );
            job
        }

        fn assign(&self, child: &std::process::Child) {
            // SAFETY: exact retained objects; child is blocked on private stdin
            // activation and cannot yet launch even the Go version probe.
            assert_ne!(
                unsafe { AssignProcessToJobObject(self.0.as_raw_handle(), child.as_raw_handle()) },
                0,
                "fixture Job assignment: {}",
                std::io::Error::last_os_error()
            );
        }

        fn terminate(&self) {
            // SAFETY: only our parent-owned Job, never a PID supplied over TCP.
            // Success reaches this only AFTER observing the real Go signal.
            if unsafe { TerminateJobObject(self.0.as_raw_handle(), 99) } == 0 {
                eprintln!(
                    "fixture TerminateJobObject failed: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
    }

    struct SupervisorChild {
        child: std::process::Child,
        outer: FixtureJob,
    }
    impl Drop for SupervisorChild {
        fn drop(&mut self) {
            self.outer.terminate();
            // Bounds cover polling, NOT native-call latency or scheduling.
            // No unbounded Child::wait. Field destruction closes the final
            // kill-on-close outer Job handle even after errors/deadline expiry.
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => {}
                Err(error) => eprintln!("fixture supervisor initial try_wait: {error}"),
            }
            if let Err(error) = self.child.kill() {
                eprintln!("fixture supervisor kill failed: {error}");
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match self.child.try_wait() {
                    Ok(Some(_)) => return,
                    Ok(None) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Ok(None) => {
                        eprintln!("fixture supervisor cleanup polling deadline exceeded");
                        return;
                    }
                    Err(error) => {
                        eprintln!("fixture supervisor cleanup try_wait failed: {error}");
                        return;
                    }
                }
            }
        }
    }

    fn spawn_supervisor(
        listener: &TcpListener,
        mode: &str,
        binary: Option<&std::path::Path>,
    ) -> (SupervisorChild, [u8; 16]) {
        let outer = FixtureJob::new();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "windows_crash::real_sing_box_supervisor_child",
                "--ignored",
                "--nocapture",
            ])
            .env("ORANGESPACE_REAL_SUPERVISOR_CHILD", mode)
            .env(
                "ORANGESPACE_REAL_SUPERVISOR_CONTROL",
                listener.local_addr().unwrap().to_string(),
            )
            .stdin(std::process::Stdio::piped());
        if let Some(binary) = binary {
            command.env("ORANGESPACE_TEST_SING_BOX", binary);
        }
        let mut supervisor = SupervisorChild {
            child: command.spawn().unwrap(),
            outer,
        };
        supervisor.outer.assign(&supervisor.child);
        let nonce = *uuid::Uuid::new_v4().as_bytes();
        // Capability ONLY through this child's inherited private stdin: never
        // argv, environment, disk or logs. Assignment precedes activation.
        supervisor
            .child
            .stdin
            .take()
            .unwrap()
            .write_all(&nonce)
            .unwrap();
        (supervisor, nonce)
    }

    fn authenticated_control(
        listener: &TcpListener,
        supervisor: &mut SupervisorChild,
        nonce: &[u8; 16],
    ) -> TcpStream {
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut control = loop {
            assert!(
                supervisor.child.try_wait().unwrap().is_none(),
                "supervisor exited before readiness"
            );
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("fixture control accept: {error}"),
            }
            assert!(Instant::now() < deadline, "supervisor readiness timed out");
            std::thread::sleep(Duration::from_millis(20));
        };
        // Windows accepts inherit the listener's nonblocking mode. Restore
        // blocking I/O before applying timeouts and reading the readiness frame.
        control.set_nonblocking(false).unwrap();
        control
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        control
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut echoed_nonce = [0; 16];
        control.read_exact(&mut echoed_nonce).unwrap();
        // Fail closed BEFORE parsing metadata. Not assert_eq!: never print the
        // private capability when an unauthenticated first peer connects.
        assert!(
            echoed_nonce == *nonce,
            "fixture control authentication failed"
        );
        control
    }

    struct ObservedHelper(OwnedHandle);
    impl ObservedHelper {
        fn open(pid: u32, supervisor: &mut SupervisorChild) -> Self {
            assert_ne!(pid, supervisor.child.id(), "reported helper is supervisor");
            assert!(
                supervisor.child.try_wait().unwrap().is_none(),
                "supervisor exited before observation"
            );
            // SAFETY: observation ONLY, no terminate/VM/duplicate rights.
            let raw = unsafe {
                OpenProcess(
                    PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                    0,
                    pid,
                )
            };
            assert!(
                !raw.is_null(),
                "OpenProcess: {}",
                std::io::Error::last_os_error()
            );
            // SAFETY: newly owned valid process handle, closed exactly once.
            let helper = Self(unsafe { OwnedHandle::from_raw_handle(raw) });
            let mut in_outer = 0;
            // SAFETY: retained objects and valid writable BOOL out pointer.
            // Reject unrelated/reused external PIDs BEFORE using observation.
            assert_ne!(
                unsafe {
                    IsProcessInJob(
                        helper.0.as_raw_handle(),
                        supervisor.outer.0.as_raw_handle(),
                        &mut in_outer,
                    )
                },
                0,
                "IsProcessInJob: {}",
                std::io::Error::last_os_error()
            );
            assert_ne!(in_outer, 0, "reported helper is outside fixture Job");
            assert!(
                supervisor.child.try_wait().unwrap().is_none(),
                "supervisor exited during observation"
            );
            helper
        }

        fn wait(&self, milliseconds: u32) -> u32 {
            // SAFETY: retained handle keeps the exact validated process alive.
            unsafe { WaitForSingleObject(self.0.as_raw_handle(), milliseconds) }
        }
    }

    #[test]
    #[ignore = "requires ORANGESPACE_TEST_SING_BOX pointing to verified official sing-box 1.14.4"]
    fn real_sing_box_dies_after_abrupt_supervisor_exit() {
        let Some(binary) = verified_real_runtime() else {
            return;
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let (mut supervisor, nonce) = spawn_supervisor(&listener, "exit-37", Some(&binary));
        let mut control = authenticated_control(&listener, &mut supervisor, &nonce);
        // Child sends this only after authenticating the real SOCKS listener.
        let mut ready = [0; 6];
        control.read_exact(&mut ready).unwrap();
        let pid = u32::from_le_bytes(ready[..4].try_into().unwrap());
        let socks_port = u16::from_le_bytes(ready[4..].try_into().unwrap());
        let helper = ObservedHelper::open(pid, &mut supervisor);
        assert_eq!(helper.wait(0), WAIT_TIMEOUT, "helper already exited");
        assert!(authenticate(socks_port, "fixture-crash-password"));
        assert!(supervisor.child.try_wait().unwrap().is_none());

        // Keep this socket OPEN through exit: EOF is never the shutdown trigger.
        control.write_all(&[37]).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = supervisor.child.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "supervisor did not exit on command"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(status.code(), Some(37), "must exit without supervisor Drop");
        assert_eq!(
            helper.wait(10_000),
            WAIT_OBJECT_0,
            "real helper process did not signal after supervisor crash"
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while !listener_closed(socks_port) {
            assert!(
                Instant::now() < deadline,
                "real helper retained its SOCKS listener"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        drop(control);
        // Only NOW may the independent outer guard terminate/close its Job.
        drop(supervisor);
    }

    #[test]
    fn outer_fixture_cleanup_terminates_descendant_before_runtime_readiness() {
        // Fixture-only regression: no production HelperSupervisor/inner Job and
        // no Go runtime. The sleeping descendant survives until OUTER cleanup.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let (mut supervisor, nonce) = spawn_supervisor(&listener, "cleanup-probe", None);
        let mut control = authenticated_control(&listener, &mut supervisor, &nonce);
        let mut pid = [0; 4];
        control.read_exact(&mut pid).unwrap();
        let descendant = ObservedHelper::open(u32::from_le_bytes(pid), &mut supervisor);
        assert_eq!(descendant.wait(0), WAIT_TIMEOUT);
        // No runtime-ready message was sent. Exercise actual error unwinding
        // with a living descendant and no production Job cleanup to help us.
        let failure = std::panic::catch_unwind(move || {
            let _guard = supervisor;
            panic!("injected pre-readiness fixture failure");
        });
        assert!(failure.is_err());
        assert_eq!(
            descendant.wait(5_000),
            WAIT_OBJECT_0,
            "outer fixture cleanup left descendant alive"
        );
    }

    #[test]
    #[ignore = "subprocess fixture only; real sing-box, not the fake version probe"]
    fn real_sing_box_supervisor_child() {
        // A broad --ignored invocation must not launch a nested supervisor.
        let mode = std::env::var("ORANGESPACE_REAL_SUPERVISOR_CHILD").unwrap_or_default();
        if mode != "exit-37" && mode != "cleanup-probe" {
            return;
        }
        let mut nonce = [0; 16];
        // MUST precede even the Go version probe: parent assigns our retained
        // process to its outer Job, then releases private stdin activation.
        if std::io::stdin().read_exact(&mut nonce).is_err() {
            std::process::exit(98);
        }
        let address: std::net::SocketAddr = std::env::var("ORANGESPACE_REAL_SUPERVISOR_CONTROL")
            .unwrap()
            .parse()
            .unwrap();
        assert!(address.ip().is_loopback());
        if mode == "cleanup-probe" {
            // Intentionally do NOT wait/kill in this subprocess: only the
            // independent parent-owned outer Job may clean up this descendant.
            #[allow(clippy::zombie_processes)]
            let _descendant = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "version_probe_child", "--ignored", "--nocapture"])
                .env_remove("ORANGESPACE_REAL_SUPERVISOR_CHILD")
                .env("ORANGESPACE_VERSION_PROBE_CHILD", "sleep")
                .stdin(std::process::Stdio::null())
                .spawn()
                .unwrap();
            let mut control = TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap();
            control
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            control.write_all(&nonce).unwrap();
            control.write_all(&_descendant.id().to_le_bytes()).unwrap();
            loop {
                std::thread::park();
            }
        }
        let Some(binary) = verified_real_runtime() else {
            return;
        };
        let mut control = TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap();
        control
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let executable = TrustedExecutable::acknowledge_protected_installation(binary).unwrap();
        let mut supervisor = HelperSupervisor::new(executable, Duration::from_secs(2)).unwrap();
        let binding = binding();
        let socks_port = port();
        let pid = supervisor
            .start(
                binding,
                &settings(binding.node_id, socks_port, "fixture-crash-password"),
            )
            .unwrap();
        wait_listener(&mut supervisor, binding, socks_port);
        assert!(authenticate(socks_port, "fixture-crash-password"));
        control.write_all(&nonce).unwrap();
        control.write_all(&pid.to_le_bytes()).unwrap();
        control.write_all(&socks_port.to_le_bytes()).unwrap();
        let mut command = [0];
        if control.read_exact(&mut command).is_ok() && command == [37] {
            // Intentionally bypass HelperSupervisor::drop and all Rust cleanup.
            std::process::exit(37);
        }
        // EOF, a bad command or a socket error must NOT gracefully stop the
        // helper and produce false containment evidence. Parent-owned OUTER Job
        // handles failure cleanup independently, including before readiness.
        loop {
            std::thread::park();
        }
    }
}
