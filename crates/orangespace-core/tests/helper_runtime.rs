//! Opt-in real-runtime integration. It validates supervisor -> sing-box stdin
//! configuration and independent authenticated SOCKS listeners, NOT TUIC egress,
//! process-tree containment, Windows WFP, DNS, or a browser launch permit.
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
    let result = (|| {
        loop {
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
        }
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

#[test]
#[ignore = "requires ORANGESPACE_TEST_SING_BOX pointing to verified official sing-box 1.14.4"]
fn real_sing_box_stdin_authentication_and_independent_lifecycle() {
    let binary = std::env::var_os("ORANGESPACE_TEST_SING_BOX")
        .expect("explicit verified runtime path required");
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
