use super::*;
#[path = "local_channel_tests.rs"]
mod local_channel_tests;
use serde_json::{Value, json};

#[test]
fn explicit_local_proxy_constructor_rejects_unknown_protocol_and_keeps_legacy_socks() {
    let path = std::env::current_exe().unwrap();
    let path = path.to_str().unwrap();
    for protocol in [0, 1, 2, u32::MAX] {
        let h = unsafe {
            os_runtime_new_with_local_proxy_v1(
                path.as_ptr(),
                path.len(),
                100,
                std::ptr::null(),
                0,
                protocol,
            )
        };
        assert_eq!(h.is_null(), protocol > 1);
        os_runtime_free(h);
    }
}

fn binding() -> Binding {
    Binding {
        user_id: orangespace_core::UserId::new(),
        sandbox_id: orangespace_core::SandboxId::new(),
        node_id: orangespace_core::NodeId::new(),
        generation: 1,
        tunnel_id: orangespace_core::TunnelId::new(),
    }
}
fn lease(b: Binding) -> Value {
    json!({"lease_schema":2,"remaining_ttl_ms":30000,"user_id":b.user_id,"sandbox_id":b.sandbox_id,"node_id":b.node_id,"generation":b.generation,"tunnel_id":b.tunnel_id,
        "expires_at":now_secs().unwrap()+30,"endpoint_ip":"127.0.0.1","endpoint_port":443,"tls_server_name":"node.example.test",
        "tuic_uuid":uuid::Uuid::new_v4(),"tuic_password":"fixture-tuic-password-not-api-token",
        "probe_host":"127.0.0.1","probe_port":8080,"probe_request":"a".repeat(43),"probe_response":"b".repeat(43)})
}

#[test]
fn stdin_io_deadline_is_original_common_budget_not_a_fresh_timeout() {
    // Real common clock + real Instant; no assumed shared epoch. The deliberately
    // old Instant sample models scheduling/preparation before the common sample.
    let sampled = std::time::Instant::now();
    let common = clock_ms().unwrap();
    let original = common + 100;
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    assert_eq!(
        rx.recv_timeout(Duration::from_millis(150)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    );
    drop(tx);
    assert!(
        stdin_io_deadline(original).is_err(),
        "expired original budget must reject before core start"
    );
    let original = clock_ms().unwrap() + 100;
    let before = std::time::Instant::now();
    let io_deadline = stdin_io_deadline(original).unwrap();
    assert!(io_deadline <= before + Duration::from_millis(101));
    assert!(io_deadline > sampled);
}

#[test]
fn lease_requires_exact_full_binding_and_canonical_nonzero_ids() {
    let b = binding();
    let valid = lease(b);
    assert!(parse_start(&start_request(b, valid.clone())).is_ok());
    for key in [
        "user_id",
        "sandbox_id",
        "node_id",
        "generation",
        "tunnel_id",
    ] {
        let mut bad = valid.clone();
        bad[key] = if key == "generation" {
            json!(2)
        } else {
            json!(uuid::Uuid::new_v4())
        };
        assert!(
            parse_start(&start_request(b, bad)).is_err(),
            "accepted mismatched {key}"
        );
    }
    for id in [
        "00000000-0000-0000-0000-000000000000",
        "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
        "11111111111141118111111111111111",
    ] {
        let mut bad = valid.clone();
        bad["user_id"] = json!(id);
        let mut bb = serde_json::to_value(b).unwrap();
        bb["user_id"] = json!(id);
        assert!(parse_start(
            &serde_json::to_vec(
                &json!({"schema":2,"op":"start","binding":bb,"lease":bad,"budget":budget(30000)})
            )
            .unwrap()
        )
        .is_err());
    }
}

#[test]
fn lease_rejects_expiry_untrusted_targets_and_echoable_or_malformed_secrets() {
    let b = binding();
    let base = lease(b);
    for (key, value) in [
        ("expires_at", json!(0)),
        ("expires_at", json!(MAX_EXACT + 1)),
        ("endpoint_ip", json!("node.example.test")),
        ("endpoint_port", json!(0)),
        ("tls_server_name", json!("192.0.2.99")),
        ("tls_server_name", json!("bad name")),
        ("probe_host", json!("127.0.0.2")),
        ("probe_host", json!("localhost")),
        ("probe_port", json!(0)),
        ("probe_request", base["probe_response"].clone()),
        ("probe_request", json!("a\r\nInjected: yes")),
        ("tuic_uuid", json!(uuid::Uuid::nil())),
        ("tuic_password", json!("short")),
        ("certificate_path", json!("/untrusted/ca")),
        ("unknown", json!(true)),
    ] {
        let mut bad = base.clone();
        bad[key] = value;
        assert!(
            parse_start(&start_request(b, bad)).is_err(),
            "accepted unsafe {key}"
        );
    }
    for generation in [0u64, 9_007_199_254_740_992] {
        let mut bad = base.clone();
        bad["generation"] = json!(generation);
        let mut bb = serde_json::to_value(b).unwrap();
        bb["generation"] = json!(generation);
        assert!(parse_start(
            &serde_json::to_vec(
                &json!({"schema":2,"op":"start","binding":bb,"lease":bad,"budget":budget(30000)})
            )
            .unwrap()
        )
        .is_err());
    }
}

#[test]
fn bounded_http_proof_requires_exact_response_secret_tuple_status_and_framing() {
    let b = binding();
    let secret = "b".repeat(43);
    let body = serde_json::to_string(&json!({"tunnel_id":b.tunnel_id,"proof":secret})).unwrap();
    let response = |body: &str| {
        format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).into_bytes()
    };
    assert!(verify_http(&mut std::io::Cursor::new(response(&body)), b, &secret).is_ok());
    let wrong =
        serde_json::to_string(&json!({"tunnel_id":b.tunnel_id,"proof":"a".repeat(43)})).unwrap();
    let tuple =
        serde_json::to_string(&json!({"tunnel_id":uuid::Uuid::new_v4(),"proof":secret})).unwrap();
    let mut duplicate = response(&body);
    let at = duplicate.windows(2).position(|w| w == b"\r\n").unwrap();
    duplicate.splice(at..at, b"\r\nContent-Length: 1".iter().copied());
    for bad in [
        response(&wrong),
        response(&tuple),
        duplicate,
        response(&body).into_iter().chain([0]).collect(),
        format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{body}").into_bytes(),
        format!(
            "HTTP/1.1 500 Nope\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999\r\n\r\n".to_vec(),
        vec![b'A'; 8193],
        response(&body)[..body.len()].to_vec(),
        response(&format!(
            "{{\"tunnel_id\":\"{}\",\"proof\":\"{}\",\"extra\":true}}",
            b.tunnel_id, secret
        )),
    ] {
        assert!(verify_http(&mut std::io::Cursor::new(bad), b, &secret).is_err());
    }
}

struct TestChild(std::process::Child);
impl Drop for TestChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct RealNode {
    _dir: tempfile::TempDir,
    _child: TestChild,
    cert: std::path::PathBuf,
    port: u16,
}
fn real_node(binary: &std::path::Path, l: &mut Value) -> RealNode {
    use std::{
        io::Write,
        net::UdpSocket,
        process::{Command, Stdio},
    };
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    let result = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=node.example.test",
            "-addext",
            "subjectAltName=DNS:node.example.test",
            "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .output()
        .unwrap();
    assert!(result.status.success());
    let port = UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let config = json!({"log":{"disabled":true},"inbounds":[{"type":"tuic","listen":"127.0.0.1","listen_port":port,
        "users":[{"uuid":l["tuic_uuid"],"password":l["tuic_password"]}],"zero_rtt_handshake":false,
        "tls":{"enabled":true,"certificate_path":cert,"key_path":key}}],"outbounds":[{"type":"direct","tag":"loopback"}],
        "route":{"rules":[{"ip_cidr":["127.0.0.1/32"],"port":l["probe_port"],"action":"route","outbound":"loopback"},{"action":"reject"}]}});
    let mut child = TestChild(
        Command::new(binary)
            .args(["run", "--config", "stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    child
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&config).unwrap())
        .unwrap();
    l["endpoint_port"] = json!(port);
    std::thread::sleep(std::time::Duration::from_millis(150));
    assert!(child.0.try_wait().unwrap().is_none());
    RealNode {
        _dir: dir,
        _child: child,
        cert,
        port,
    }
}
struct ProbeServer {
    port: u16,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}
impl Drop for ProbeServer {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            t.join().unwrap();
        }
    }
}
fn probe_server(b: Binding, echo: bool) -> ProbeServer {
    probe_server_delayed(b, echo, Duration::ZERO)
}
fn probe_server_delayed(b: Binding, echo: bool, delay: Duration) -> ProbeServer {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Duration,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let done = stop.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let thread = std::thread::spawn(move || {
        while !done.load(Ordering::SeqCst) {
            let Ok((mut stream, _)) = listener.accept() else {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") && request.len() < 8192 {
                let mut c = [0];
                if stream.read_exact(&mut c).is_err() {
                    break;
                }
                request.push(c[0]);
            }
            let request = String::from_utf8(request).unwrap();
            if !request.starts_with(&format!(
                "POST /v1/tunnels/{}/probe HTTP/1.1\r\n",
                b.tunnel_id
            )) || !request.contains(&format!("X-OrangeSpace-Probe: {}\r\n", "a".repeat(43)))
                || request.contains("Authorization:")
            {
                continue;
            }
            // Expected response secret must NEVER have appeared in the request.
            assert!(!request.contains(&"b".repeat(43)));
            count.fetch_add(1, Ordering::SeqCst);
            let body=serde_json::to_string(&json!({"tunnel_id":b.tunnel_id,"proof":if echo{"a".repeat(43)}else{"b".repeat(43)}})).unwrap();
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            std::thread::sleep(delay);
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    ProbeServer {
        port,
        stop,
        thread: Some(thread),
        calls,
    }
}
fn budget(ttl: u64) -> Value {
    let start = clock_ms().unwrap();
    json!({"clock":CLOCK,"request_started_ms":start,"remaining_ttl_ms":ttl,"deadline_ms":start+ttl})
}
fn start_request(b: Binding, l: Value) -> Vec<u8> {
    let ttl = l["remaining_ttl_ms"].as_u64().unwrap_or(30000);
    serde_json::to_vec(&json!({"schema":2,"op":"start","binding":b,"lease":l,"budget":budget(ttl)}))
        .unwrap()
}

#[test]
#[ignore = "requires ORANGESPACE_TEST_SING_BOX verified 1.14.4; isolated loopback TUIC"]
fn real_tuic_proof_not_stdin_and_close_a_does_not_close_b() {
    use std::{path::PathBuf, sync::atomic::Ordering, time::Duration};
    let binary = PathBuf::from(
        std::env::var_os("ORANGESPACE_TEST_SING_BOX").expect("explicit verified helper required"),
    );
    let a = binding();
    let b = binding();
    let probes_a = probe_server(a, false);
    let probes_b = probe_server(b, false);
    let mut la = lease(a);
    la["probe_port"] = json!(probes_a.port);
    let node_a = real_node(&binary, &mut la);
    let mut lb = lease(b);
    lb["probe_port"] = json!(probes_b.port);
    let node_b = real_node(&binary, &mut lb);
    assert_ne!(node_a.port, node_b.port);
    let mut runtime = Runtime::new(binary, Duration::from_secs(4)).unwrap();
    runtime.test_certificate = Some(node_a.cert.clone());
    let request_a = start_request(a, la.clone());
    let ra = runtime.dispatch(&request_a).unwrap();
    assert_eq!(ra["running"], true);
    assert_eq!(ra["process_started"], true);
    assert_eq!(ra["tunnel_authenticated"], true);
    assert_eq!(ra["forwarding_verified"], true);
    assert_eq!(probes_a.calls.load(Ordering::SeqCst), 1);
    runtime.test_certificate = Some(node_b.cert.clone());
    let request_b = start_request(b, lb.clone());
    let rb = runtime.dispatch(&request_b).unwrap();
    assert_eq!(rb["running"], true);
    assert_ne!(ra["pid"], rb["pid"]);
    assert_ne!(ra["socks_port"], rb["socks_port"]);
    assert!(runtime.dispatch(&request_a).is_err());
    let stale = Binding { generation: 2, ..a };
    assert!(
        runtime
            .dispatch(
                &serde_json::to_vec(&json!({"schema":2,"op":"close","binding":stale})).unwrap()
            )
            .is_err()
    );
    assert_eq!(
        runtime
            .dispatch(&serde_json::to_vec(&json!({"schema":2,"op":"close","binding":a})).unwrap())
            .unwrap()["running"],
        false
    );
    assert!(
        std::net::TcpStream::connect((
            std::net::Ipv4Addr::LOCALHOST,
            ra["socks_port"].as_u64().unwrap() as u16
        ))
        .is_err()
    );
    assert!(runtime.supervisor.poll(b).unwrap().is_none());
    assert!(
        matches!(runtime.dispatch(&request_a), Err(Error::Invalid)),
        "a stale start must not fatally invalidate unrelated helpers"
    );
    assert!(runtime.supervisor.poll(b).unwrap().is_none());
    let probe_request = |binding| {
        serde_json::to_vec(
            &json!({"schema":2,"op":"probe","binding":binding,"budget":budget(2000)}),
        )
        .unwrap()
    };
    let before = probes_b.calls.load(Ordering::SeqCst);
    let deadline = runtime.active[&b].deadline;
    let attempts = runtime.attempts;
    let fresh = runtime
        .dispatch(&probe_request(b))
        .expect("existing binding fresh probe operation missing");
    assert_eq!(
        fresh
            .value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec![
            "binding",
            "expires_at",
            "forwarding_verified",
            "lease_deadline_ms",
            "observed_at_ms",
            "ok",
            "process_alive",
            "reason"
        ]
    );
    assert_eq!(fresh["process_alive"], true);
    assert_eq!(fresh["reason"], "verified");
    assert!(fresh["observed_at_ms"].as_u64().unwrap() <= clock_ms().unwrap());
    assert_eq!(fresh["binding"], json!(b));
    assert_eq!(fresh["forwarding_verified"], true);
    assert_eq!(fresh["lease_deadline_ms"], deadline);
    assert_eq!(probes_b.calls.load(Ordering::SeqCst), before + 1);
    let encoded = ffi::encode_reply(&mut runtime, fresh).unwrap();
    let encoded = String::from_utf8(encoded).unwrap();
    for secret in [
        &runtime.probes[&b].user,
        &runtime.probes[&b].password,
        &runtime.probes[&b].probe_request,
        &runtime.probes[&b].probe_response,
    ] {
        assert!(!encoded.contains(secret));
    }
    assert_eq!(runtime.probes.len(), 1);
    assert!(!runtime.probes.contains_key(&a));
    // A valid helper with an incorrect expected node response must never publish proof.
    runtime.probes.get_mut(&b).unwrap().probe_response = "c".repeat(43);
    let before_wrong = probes_b.calls.load(Ordering::SeqCst);
    let negative = runtime.dispatch(&probe_request(b)).unwrap();
    assert_eq!(negative["ok"], false);
    assert_eq!(negative["forwarding_verified"], false);
    assert_eq!(negative["process_alive"], true);
    assert_eq!(negative["reason"], "probe_failed");
    assert_eq!(negative["lease_deadline_ms"], deadline);
    assert_eq!(negative["expires_at"], runtime.active[&b].expires_at);
    assert_eq!(negative.value.as_object().unwrap().len(), 8);
    ffi::encode_reply(&mut runtime, negative).unwrap();
    assert_eq!(probes_b.calls.load(Ordering::SeqCst), before_wrong + 1);
    assert_eq!(runtime.active[&b].deadline, deadline);
    assert!(runtime.supervisor.poll(b).unwrap().is_none());
    runtime.probes.get_mut(&b).unwrap().probe_response = "b".repeat(43);
    // Serialization fence rejects an expired observation WITHOUT retiring a live lease.
    let observation_budget = budget(200);
    let observation_deadline = observation_budget["deadline_ms"].as_u64().unwrap();
    let short = serde_json::to_vec(
        &json!({"schema":2,"op":"probe","binding":b,"budget":observation_budget}),
    )
    .unwrap();
    let fresh = runtime.dispatch(&short).unwrap();
    assert!(
        fresh
            .publication
            .as_ref()
            .unwrap()
            .observation_deadline
            .unwrap()
            <= observation_deadline
    );
    std::thread::sleep(Duration::from_millis(
        observation_deadline.saturating_sub(clock_ms().unwrap()) + 1,
    ));
    assert!(matches!(
        ffi::encode_reply(&mut runtime, fresh),
        Err(Error::Invalid)
    ));
    let before_expired = probes_b.calls.load(Ordering::SeqCst);
    assert!(matches!(runtime.dispatch(&short), Err(Error::Invalid)));
    assert_eq!(probes_b.calls.load(Ordering::SeqCst), before_expired);
    assert_eq!(runtime.active[&b].deadline, deadline);
    assert!(runtime.supervisor.poll(b).unwrap().is_none());
    #[cfg(target_os = "linux")]
    assert!(std::path::Path::new(&format!("/proc/{}", rb["pid"])).exists());
    for wrong in [a, stale, Binding { generation: 2, ..b }] {
        let negative = runtime.dispatch(&probe_request(wrong)).unwrap();
        assert_eq!(negative["ok"], false);
        assert_eq!(negative["forwarding_verified"], false);
        assert_eq!(negative["process_alive"], false);
        assert_eq!(negative["reason"], "not_active");
        assert_eq!(negative["binding"], json!(wrong));
        assert_eq!(negative["lease_deadline_ms"], 0);
        assert_eq!(negative["expires_at"], 0);
        assert_eq!(negative.value.as_object().unwrap().len(), 8);
        ffi::encode_reply(&mut runtime, negative).unwrap();
    }
    assert_eq!(runtime.attempts, attempts);
    assert_eq!(runtime.active[&b].deadline, deadline);
    assert!(runtime.supervisor.poll(b).unwrap().is_none());
    let response = serde_json::to_string(&rb).unwrap();
    for secret in [
        "fixture-tuic-password-not-api-token",
        &"a".repeat(43),
        &"b".repeat(43),
    ] {
        assert!(!response.contains(secret));
    }
    let pb = rb["socks_port"].as_u64().unwrap() as u16;
    drop(runtime);
    assert!(std::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, pb)).is_err());
}

#[test]
fn ffi_capacity_preflight_invalid_handles_double_free_and_concurrent_free_are_safe() {
    let path = std::env::current_exe().unwrap();
    let path = path.to_str().unwrap().as_bytes();
    // SAFETY: all supplied buffers live throughout each call and never overlap.
    let h = unsafe { os_runtime_new(path.as_ptr(), path.len(), 100) };
    assert!(!h.is_null());
    let request = br#"{"schema":2,"op":"poll"}"#;
    let mut out = vec![0x55; 65536];
    assert_eq!(
        unsafe { os_runtime_call(h, request.as_ptr(), request.len(), out.as_mut_ptr(), 65535) },
        -2
    );
    assert!(out.iter().all(|x| *x == 0x55));
    let n = unsafe {
        os_runtime_call(
            h,
            request.as_ptr(),
            request.len(),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    assert!(n > 0);
    let v: Value = serde_json::from_slice(&out[..n as usize]).unwrap();
    assert_eq!(v, json!({"ok":true,"exited":[]}));
    let malformed = br#"{"schema":2,"op":"poll","unknown":"do not echo me"}"#;
    assert_eq!(
        unsafe {
            os_runtime_call(
                h,
                malformed.as_ptr(),
                malformed.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        },
        -1
    );
    let token = h as usize;
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(move || {
                let h = token as *mut std::ffi::c_void;
                let mut out = vec![0; 65536];
                let n = unsafe {
                    os_runtime_call(
                        h,
                        request.as_ptr(),
                        request.len(),
                        out.as_mut_ptr(),
                        out.len(),
                    )
                };
                assert!(n > 0 || n == -3);
            });
        }
        scope.spawn(move || os_runtime_free(token as *mut std::ffi::c_void));
    });
    os_runtime_free(h);
    assert_eq!(
        unsafe {
            os_runtime_call(
                h,
                request.as_ptr(),
                request.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        },
        -3
    );
    assert_eq!(
        unsafe {
            os_runtime_call(
                123usize as *mut std::ffi::c_void,
                request.as_ptr(),
                request.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        },
        -3
    );
    assert!(unsafe { os_runtime_new(std::ptr::null(), 1, 100) }.is_null());
    assert!(unsafe { os_runtime_new(path.as_ptr(), path.len(), 0) }.is_null());
    let h2 = unsafe { os_runtime_new(path.as_ptr(), path.len(), 100) };
    assert_ne!(h, h2);
    os_runtime_free(h2);
}

#[test]
#[ignore = "requires ORANGESPACE_TEST_SING_BOX verified 1.14.4; real TUIC proof-negative"]
fn real_tuic_echoed_request_is_not_proof_and_failed_helper_is_reaped() {
    use std::{path::PathBuf, sync::atomic::Ordering, time::Duration};
    let binary = PathBuf::from(
        std::env::var_os("ORANGESPACE_TEST_SING_BOX").expect("explicit verified helper required"),
    );
    let b = binding();
    let probe = probe_server(b, true);
    let mut l = lease(b);
    l["probe_port"] = json!(probe.port);
    let node = real_node(&binary, &mut l);
    let mut runtime = Runtime::new(binary, Duration::from_secs(3)).unwrap();
    runtime.test_certificate = Some(node.cert.clone());
    let request = start_request(b, l.clone());
    let reply = runtime.dispatch(&request).unwrap();
    assert_eq!(reply["process_started"], true);
    for flag in [
        "ok",
        "running",
        "tunnel_authenticated",
        "forwarding_verified",
    ] {
        assert_eq!(reply[flag], false, "false-positive {flag}");
    }
    assert_eq!(
        probe.calls.load(Ordering::SeqCst),
        1,
        "must traverse actual TUIC to loopback API before rejecting echo"
    );
    assert!(runtime.active.is_empty());
    assert!(
        runtime.supervisor.poll(b).is_err(),
        "failed helper was not reaped"
    );
    let port = reply["socks_port"].as_u64().unwrap() as u16;
    assert!(std::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).is_err());
    assert!(matches!(runtime.dispatch(&request), Err(Error::Invalid)));
    assert_eq!(
        runtime.dispatch(br#"{"schema":2,"op":"poll"}"#).unwrap()["exited"],
        json!([])
    );
}
#[test]
#[ignore = "requires ORANGESPACE_TEST_SING_BOX verified 1.14.4; real stdin is not forwarding"]
fn real_socks_stdin_without_tuic_never_reports_authenticated_or_running() {
    use std::{path::PathBuf, time::Duration};
    let binary = PathBuf::from(
        std::env::var_os("ORANGESPACE_TEST_SING_BOX").expect("explicit verified helper required"),
    );
    let b = binding();
    let mut l = lease(b);
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    l["endpoint_port"] = json!(socket.local_addr().unwrap().port());
    let mut runtime = Runtime::new(binary, Duration::from_millis(300)).unwrap();
    let reply = runtime.dispatch(&start_request(b, l)).unwrap();
    assert_eq!(reply["process_started"], true);
    for flag in [
        "ok",
        "running",
        "tunnel_authenticated",
        "forwarding_verified",
    ] {
        assert_eq!(reply[flag], false);
    }
    assert!(runtime.supervisor.poll(b).is_err());
    assert!(runtime.active.is_empty());
}
#[test]
#[ignore = "requires ORANGESPACE_TEST_SING_BOX verified 1.14.4; real expired helper cleanup"]
fn real_runtime_poll_reaps_expired_lease_once_and_preserves_tuple() {
    use std::{path::PathBuf, time::Duration};
    let binary = PathBuf::from(
        std::env::var_os("ORANGESPACE_TEST_SING_BOX").expect("explicit verified helper required"),
    );
    let b = binding();
    let probe = probe_server(b, false);
    let mut l = lease(b);
    l["probe_port"] = json!(probe.port);
    let node = real_node(&binary, &mut l);
    l["expires_at"] = json!(now_secs().unwrap() + 3);
    l["remaining_ttl_ms"] = json!(3000);
    let mut runtime = Runtime::new(binary, Duration::from_secs(2)).unwrap();
    runtime.test_certificate = Some(node.cert.clone());
    let request = start_request(b, l.clone());
    let reply = runtime.dispatch(&request).unwrap();
    assert_eq!(reply["running"], true);
    std::thread::sleep(Duration::from_secs(3));
    let negative = runtime
        .dispatch(
            &serde_json::to_vec(
                &json!({"schema":2,"op":"probe","binding":b,"budget":budget(1000)}),
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(negative["ok"], false);
    assert_eq!(negative["process_alive"], false);
    assert_eq!(negative["reason"], "expired");
    assert_eq!(negative["lease_deadline_ms"], 0);
    assert_eq!(negative["expires_at"], 0);
    assert_eq!(negative.value.as_object().unwrap().len(), 8);
    ffi::encode_reply(&mut runtime, negative).unwrap();
    let events = runtime.dispatch(br#"{"schema":2,"op":"poll"}"#).unwrap();
    assert_eq!(events["exited"], json!([{"binding":b,"pid":reply["pid"]}]));
    assert_eq!(
        runtime.dispatch(br#"{"schema":2,"op":"poll"}"#).unwrap()["exited"],
        json!([])
    );
    assert!(runtime.active.is_empty());
    assert!(runtime.supervisor.poll(b).is_err());
}
#[cfg(unix)]
#[test]
#[ignore = "requires ORANGESPACE_TEST_SING_BOX verified 1.14.4; real asynchronous child exit"]
fn real_runtime_poll_reports_unexpected_child_exit_exactly_once() {
    use std::{
        path::PathBuf,
        time::{Duration, Instant},
    };
    let binary = PathBuf::from(
        std::env::var_os("ORANGESPACE_TEST_SING_BOX").expect("explicit verified helper required"),
    );
    let b = binding();
    let probe = probe_server(b, false);
    let mut l = lease(b);
    l["probe_port"] = json!(probe.port);
    let node = real_node(&binary, &mut l);
    let mut runtime = Runtime::new(binary, Duration::from_secs(2)).unwrap();
    runtime.test_certificate = Some(node.cert.clone());
    let reply = runtime.dispatch(&start_request(b, l)).unwrap();
    assert_eq!(reply["running"], true);
    assert!(
        std::process::Command::new("kill")
            .args(["-KILL", &reply["pid"].as_u64().unwrap().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let negative = runtime
            .dispatch(
                &serde_json::to_vec(
                    &json!({"schema":2,"op":"probe","binding":b,"budget":budget(1000)}),
                )
                .unwrap(),
            )
            .unwrap();
        if negative["reason"] == "helper_stopped" {
            assert_eq!(negative["ok"], false);
            assert_eq!(negative["process_alive"], false);
            assert_eq!(negative["lease_deadline_ms"], 0);
            assert_eq!(negative["expires_at"], 0);
            assert_eq!(negative.value.as_object().unwrap().len(), 8);
            ffi::encode_reply(&mut runtime, negative).unwrap();
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    loop {
        let events = runtime.dispatch(br#"{"schema":2,"op":"poll"}"#).unwrap();
        if events["exited"] != json!([]) {
            assert_eq!(events["exited"], json!([{"binding":b,"pid":reply["pid"]}]));
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        runtime.dispatch(br#"{"schema":2,"op":"poll"}"#).unwrap()["exited"],
        json!([])
    );
}

#[test]
#[ignore = "requires ORANGESPACE_TEST_SING_BOX verified 1.14.4; real ABI start preflight"]
fn real_abi_small_output_does_not_spawn_or_consume_binding() {
    let binary =
        std::env::var("ORANGESPACE_TEST_SING_BOX").expect("explicit verified helper required");
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let b = binding();
    let mut l = lease(b);
    l["endpoint_port"] = json!(socket.local_addr().unwrap().port());
    let request = start_request(b, l);
    let h = unsafe { os_runtime_new(binary.as_ptr(), binary.len(), 300) };
    assert!(!h.is_null());
    struct Handle(*mut std::ffi::c_void);
    impl Drop for Handle {
        fn drop(&mut self) {
            os_runtime_free(self.0);
        }
    }
    let _guard = Handle(h);
    let mut out = vec![0x55; 65536];
    assert_eq!(
        unsafe { os_runtime_call(h, request.as_ptr(), request.len(), out.as_mut_ptr(), 65535) },
        -2
    );
    assert!(out.iter().all(|c| *c == 0x55));
    let n = unsafe {
        os_runtime_call(
            h,
            request.as_ptr(),
            request.len(),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    assert!(
        n > 0,
        "undersized-output call consumed binding or failed runtime"
    );
    let response: Value = serde_json::from_slice(&out[..n as usize]).unwrap();
    assert_eq!(response["process_started"], true);
    assert_eq!(response["running"], false);
    assert_eq!(
        unsafe {
            os_runtime_call(
                h,
                request.as_ptr(),
                request.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        },
        -1
    );
}

include!("renew_tests.rs");

#[test]
fn v2_rejects_legacy_poll_without_work() {
    let mut runtime =
        Runtime::new(std::env::current_exe().unwrap(), Duration::from_millis(100)).unwrap();
    assert!(matches!(
        runtime.dispatch(br#"{"op":"poll"}"#),
        Err(Error::Invalid)
    ));
    assert_eq!(runtime.attempts, 0);
}

#[test]
fn v2_lease_accepts_node_clock_skew_and_requires_exact_ttl() {
    let b = binding();
    let mut l = lease(b);
    l["lease_schema"] = json!(2);
    l["remaining_ttl_ms"] = json!(30000);
    for expiry in [now_secs().unwrap() - 1, now_secs().unwrap() + 31] {
        l["expires_at"] = json!(expiry);
        assert!(parse_start(&start_request(b, l.clone())).is_ok());
    }
    for ttl in [
        json!(0),
        json!(30001),
        json!(1.5),
        json!(-1),
        json!(true),
        json!(null),
    ] {
        l["remaining_ttl_ms"] = ttl;
        assert!(parse_start(&start_request(b, l.clone())).is_err());
    }
}

#[test]
fn v2_late_queue_budget_denied_before_generation_or_helper_work() {
    let b = binding();
    let mut l = lease(b);
    l["lease_schema"] = json!(2);
    l["remaining_ttl_ms"] = json!(1);
    let mut request: Value = serde_json::from_slice(&start_request(b, l)).unwrap();
    request["budget"]["request_started_ms"] = json!(0);
    request["budget"]["deadline_ms"] = json!(1);
    let mut runtime =
        Runtime::new(std::env::current_exe().unwrap(), Duration::from_millis(100)).unwrap();
    assert!(matches!(
        runtime.dispatch(&serde_json::to_vec(&request).unwrap()),
        Err(Error::Invalid)
    ));
    assert_eq!(runtime.attempts, 0);
    assert!(runtime.history.is_empty());
}

#[test]
fn budget_boundaries_preserve_original_anchor_and_expire_at_equality() {
    let make = |m0, ttl, d| {
        serde_json::from_value::<Budget>(
            json!({"clock":CLOCK,"request_started_ms":m0,"remaining_ttl_ms":ttl,"deadline_ms":d}),
        )
        .unwrap()
    };
    let b = make(1000, 1, 1001);
    assert!(b.validate_at(1000).is_ok());
    assert!(b.validate_at(1001).is_err());
    assert!(b.validate_at(999).is_err());
    assert!(make(1000, 30000, 31000).validate_at(30999).is_ok());
    assert!(make(1000, 30000, 31000).validate_at(31000).is_err());
    for (m0, ttl, d, now) in [
        (1000, 0, 1000, 1000),
        (1000, 30001, 31001, 1000),
        (1000, 10, 1011, 1000),
        (MAX_EXACT, 1, MAX_EXACT + 1, MAX_EXACT),
        (u64::MAX, 1, 0, 0),
    ] {
        assert!(make(m0, ttl, d).validate_at(now).is_err());
    }
    assert!(
        make(MAX_EXACT - 1, 1, MAX_EXACT)
            .validate_at(MAX_EXACT - 1)
            .is_ok()
    );
    // The native common clock progresses without borrowing a Rust Instant epoch.
    let first = clock_ms().unwrap();
    // GetTickCount64 can have 10-16 ms resolution; 2 ms need not advance it.
    let observation_started = std::time::Instant::now();
    while clock_ms().unwrap() <= first {
        assert!(
            observation_started.elapsed() < Duration::from_secs(1),
            "native common clock did not advance within one second"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}
#[test]
fn schema_and_budget_invalid_inputs_never_consume_authority() {
    let b = binding();
    let start: Value = serde_json::from_slice(&start_request(b, lease(b))).unwrap();
    let mut runtime =
        Runtime::new(std::env::current_exe().unwrap(), Duration::from_millis(100)).unwrap();
    let mut cases = Vec::new();
    for op in ["start", "renew", "probe", "close", "poll"] {
        let request = match op {
            "start" => start.clone(),
            "renew" => {
                json!({"schema":2,"op":op,"binding":b,"expires_at":1,"budget":budget(30000)})
            }
            "probe" => json!({"schema":2,"op":op,"binding":b,"budget":budget(30000)}),
            "close" => json!({"schema":2,"op":op,"binding":b}),
            _ => json!({"schema":2,"op":op}),
        };
        for schema in [
            json!(1),
            json!(3),
            json!(2.0),
            json!("2"),
            json!(true),
            json!(null),
        ] {
            let mut bad = request.clone();
            bad["schema"] = schema;
            cases.push(bad);
        }
        let mut bad = request.clone();
        bad.as_object_mut().unwrap().remove("schema");
        cases.push(bad);
        let mut bad = request;
        bad["extra"] = json!(true);
        cases.push(bad);
    }
    for field in [
        "clock",
        "request_started_ms",
        "remaining_ttl_ms",
        "deadline_ms",
    ] {
        let mut bad = start.clone();
        bad["budget"].as_object_mut().unwrap().remove(field);
        cases.push(bad);
        for value in [json!(-1), json!(1.5), json!("1"), json!(null), json!(true)] {
            let mut bad = start.clone();
            bad["budget"][field] = value;
            cases.push(bad);
        }
    }
    for clock in [
        "windows-gettickcount64-ms-v1",
        "linux-clock-monotonic-ms-v1",
        "steady_clock",
        "unsupported",
    ] {
        if clock == CLOCK {
            continue;
        }
        let mut bad = start.clone();
        bad["budget"]["clock"] = json!(clock);
        cases.push(bad);
    }
    let mut bad = start.clone();
    bad["budget"]["extra"] = json!(true);
    cases.push(bad);
    let mut bad = start.clone();
    bad["lease"]["remaining_ttl_ms"] = json!(29999);
    cases.push(bad);
    for key in ["lease_schema", "remaining_ttl_ms"] {
        let mut bad = start.clone();
        bad["lease"].as_object_mut().unwrap().remove(key);
        cases.push(bad);
    }
    let mut bad = start;
    bad["lease"]["lease_schema"] = json!(1);
    cases.push(bad);
    for case in cases {
        assert!(matches!(
            runtime.dispatch(&serde_json::to_vec(&case).unwrap()),
            Err(Error::Invalid)
        ));
        assert_eq!(runtime.attempts, 0);
        assert!(runtime.history.is_empty());
    }
}
#[test]
#[ignore = "requires verified cached Go/TUIC; publication fence after serialization"]
fn real_ffi_reply_cannot_publish_after_original_deadline() {
    let binary = std::path::PathBuf::from(std::env::var_os("ORANGESPACE_TEST_SING_BOX").unwrap());
    let b = binding();
    let probes = probe_server(b, false);
    let mut l = lease(b);
    l["probe_port"] = json!(probes.port);
    let node = real_node(&binary, &mut l);
    l["remaining_ttl_ms"] = json!(1500);
    let request = start_request(b, l);
    let mut runtime = Runtime::new(binary, Duration::from_secs(2)).unwrap();
    runtime.test_certificate = Some(node.cert.clone());
    let reply = runtime.dispatch(&request).unwrap();
    assert_eq!(reply["running"], true);
    let deadline = runtime.active[&b].deadline;
    std::thread::sleep(Duration::from_millis(
        deadline.saturating_sub(clock_ms().unwrap()) + 1,
    ));
    assert!(
        ffi::encode_reply(&mut runtime, reply).is_err(),
        "serialization/publication must retain the original deadline"
    );
    assert!(runtime.active.is_empty());
    assert!(runtime.supervisor.poll(b).is_err());
}

#[test]
#[ignore = "requires verified cached Go/TUIC; proof consumes original POST budget"]
fn real_slow_proof_exhausts_original_budget_and_reaps_helper() {
    let binary = std::path::PathBuf::from(std::env::var_os("ORANGESPACE_TEST_SING_BOX").unwrap());
    let b = binding();
    let probes = probe_server_delayed(b, false, Duration::from_millis(900));
    let mut l = lease(b);
    l["probe_port"] = json!(probes.port);
    let node = real_node(&binary, &mut l);
    l["remaining_ttl_ms"] = json!(600);
    let request = start_request(b, l);
    let mut runtime = Runtime::new(binary, Duration::from_secs(2)).unwrap();
    runtime.test_certificate = Some(node.cert.clone());
    let reply = runtime.dispatch(&request).unwrap();
    assert_eq!(reply["process_started"], true);
    assert_eq!(reply["running"], false);
    assert_eq!(reply["forwarding_verified"], false);
    assert_eq!(probes.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(runtime.active.is_empty());
    assert!(runtime.supervisor.poll(b).is_err());
    assert!(runtime.dispatch(&request).is_err());
}
#[test]
#[ignore = "requires verified cached Go/TUIC; old deadline survives renewal serialization"]
fn real_renew_publication_cannot_cross_old_deadline() {
    let binary = std::path::PathBuf::from(std::env::var_os("ORANGESPACE_TEST_SING_BOX").unwrap());
    let b = binding();
    let probes = probe_server(b, false);
    let mut l = lease(b);
    l["probe_port"] = json!(probes.port);
    let node = real_node(&binary, &mut l);
    l["remaining_ttl_ms"] = json!(1500);
    let expiry = l["expires_at"].as_u64().unwrap();
    let mut runtime = Runtime::new(binary, Duration::from_secs(2)).unwrap();
    runtime.test_certificate = Some(node.cert.clone());
    let request = start_request(b, l);
    assert_eq!(runtime.dispatch(&request).unwrap()["running"], true);
    let old_deadline = runtime.active[&b].deadline;
    let request = serde_json::to_vec(
        &json!({"schema":2,"op":"renew","binding":b,"expires_at":expiry+30,"budget":budget(30000)}),
    )
    .unwrap();
    let reply = runtime.dispatch(&request).unwrap();
    assert!(runtime.active[&b].deadline > old_deadline);
    std::thread::sleep(Duration::from_millis(
        old_deadline.saturating_sub(clock_ms().unwrap()) + 1,
    ));
    assert!(ffi::encode_reply(&mut runtime, reply).is_err());
    assert!(runtime.active.is_empty());
    assert!(runtime.supervisor.poll(b).is_err());
    assert!(runtime.dispatch(&request).is_err());
}
#[test]
#[cfg(unix)]
#[ignore = "requires verified cached Go/TUIC; cancelled root and new generation"]
fn real_cancelled_root_cannot_renew_or_reclaim_new_generation() {
    let binary = std::path::PathBuf::from(std::env::var_os("ORANGESPACE_TEST_SING_BOX").unwrap());
    let a = binding();
    let probes = probe_server(a, false);
    let mut l = lease(a);
    l["probe_port"] = json!(probes.port);
    let node = real_node(&binary, &mut l);
    let old_request = start_request(a, l);
    let mut runtime = Runtime::new(binary.clone(), Duration::from_secs(2)).unwrap();
    runtime.test_certificate = Some(node.cert.clone());
    let reply = runtime.dispatch(&old_request).unwrap();
    assert_eq!(reply["running"], true);
    assert!(
        std::process::Command::new("kill")
            .args(["-KILL", &reply["pid"].as_u64().unwrap().to_string()])
            .status()
            .unwrap()
            .success()
    );
    std::thread::sleep(Duration::from_millis(100));
    let renew=serde_json::to_vec(&json!({"schema":2,"op":"renew","binding":a,"expires_at":now_secs().unwrap()+30,"budget":budget(30000)})).unwrap();
    assert!(runtime.dispatch(&renew).is_err());
    assert!(runtime.active.is_empty());
    let b = Binding {
        generation: 2,
        tunnel_id: orangespace_core::TunnelId::new(),
        ..a
    };
    let probes_b = probe_server(b, false);
    let mut lb = lease(b);
    lb["probe_port"] = json!(probes_b.port);
    let node_b = real_node(&binary, &mut lb);
    runtime.test_certificate = Some(node_b.cert.clone());
    let new_request = start_request(b, lb);
    assert_eq!(runtime.dispatch(&new_request).unwrap()["running"], true);
    assert!(runtime.dispatch(&old_request).is_err());
    assert!(runtime.dispatch(&renew).is_err());
    let events = runtime.dispatch(br#"{"schema":2,"op":"poll"}"#).unwrap();
    assert_eq!(events["exited"], json!([{"binding":a,"pid":reply["pid"]}]));
    assert!(runtime.active.contains_key(&b));
    assert!(runtime.supervisor.poll(b).unwrap().is_none());
}

include!("private_ca_tests.rs");
