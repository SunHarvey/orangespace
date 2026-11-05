use super::*;

thread_local! { static ALLOCATIONS: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) }; }
thread_local! { static DENY_ALLOCATIONS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
struct ObservedAllocator;
fn record_allocation() {
    let _ = ALLOCATIONS.try_with(|c| {
        if let Some(n) = c.get() {
            c.set(Some(n + 1));
        }
    });
}
unsafe impl std::alloc::GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        record_allocation();
        if DENY_ALLOCATIONS.try_with(|c| c.get()).unwrap_or(false) {
            return std::ptr::null_mut();
        }
        unsafe { std::alloc::System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        record_allocation();
        if DENY_ALLOCATIONS.try_with(|c| c.get()).unwrap_or(false) {
            return std::ptr::null_mut();
        }
        unsafe { std::alloc::System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        record_allocation();
        if DENY_ALLOCATIONS.try_with(|c| c.get()).unwrap_or(false) {
            return std::ptr::null_mut();
        }
        unsafe { std::alloc::System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;

struct Handle(*mut std::ffi::c_void);
impl Drop for Handle {
    fn drop(&mut self) {
        os_runtime_free(self.0);
    }
}
fn call(h: &Handle, request: &[u8]) -> Value {
    let mut out = vec![0; 65536];
    let n = unsafe {
        os_runtime_call(
            h.0,
            request.as_ptr(),
            request.len(),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    assert!(n > 0, "generic ABI failed {n}");
    serde_json::from_slice(&out[..n as usize]).unwrap()
}
fn take(h: &Handle, b: Binding, out: &mut [u8]) -> i32 {
    let bytes = serde_json::to_vec(&b).unwrap();
    unsafe {
        os_runtime_take_local_channel_v1(
            h.0,
            bytes.as_ptr(),
            bytes.len(),
            out.as_mut_ptr(),
            out.len(),
        )
    }
}
#[test]
#[ignore = "requires approved ORANGESPACE_TEST_SING_BOX, local TUIC only"]
fn real_mixed_private_channel_is_exact_once_and_small_output_does_not_consume() {
    let binary = std::env::var("ORANGESPACE_TEST_SING_BOX").unwrap();
    let b = Binding {
        generation: 2,
        ..binding()
    };
    let server = probe_server(b, false);
    let mut l = lease(b);
    l["probe_port"] = json!(server.port);
    let node = real_node(std::path::Path::new(&binary), &mut l);
    let ca = std::fs::read(node.cert).unwrap();
    let h = Handle(unsafe {
        os_runtime_new_with_local_proxy_v1(
            binary.as_ptr(),
            binary.len(),
            3000,
            ca.as_ptr(),
            ca.len(),
            1,
        )
    });
    assert!(!h.0.is_null());
    let started = call(&h, &start_request(b, l));
    assert_eq!(started["running"], true);
    assert!(started.get("username").is_none());
    let mut out = vec![0x5a; 4096];
    for bad in [
        Binding {
            user_id: orangespace_core::UserId::new(),
            ..b
        },
        Binding {
            sandbox_id: orangespace_core::SandboxId::new(),
            ..b
        },
        Binding {
            node_id: orangespace_core::NodeId::new(),
            ..b
        },
        Binding {
            generation: b.generation - 1,
            ..b
        },
        Binding {
            tunnel_id: orangespace_core::TunnelId::new(),
            ..b
        },
    ] {
        assert_eq!(take(&h, bad, &mut out), -1);
        assert!(out.iter().all(|v| *v == 0x5a));
    }
    assert_eq!(take(&h, b, &mut out[..1]), -2);
    for invalid in [
        format!("{{\"binding\":{}}}", serde_json::to_string(&b).unwrap()),
        format!(
            "{{\"schema\":2,\"user_id\":\"{}\",\"sandbox_id\":\"{}\",\"node_id\":\"{}\",\"generation\":1,\"tunnel_id\":\"{}\"}}",
            b.user_id, b.sandbox_id, b.node_id, b.tunnel_id
        ),
        serde_json::to_string(&b)
            .unwrap()
            .replace("\"generation\":2", "\"generation\":2.0"),
    ] {
        assert_eq!(
            unsafe {
                os_runtime_take_local_channel_v1(
                    h.0,
                    invalid.as_ptr(),
                    invalid.len(),
                    out.as_mut_ptr(),
                    out.len(),
                )
            },
            -1
        );
    }
    assert!(out.iter().all(|v| *v == 0x5a));
    let input = serde_json::to_vec(&b).unwrap();
    ALLOCATIONS.with(|c| c.set(Some(0)));
    // Positive control: the thread-local denial really returns allocation failure.
    DENY_ALLOCATIONS.with(|c| c.set(true));
    let denied = unsafe { std::alloc::alloc(std::alloc::Layout::new::<u64>()) };
    DENY_ALLOCATIONS.with(|c| c.set(false));
    assert!(denied.is_null());
    ALLOCATIONS.with(|c| c.set(Some(0)));
    // An actual complete handoff runs with sticky heap denial, not a mock encoder.
    DENY_ALLOCATIONS.with(|c| c.set(true));
    let n = unsafe {
        os_runtime_take_local_channel_v1(
            h.0,
            input.as_ptr(),
            input.len(),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    let allocations = ALLOCATIONS.with(|c| c.replace(None).unwrap());
    DENY_ALLOCATIONS.with(|c| c.set(false));
    assert_eq!(allocations, 0, "private delivery must not allocate");
    assert!(n > 0, "take failed {n}");
    let channel: Value = serde_json::from_slice(&out[..n as usize]).unwrap();
    assert_eq!(channel["binding"], serde_json::to_value(b).unwrap());
    assert_eq!(channel["host"], "127.0.0.1");
    assert_eq!(channel["port"], started["socks_port"]);
    assert_eq!(channel["clock"], CLOCK);
    assert!(channel.get("tuic_password").is_none());
    assert_eq!(
        channel
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "binding",
            "clock",
            "deadline_ms",
            "host",
            "password",
            "port",
            "proof_observed_at_ms",
            "remaining_ttl_ms",
            "request_started_ms",
            "schema",
            "username"
        ]
    );
    for auth in [None, Some("Zml4dHVyZTp3cm9uZw==")] {
        let mut stream =
            TcpStream::connect(("127.0.0.1", channel["port"].as_u64().unwrap() as u16)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        write!(
            stream,
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1\r\n{}\r\n",
            server.port,
            auth.map(|s| format!("Proxy-Authorization: Basic {s}\r\n"))
                .unwrap_or_default()
        )
        .unwrap();
        assert!(read_head(&mut stream).starts_with("HTTP/1.1 407 "));
    }
    let auth = base64(
        format!(
            "{}:{}",
            channel["username"].as_str().unwrap(),
            channel["password"].as_str().unwrap()
        )
        .as_bytes(),
    );
    let mut stream =
        TcpStream::connect(("127.0.0.1", channel["port"].as_u64().unwrap() as u16)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    write!(stream, "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n", server.port).unwrap();
    assert!(read_head(&mut stream).starts_with("HTTP/1.1 200 "));
    write!(stream, "POST /v1/tunnels/{}/probe HTTP/1.1\r\nHost: 127.0.0.1\r\nX-OrangeSpace-Probe: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", b.tunnel_id, "a".repeat(43)).unwrap();
    assert!(verify_http(&mut stream, b, &"b".repeat(43)).is_ok());
    out.fill(0x5a);
    assert_eq!(take(&h, b, &mut out), -1);
    assert!(out.iter().all(|v| *v == 0x5a));
    // Taking the Service copy must not remove ongoing SOCKS proof credentials.
    assert_eq!(
        call(
            &h,
            &serde_json::to_vec(
                &json!({"schema":2,"op":"probe","binding":b,"budget":budget(3000)})
            )
            .unwrap()
        )["forwarding_verified"],
        true
    );
    call(
        &h,
        &serde_json::to_vec(&json!({"schema":2,"op":"close","binding":b})).unwrap(),
    );
    assert_eq!(take(&h, b, &mut out), -1);
    os_runtime_free(h.0);
    assert_eq!(take(&h, b, &mut out), -3);
}

#[test]
#[ignore = "requires approved ORANGESPACE_TEST_SING_BOX, local TUIC only"]
fn real_unclaimed_channel_rejects_close_expiry_and_stale_proof_without_resetting_grant() {
    let binary = std::env::var("ORANGESPACE_TEST_SING_BOX").unwrap();
    for scenario in [
        "closed",
        "expired",
        "stale",
        "failed_probe",
        "renewed",
        "dead_helper",
    ] {
        if scenario == "dead_helper" && !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            continue;
        }
        let b = binding();
        let server = probe_server(b, false);
        let mut l = lease(b);
        l["probe_port"] = json!(server.port);
        if scenario == "expired" || scenario == "renewed" {
            l["remaining_ttl_ms"] = json!(1500);
        }
        let mut node = real_node(std::path::Path::new(&binary), &mut l);
        let ca = std::fs::read(&node.cert).unwrap();
        let h = Handle(unsafe {
            os_runtime_new_with_local_proxy_v1(
                binary.as_ptr(),
                binary.len(),
                1000,
                ca.as_ptr(),
                ca.len(),
                1,
            )
        });
        let request = start_request(b, l);
        let original: Value = serde_json::from_slice(&request).unwrap();
        let started = call(&h, &request);
        assert_eq!(started["running"], true);
        match scenario {
            "closed" => {
                call(
                    &h,
                    &serde_json::to_vec(&json!({"schema":2,"op":"close","binding":b})).unwrap(),
                );
            }
            "expired" | "renewed" => {
                if scenario == "renewed" {
                    call(&h, &serde_json::to_vec(&json!({"schema":2,"op":"renew","binding":b,
                        "expires_at":original["lease"]["expires_at"].as_u64().unwrap()+10,"budget":budget(30000)})).unwrap());
                }
                let deadline = original["budget"]["deadline_ms"].as_u64().unwrap();
                while clock_ms().unwrap() < deadline {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            "stale" => std::thread::sleep(Duration::from_millis(3100)),
            "failed_probe" => {
                node._child.0.kill().unwrap();
                node._child.0.wait().unwrap();
                assert_eq!(
                    call(
                        &h,
                        &serde_json::to_vec(
                            &json!({"schema":2,"op":"probe","binding":b,"budget":budget(500)})
                        )
                        .unwrap()
                    )["forwarding_verified"],
                    false
                );
            }
            "dead_helper" => {
                // Exact unreaped owned root: no PID reuse before this runtime
                // reaps it. Linux-only asynchronous-exit fault injection.
                let pid = started["pid"].as_u64().unwrap();
                assert!(
                    std::process::Command::new("kill")
                        .args(["-KILL", &pid.to_string()])
                        .status()
                        .unwrap()
                        .success()
                );
                wait_until_waitable(pid);
            }
            _ => unreachable!(),
        }
        let mut out = [0x5a; 4096];
        assert_eq!(take(&h, b, &mut out), -1, "scenario {scenario}");
        assert!(out.iter().all(|v| *v == 0x5a));
        if scenario == "renewed" {
            assert_eq!(
                call(
                    &h,
                    &serde_json::to_vec(
                        &json!({"schema":2,"op":"probe","binding":b,"budget":budget(1000)})
                    )
                    .unwrap()
                )["forwarding_verified"],
                true
            );
            assert_eq!(take(&h, b, &mut out), -1);
        }
        if scenario == "stale" {
            assert_eq!(
                call(
                    &h,
                    &serde_json::to_vec(
                        &json!({"schema":2,"op":"probe","binding":b,"budget":budget(1000)})
                    )
                    .unwrap()
                )["forwarding_verified"],
                true
            );
            let n = take(&h, b, &mut out);
            assert!(n > 0);
            let grant: Value = serde_json::from_slice(&out[..n as usize]).unwrap();
            assert_eq!(grant["deadline_ms"], original["budget"]["deadline_ms"]);
            assert_eq!(
                grant["request_started_ms"],
                original["budget"]["request_started_ms"]
            );
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn wait_until_waitable(pid: u64) {
    // Checked against this Linux x64 libc's sys/wait.h/signal.h layout.
    // WNOWAIT observes completion WITHOUT stealing the supervisor's child.
    // /proc root Z is insufficient while Go's other threads are exiting.
    unsafe extern "C" {
        fn waitid(which: i32, pid: u32, info: *mut [u64; 16], options: i32) -> i32;
    }
    let end = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let mut info = [0u64; 16];
        assert_eq!(
            unsafe { waitid(1, pid as u32, &mut info, 4 | 1 | 16777216) },
            0
        );
        let observed = unsafe { std::ptr::read(info.as_ptr().cast::<u8>().add(16).cast::<u32>()) };
        if observed as u64 == pid {
            break;
        }
        assert!(std::time::Instant::now() < end);
        std::thread::yield_now();
    }
}
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn wait_until_waitable(_: u64) {
    unreachable!("Linux x64 fixture only");
}

fn read_head(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") && bytes.len() < 8192 {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
    }
    String::from_utf8(bytes).unwrap()
}
fn base64(bytes: &[u8]) -> String {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = ((c[0] as u32) << 16)
            | ((c.get(1).copied().unwrap_or(0) as u32) << 8)
            | c.get(2).copied().unwrap_or(0) as u32;
        out.push(alphabet[((n >> 18) & 63) as usize] as char);
        out.push(alphabet[((n >> 12) & 63) as usize] as char);
        out.push(if c.len() > 1 {
            alphabet[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            alphabet[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}
