use orangespace_https::*;
use std::{
    ffi::c_void,
    fs,
    io::{BufRead, BufReader},
    process::{Command, Stdio},
};
fn b(x: &[u8]) -> OsHttpsBytes {
    OsHttpsBytes {
        ptr: x.as_ptr(),
        len: x.len(),
    }
}
#[derive(Default)]
struct State {
    received: usize,
    source: usize,
    pos: usize,
    cancel: bool,
    cancel_after: bool,
    calls: usize,
}
unsafe extern "C" fn read(c: *mut c_void, p: *mut u8, n: usize) -> i64 {
    let s = unsafe { &mut *(c as *mut State) };
    let n = n.min(s.source - s.pos);
    unsafe { std::ptr::write_bytes(p, b'x', n) };
    s.pos += n;
    s.calls += 1;
    n as i64
}
unsafe extern "C" fn write(c: *mut c_void, p: *const u8, n: usize) -> i32 {
    let s = unsafe { &mut *(c as *mut State) };
    assert!(n <= 65536);
    assert!(unsafe { std::slice::from_raw_parts(p, n) }
        .iter()
        .all(|x| *x == b'x'));
    s.received += n;
    if s.cancel_after {
        s.cancel = true
    };
    0
}
unsafe extern "C" fn cancelled(c: *mut c_void) -> i32 {
    unsafe { (*(c as *mut State)).cancel as i32 }
}
struct Fixture(std::process::Child);
impl std::ops::Deref for Fixture {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for Fixture {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.0.stdin.take();
        // Retain/reap this exact child even when an assertion unwinds.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[test]
fn streaming_real_tls_contract() {
    let mut child = Fixture(
        Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/transfer_fixture.py"
            ))
            .env("TMPDIR", "/var/tmp/hermes-runtime/tmp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let (port, dir) = line.trim().split_once(' ').unwrap();
    let origin = format!("https://localhost:{port}");
    let ca = fs::read(format!("{dir}/ca.pem")).unwrap();
    let wrong = fs::read(format!("{dir}/wrong.pem")).unwrap();
    let run = |method: &[u8],
               path: &[u8],
               origin: &str,
               ca: &[u8],
               source: usize,
               size: u64,
               cancel: bool,
               after: bool| {
        let mut s = State {
            source,
            cancel,
            cancel_after: after,
            ..Default::default()
        };
        let r = OsHttpsTransferRequest {
            origin: b(origin.as_bytes()),
            ca_pem: b(ca),
            method: b(method),
            path: b(path),
            bearer: b(&[b'T'; 43]),
            expected_node: b(b"22222222-2222-4222-8222-222222222222"),
            upload_size: size,
            context: (&mut s as *mut State).cast(),
            read: if method == b"GET" { None } else { Some(read) },
            write: Some(write),
            cancelled: Some(cancelled),
        };
        let (mut status, mut total) = (999, 0);
        let result = unsafe { os_https_transfer_v1(&r, &mut status, &mut total) };
        (result, status, total, s)
    };
    let n = 2 * 1024 * 1024 + 17;
    let a = run(b"GET", b"/v1/files/large", &origin, &ca, 0, 0, false, false);
    assert_eq!(a.0, 0);
    assert_eq!(a.3.received, n);
    assert_eq!(a.2, n as u64);
    for path in [
        b"/v1/files/missingtype".as_slice(),
        b"/v1/files/badtype".as_slice(),
        b"/v1/files/duplicatetype".as_slice(),
        b"/v1/files?path=missingtype".as_slice(),
        b"/v1/files?path=badtype".as_slice(),
        b"/v1/files?path=duplicatetype".as_slice(),
    ] {
        let media = run(b"GET", path, &origin, &ca, 0, 0, false, false);
        assert_eq!(media.0, -1, "invalid media type must fail");
        assert_eq!(
            media.3.received, 0,
            "invalid media type must not reach sink"
        );
    }
    let prefixed = run(
        b"GET",
        b"/nodes/22222222-2222-4222-8222-222222222222/v1/files/large",
        &origin,
        &ca,
        0,
        0,
        false,
        false,
    );
    assert_eq!(prefixed.0, 0, "protected node API prefix must stream");
    assert_eq!(prefixed.3.received, n);
    let wrong_prefix = run(
        b"GET",
        b"/nodes/33333333-3333-4333-8333-333333333333/v1/files/large",
        &origin,
        &ca,
        0,
        0,
        false,
        false,
    );
    assert_eq!(wrong_prefix.0, -1);
    assert_eq!(
        wrong_prefix.1, 0,
        "wrong prefix must fail before connecting"
    );
    let a = run(
        b"PUT",
        b"/v1/files/large",
        &origin,
        &ca,
        n,
        n as u64,
        false,
        false,
    );
    assert_eq!(a.0, 0);
    assert_eq!(a.1, 201);
    assert_eq!(a.3.pos, n);
    assert!(a.3.calls > 2);
    for (path, status) in [
        (b"/v1/files/missing".as_slice(), 200),
        (b"/v1/files/duplicate", 200),
        (b"/v1/files/wrong", 200),
        (b"/v1/files/redirect", 302),
        (b"/v1/files/error", 401),
        (b"/v1/files/partial", 200),
    ] {
        let a = run(b"GET", path, &origin, &ca, 0, 0, false, false);
        assert_eq!(a.0, -1);
        assert_eq!(a.1, status);
        if path != b"/v1/files/partial" {
            assert_eq!(a.3.received, 0)
        }
    }
    for (o, c) in [
        (&origin, &wrong),
        (&origin.replace("localhost", "127.0.0.1"), &ca),
    ] {
        let a = run(b"PUT", b"/v1/files/large", o, c, n, n as u64, false, false);
        assert_eq!(a.0, -1);
        assert_eq!(a.3.calls, 0);
        assert_eq!(a.1, 0)
    }
    for (source, size) in [(n, n as u64 + 1), (n, n as u64 - 1)] {
        let a = run(
            b"PUT",
            b"/v1/files/large",
            &origin,
            &ca,
            source,
            size,
            false,
            false,
        );
        assert_eq!(a.0, -1)
    }
    for (before, after) in [(true, false), (false, true)] {
        let a = run(
            b"GET",
            b"/v1/files/large",
            &origin,
            &ca,
            0,
            0,
            before,
            after,
        );
        assert_eq!(a.0, -1)
    }
    drop(child.stdin.take());
    assert!(child.wait().unwrap().success());
}
