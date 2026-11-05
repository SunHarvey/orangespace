use orangespace_https::*;
use std::{
    fs,
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
};
struct Fixture {
    child: Child,
    origin: String,
    ca: Vec<u8>,
    wrong_ca: Vec<u8>,
}
impl Fixture {
    fn new() -> Self {
        Self::with_mode("valid")
    }
    fn with_mode(mode: &str) -> Self {
        let mut child = Command::new("python3")
            .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/tls_fixture.py"))
            .arg(mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let (port, dir) = line.trim().split_once(' ').unwrap();
        Self {
            origin: format!("https://localhost:{port}"),
            ca: fs::read(format!("{dir}/ca.pem")).unwrap(),
            wrong_ca: fs::read(format!("{dir}/wrong.pem")).unwrap(),
            child,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let _ = self.child.wait();
    }
}
fn bytes(b: &[u8]) -> OsHttpsBytes {
    OsHttpsBytes {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}
fn invoke(
    origin: &[u8],
    ca: &[u8],
    method: &[u8],
    path: &[u8],
    body: &[u8],
    bearer: &[u8],
) -> (i32, u32, u32, Vec<u8>, Vec<u8>) {
    let r = OsHttpsRequest {
        origin: bytes(origin),
        ca_pem: bytes(ca),
        method: bytes(method),
        path: bytes(path),
        body: bytes(body),
        bearer: bytes(bearer),
    };
    let mut out = vec![0xA5; MAX_RESPONSE];
    let mut head = vec![0xA5; 64];
    let mut status = 999;
    let mut hlen = 999;
    let code = unsafe {
        os_https_request_v1(
            &r,
            out.as_mut_ptr(),
            out.len(),
            &mut status,
            head.as_mut_ptr(),
            head.len(),
            &mut hlen,
        )
    };
    (code, status, hlen, out, head)
}
#[test]
fn node_protocol_header_preserves_lease_v2_admission() {
    let f = Fixture::new();
    let (n, status, _, _, _) = invoke(
        f.origin.as_bytes(),
        &f.ca,
        b"POST",
        b"/lease-header",
        b"{}",
        b"",
    );
    assert!(n >= 0);
    assert_eq!(status, 200);
}
#[test]
fn centre_node_list_allows_only_canonical_pagination_query() {
    let f = Fixture::new();
    for path in [
        "/control/v1/me/nodes?limit=100",
        "/control/v1/me/nodes?limit=100&cursor=11111111-1111-4111-8111-111111111111",
    ] {
        let (n, status, _, _, _) = invoke(
            f.origin.as_bytes(),
            &f.ca,
            b"GET",
            path.as_bytes(),
            b"",
            b"",
        );
        assert!(n >= 0);
        assert_eq!(status, 200);
    }
    for path in [
        "/control/v1/me/nodes?limit=100&cursor=bad",
        "/control/v1/me/nodes?limit=100&cursor=00000000-0000-0000-0000-000000000000",
        "/control/v1/me/nodes?limit=100&url=https://other.test",
        "/other?limit=100",
    ] {
        assert_atomic_error(invoke(
            f.origin.as_bytes(),
            &f.ca,
            b"GET",
            path.as_bytes(),
            b"",
            b"",
        ));
    }
}
#[test]
fn json_transport_preserves_unique_content_type_guard() {
    let f = Fixture::new();
    for path in [
        b"/not-json".as_slice(),
        b"/duplicate-content-type".as_slice(),
    ] {
        assert_atomic_error(invoke(f.origin.as_bytes(), &f.ca, b"GET", path, b"", b""));
    }
}
#[test]
fn duplicate_node_header_is_atomic_error() {
    let f = Fixture::new();
    assert_atomic_error(invoke(
        f.origin.as_bytes(),
        &f.ca,
        b"GET",
        b"/duplicate",
        b"",
        b"",
    ));
}
fn assert_atomic_error(result: (i32, u32, u32, Vec<u8>, Vec<u8>)) {
    let (n, status, hlen, out, head) = result;
    assert_eq!(n, OS_HTTPS_ERROR);
    assert_eq!(status, 999);
    assert_eq!(hlen, 999);
    assert!(out.iter().all(|x| *x == 0xA5));
    assert!(head.iter().all(|x| *x == 0xA5));
}
#[test]
fn get_post_delete_preserve_json_bodies() {
    let f = Fixture::new();
    for method in [b"GET".as_slice(), b"POST", b"DELETE"] {
        let (n, status, _, out, _) = invoke(
            f.origin.as_bytes(),
            &f.ca,
            method,
            b"/echo",
            b"{\"x\":1}",
            &[b'T'; 43],
        );
        assert_eq!(n, 7, "method {:?}", method);
        assert_eq!(status, 200);
        assert_eq!(&out[..7], b"{\"x\":1}");
    }
}
#[test]
fn real_tls_private_ca_positive() {
    let f = Fixture::new();
    let (n, status, hlen, out, head) = invoke(f.origin.as_bytes(), &f.ca, b"GET", b"/ok", b"", b"");
    assert_eq!(n, 11);
    assert_eq!(status, 200);
    assert_eq!(&out[..11], b"{\"ok\":true}");
    assert_eq!(hlen, 43);
    assert_eq!(&head[..43], &[b'N'; 43]);
}

#[test]
fn wrong_ca_and_wrong_hostname_are_atomic_generic_errors() {
    let f = Fixture::new();
    assert_atomic_error(invoke(
        f.origin.as_bytes(),
        &f.wrong_ca,
        b"GET",
        b"/ok",
        b"",
        b"",
    ));
    assert_atomic_error(invoke(
        f.origin.replace("localhost", "127.0.0.1").as_bytes(),
        &f.ca,
        b"GET",
        b"/ok",
        b"",
        b"",
    ));
}
#[test]
fn expired_server_certificate_is_rejected() {
    let f = Fixture::with_mode("expired");
    assert_atomic_error(invoke(f.origin.as_bytes(), &f.ca, b"GET", b"/ok", b"", b""));
}
#[test]
fn http_errors_and_redirects_are_not_transport_errors() {
    let f = Fixture::new();
    for (path, expected) in [(b"/status".as_slice(), 401), (b"/redirect", 302)] {
        let (n, status, _, out, _) = invoke(f.origin.as_bytes(), &f.ca, b"GET", path, b"", b"");
        assert_eq!(n, 11);
        assert_eq!(status, expected);
        assert_eq!(&out[..11], b"{\"ok\":true}");
    }
    let (_, status, hlen, _, _) = invoke(f.origin.as_bytes(), &f.ca, b"GET", b"/centre", b"", b"");
    assert_eq!(status, 200);
    assert_eq!(hlen, 0);
    let (n, status, _, out, _) = invoke(f.origin.as_bytes(), &f.ca, b"DELETE", b"/empty", b"", b"");
    assert_eq!(n, 0);
    assert_eq!(status, 204);
    assert!(out.iter().all(|b| *b == 0xA5));
}
#[test]
fn response_body_caps_and_combined_header() {
    let f = Fixture::new();
    assert_atomic_error(invoke(
        f.origin.as_bytes(),
        &f.ca,
        b"GET",
        b"/large",
        b"",
        b"",
    ));
    assert_atomic_error(invoke(
        f.origin.as_bytes(),
        &f.ca,
        b"GET",
        b"/comma",
        b"",
        b"",
    ));
    let (n, status, _, out, _) = invoke(f.origin.as_bytes(), &f.ca, b"GET", b"/limit", b"", b"");
    assert_eq!(n, MAX_RESPONSE as i32);
    assert_eq!(status, 200);
    assert!(out.iter().all(|b| *b == b'x'));
}
#[test]
fn global_timeout_includes_response_body_and_publishes_nothing() {
    let f = Fixture::new();
    for path in [b"/slow".as_slice(), b"/slowbody"] {
        let started = std::time::Instant::now();
        assert_atomic_error(invoke(f.origin.as_bytes(), &f.ca, b"GET", path, b"", b""));
        assert!(started.elapsed() >= std::time::Duration::from_millis(4800));
        assert!(started.elapsed() < std::time::Duration::from_millis(5800));
    }
}
#[test]
fn malformed_inputs_and_request_body_cap_are_atomic() {
    let f = Fixture::new();
    for origin in [
        "http://localhost",
        "https://user:pass@localhost",
        "https://localhost/",
        "https://localhost?x",
        "https://localhost#x",
        "https://localhost\\x",
        "https://localhost:0",
    ] {
        assert_atomic_error(invoke(origin.as_bytes(), &f.ca, b"GET", b"/ok", b"", b""));
    }
    for path in [
        "https://localhost/ok",
        "//localhost/ok",
        "/a\r\nX: y",
        "/a/../b",
        "/a%0d%0a",
        "/x?q=1",
        "/a#b",
        "/a\\b",
    ] {
        assert_atomic_error(invoke(
            f.origin.as_bytes(),
            &f.ca,
            b"GET",
            path.as_bytes(),
            b"",
            b"",
        ));
    }
    assert_atomic_error(invoke(f.origin.as_bytes(), &f.ca, b"PUT", b"/ok", b"", b""));
    assert_atomic_error(invoke(
        f.origin.as_bytes(),
        &f.ca,
        b"POST",
        b"/echo",
        &vec![b'x'; 16385],
        b"",
    ));
    for bearer in [b"short".as_slice(), &[b'+'; 43], &[b'\n'; 43]] {
        assert_atomic_error(invoke(
            f.origin.as_bytes(),
            &f.ca,
            b"GET",
            b"/ok",
            b"",
            bearer,
        ));
    }
    let body = format!("\"{}\"", "x".repeat(16382));
    assert_eq!(
        invoke(
            f.origin.as_bytes(),
            &f.ca,
            b"POST",
            b"/echo",
            body.as_bytes(),
            b""
        )
        .0,
        16384
    );
}
