use crate::*;
use std::{
    ffi::c_void,
    io::{self, Read},
};
#[repr(C)]
pub struct OsHttpsTransferRequest {
    pub origin: OsHttpsBytes,
    pub ca_pem: OsHttpsBytes,
    pub method: OsHttpsBytes,
    pub path: OsHttpsBytes,
    pub bearer: OsHttpsBytes,
    pub expected_node: OsHttpsBytes,
    pub upload_size: u64,
    pub context: *mut c_void,
    pub read: Option<unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> i64>,
    pub write: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize) -> i32>,
    pub cancelled: Option<unsafe extern "C" fn(*mut c_void) -> i32>,
}
/// # Safety
/// See file_https_abi.h: live disjoint pointers and non-unwinding callbacks.
#[no_mangle]
pub unsafe extern "C" fn os_https_transfer_v1(
    r: *const OsHttpsTransferRequest,
    status: *mut u32,
    total: *mut u64,
) -> i32 {
    if status.is_null() || total.is_null() {
        return -1;
    }
    unsafe {
        *status = 0;
        *total = u64::MAX;
    }
    std::panic::catch_unwind(|| {
        if r.is_null() {
            return -1;
        }
        unsafe { transfer(&*r, status, total) }.map_or(-1, |_| 0)
    })
    .unwrap_or(-1)
}
const CHUNK: usize = 65536;
const BUDGET: Duration = Duration::from_secs(3600);
fn check(r: &OsHttpsTransferRequest, start: Instant) -> Result<(), ()> {
    if start.elapsed() >= BUDGET
        || unsafe { r.cancelled.ok_or(())?(r.context) } != 0
        || start.elapsed() >= BUDGET
    {
        Err(())
    } else {
        Ok(())
    }
}
struct Upload<'a> {
    r: &'a OsHttpsTransferRequest,
    start: Instant,
    left: u64,
}
impl Read for Upload<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut call = || -> Result<usize, ()> {
            check(self.r, self.start)?;
            let cap = out
                .len()
                .min(CHUNK)
                .min(self.left.min(CHUNK as u64) as usize);
            if cap == 0 {
                return Ok(0);
            }
            let n = unsafe { self.r.read.ok_or(())?(self.r.context, out.as_mut_ptr(), cap) };
            check(self.r, self.start)?;
            if n <= 0 || n as usize > cap {
                return Err(());
            }
            Ok(n as usize)
        };
        let n = call().map_err(|_| io::Error::other("transfer failed"))?;
        self.left -= n as u64;
        Ok(n)
    }
}
unsafe fn transfer(
    r: &OsHttpsTransferRequest,
    status: *mut u32,
    total: *mut u64,
) -> Result<(), ()> {
    let start = Instant::now();
    let origin = text(unsafe { borrow(r.origin, 2048)? })?;
    let ca = unsafe { borrow(r.ca_pem, 256 * 1024)? };
    let method = text(unsafe { borrow(r.method, 4)? })?;
    let path = text(unsafe { borrow(r.path, 16384)? })?;
    let bearer = text(unsafe { borrow(r.bearer, 43)? })?;
    let node = unsafe { borrow(r.expected_node, 64)? };
    bound_route(method, path, node)?;
    if r.write.is_none()
        || r.cancelled.is_none()
        || (method == "GET" && (r.upload_size != 0 || r.read.is_some()))
        || (method != "GET" && r.read.is_none())
        || r.upload_size == u64::MAX
        || bearer.len() != 43
        || !bearer
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        || node.is_empty()
        || !node
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(b))
    {
        return Err(());
    }
    let authority = origin.strip_prefix("https://").ok_or(())?;
    if authority.is_empty()
        || !authority.is_ascii()
        || authority
            .bytes()
            .any(|b| b <= 32 || b >= 127 || b"/@?#\\".contains(&b))
    {
        return Err(());
    }
    let uri: ureq::http::Uri = origin.parse().map_err(|_| ())?;
    if uri.host().is_none() || uri.port().is_some_and(|p| p.as_u16() == 0) {
        return Err(());
    }
    let mut certs = Vec::new();
    for item in parse_pem(ca) {
        match item.map_err(|_| ())? {
            PemItem::Certificate(c) => certs.push(c),
            _ => return Err(()),
        }
    }
    if certs.is_empty() {
        return Err(());
    }
    let tls = TlsConfig::builder()
        .provider(TlsProvider::Rustls)
        .root_certs(RootCerts::new_with_certs(&certs))
        .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .build();
    check(r, start)?;
    let config = ureq::Agent::config_builder()
        .https_only(true)
        .proxy(None)
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_global(Some(BUDGET.checked_sub(start.elapsed()).ok_or(())?))
        .timeout_resolve(Some(Duration::from_secs(30)))
        .timeout_connect(Some(Duration::from_secs(30)))
        .timeout_send_request(Some(Duration::from_secs(30)))
        .timeout_recv_response(Some(Duration::from_secs(30)))
        .max_response_header_size(16384)
        .max_idle_connections(0)
        .tls_config(tls)
        .build();
    use ureq::unversioned::{
        resolver::DefaultResolver,
        transport::{Connector, DefaultConnector},
    };
    let agent = ureq::Agent::with_parts(
        config,
        DefaultConnector::default().chain(StallConnector),
        DefaultResolver::default(),
    );
    let mut builder = ureq::http::Request::builder()
        .method(method)
        .uri(format!("{origin}{path}"))
        .header("Authorization", format!("Bearer {bearer}"))
        .header("Accept-Encoding", "identity")
        .header(
            "Content-Type",
            if method == "POST" {
                "application/json"
            } else {
                "application/octet-stream"
            },
        );
    let mut upload = Upload {
        r,
        start,
        left: r.upload_size,
    };
    let mut response = if method == "GET" {
        agent.run(builder.body(()).map_err(|_| ())?)
    } else {
        builder = builder.header("Content-Length", r.upload_size.to_string());
        agent.run(
            builder
                .body(ureq::SendBody::from_reader(&mut upload))
                .map_err(|_| ())?,
        )
    }
    .map_err(|_| ())?;
    unsafe {
        *status = response.status().as_u16() as u32;
    }
    check(r, start)?;
    let mut nodes = response.headers().get_all("X-OrangeSpace-Node").iter();
    if nodes.next().ok_or(())?.as_bytes() != node || nodes.next().is_some() {
        return Err(());
    }
    if response.status().as_u16() != if method == "GET" { 200 } else { 201 } {
        return Err(());
    }
    let mut types = response.headers().get_all("Content-Type").iter();
    let kind = types.next().ok_or(())?.as_bytes();
    let binary = method == "GET" && path.split('?').next().ok_or(())?.contains("/v1/files/");
    if types.next().is_some()
        || if binary {
            kind != b"application/octet-stream"
        } else {
            !matches!(
                kind,
                b"application/json" | b"application/json; charset=utf-8"
            )
        }
    {
        return Err(());
    }
    if method != "GET" {
        if upload.left != 0 {
            return Err(());
        }
        let mut extra = 0;
        check(r, start)?;
        let n = unsafe { r.read.ok_or(())?(r.context, &mut extra, 1) };
        check(r, start)?;
        if n != 0 {
            return Err(());
        }
    }
    let mut lengths = response.headers().get_all("Content-Length").iter();
    let length = match lengths.next() {
        None => None,
        Some(v) => {
            let b = v.as_bytes();
            if b.is_empty() || !b.iter().all(u8::is_ascii_digit) {
                return Err(());
            }
            Some(text(b)?.parse::<u64>().map_err(|_| ())?)
        }
    };
    if lengths.next().is_some()
        || (length.is_some() && response.headers().contains_key("Transfer-Encoding"))
        || response.headers().contains_key("Content-Encoding")
    {
        return Err(());
    }
    unsafe {
        *total = length.unwrap_or(u64::MAX);
    }
    let mut reader = response.body_mut().as_reader();
    let mut buf = [0u8; CHUNK];
    let mut count = 0u64;
    loop {
        check(r, start)?;
        let n = reader.read(&mut buf).map_err(|_| ())?;
        check(r, start)?;
        if n == 0 {
            break;
        }
        count = count.checked_add(n as u64).ok_or(())?;
        if length.is_some_and(|l| count > l) {
            return Err(());
        }
        let code = unsafe { r.write.ok_or(())?(r.context, buf.as_ptr(), n) };
        check(r, start)?;
        if code != 0 {
            return Err(());
        }
    }
    if length.is_some_and(|l| count != l) {
        return Err(());
    }
    check(r, start)
}
use ureq::unversioned::transport::{Buffers, ConnectionDetails, Connector, NextTimeout, Transport};
#[derive(Debug)]
struct StallConnector;
#[derive(Debug)]
struct Stall(Box<dyn Transport>);
impl Connector<Box<dyn Transport>> for StallConnector {
    type Out = Stall;
    fn connect(
        &self,
        _: &ConnectionDetails,
        c: Option<Box<dyn Transport>>,
    ) -> Result<Option<Stall>, ureq::Error> {
        Ok(c.map(Stall))
    }
}
fn stall(mut t: NextTimeout) -> NextTimeout {
    t.after = t.after.min(Duration::from_secs(30).into());
    t
}
impl Transport for Stall {
    fn buffers(&mut self) -> &mut dyn Buffers {
        self.0.buffers()
    }
    fn transmit_output(&mut self, n: usize, t: NextTimeout) -> Result<(), ureq::Error> {
        self.0.transmit_output(n, stall(t))
    }
    fn await_input(&mut self, t: NextTimeout) -> Result<bool, ureq::Error> {
        self.0.await_input(stall(t))
    }
    fn is_open(&mut self) -> bool {
        self.0.is_open()
    }
    fn is_tls(&self) -> bool {
        self.0.is_tls()
    }
}
fn relative(encoded: &str, empty: bool) -> Result<(), ()> {
    let mut decoded = Vec::with_capacity(encoded.len());
    let mut b = encoded.bytes();
    while let Some(c) = b.next() {
        let c = if c == b'%' {
            let h = b.next().ok_or(())?;
            let l = b.next().ok_or(())?;
            let hex = |c: u8| (c as char).to_digit(16).map(|x| x as u8).ok_or(());
            let c = hex(h)? * 16 + hex(l)?;
            if c == b'/' {
                return Err(());
            }
            c
        } else {
            if !(c.is_ascii_alphanumeric() || b"/._-~".contains(&c)) {
                return Err(());
            }
            c
        };
        if c < 32 || c == 127 || b"\\?#%:".contains(&c) {
            return Err(());
        }
        decoded.push(c);
    }
    let s = text(&decoded)?;
    if s.chars().any(char::is_control)
        || (!empty && s.is_empty())
        || s.starts_with('/')
        || s.ends_with('/')
        || s.split('/')
            .any(|s| s == "." || s == ".." || (s.is_empty() && !decoded.is_empty()))
    {
        return Err(());
    }
    Ok(())
}
// Match only the protected catalog's existing canonical node prefix. Keep the
// original narrow file-route grammar unchanged after this identity fence.
fn bound_route(method: &str, path: &str, expected_node: &[u8]) -> Result<(), ()> {
    let path = if let Some(rest) = path.strip_prefix("/nodes/") {
        let end = rest.find('/').ok_or(())?;
        let id = &rest.as_bytes()[..end];
        if id != expected_node
            || id.len() != 36
            || !id.iter().enumerate().all(|(i, b)| {
                if matches!(i, 8 | 13 | 18 | 23) {
                    *b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(b)
                }
            })
            || !id.iter().any(|b| matches!(b, b'1'..=b'9' | b'a'..=b'f'))
        {
            return Err(());
        }
        &rest[end..]
    } else {
        path
    };
    route(method, path)
}
fn route(method: &str, path: &str) -> Result<(), ()> {
    let (p, q) = path
        .split_once('?')
        .map_or((path, None), |(p, q)| (p, Some(q)));
    match method {
        "GET" if p == "/v1/files" => {
            if let Some(q) = q {
                relative(q.strip_prefix("path=").ok_or(())?, true)?;
            }
            Ok(())
        }
        "GET" | "PUT" if p.starts_with("/v1/files/") => {
            relative(&p[10..], false)?;
            if q.is_some()
                && !(method == "PUT" && matches!(q, Some("overwrite=true" | "overwrite=false")))
            {
                return Err(());
            }
            Ok(())
        }
        "POST" if p == "/v1/directories" && q.is_none() => Ok(()),
        _ => Err(()),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_only_actual_file_routes() {
        assert!(route("GET", "/v1/files?path=%E8%B5%84%E6%96%99").is_ok());
        assert!(route("PUT", "/v1/files/a%20b/data?overwrite=true").is_ok());
        for p in [
            "/v1/files/%2e%2e/a",
            "/v1/files/%2fa",
            "/v1/files/a%00b",
            "/v1/files/a#x",
            "/v1/files?path=//x",
            "/v1/files/%252e%252e",
            "/v1/files/a\\b",
            "/v1/files/a?url=x",
        ] {
            assert!(route("GET", p).is_err(), "{p}");
        }
    }
}
