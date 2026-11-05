mod transfer;
use std::{
    ptr, slice, str,
    sync::Arc,
    time::{Duration, Instant},
};
pub use transfer::{os_https_transfer_v1, OsHttpsTransferRequest};
use ureq::tls::{parse_pem, PemItem, RootCerts, TlsConfig, TlsProvider};
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OsHttpsBytes {
    pub ptr: *const u8,
    pub len: usize,
}
#[repr(C)]
pub struct OsHttpsRequest {
    pub origin: OsHttpsBytes,
    pub ca_pem: OsHttpsBytes,
    pub method: OsHttpsBytes,
    pub path: OsHttpsBytes,
    pub body: OsHttpsBytes,
    pub bearer: OsHttpsBytes,
}
pub const OS_HTTPS_ERROR: i32 = -1;
pub const MAX_RESPONSE: usize = 1024 * 1024;
/// # Safety
/// All non-null pointers must refer to valid, aligned, disjoint live allocations.
/// Input bytes are borrowed for the duration of the synchronous call. Output
/// buffers and scalars must be writable and must not overlap inputs or each other.
#[no_mangle]
pub unsafe extern "C" fn os_https_request_v1(
    r: *const OsHttpsRequest,
    out: *mut u8,
    cap: usize,
    status: *mut u32,
    node: *mut u8,
    hcap: usize,
    hlen: *mut u32,
) -> i32 {
    std::panic::catch_unwind(|| {
        if r.is_null()
            || out.is_null()
            || cap < MAX_RESPONSE
            || status.is_null()
            || hlen.is_null()
            || (node.is_null() && hcap != 0)
            || (!node.is_null() && hcap < 64)
        {
            return OS_HTTPS_ERROR;
        }
        // SAFETY: caller guarantees validity of all non-null pointers.
        let result = unsafe { perform(&*r) };
        match result {
            Ok((s, body, header)) => {
                unsafe {
                    ptr::copy_nonoverlapping(body.as_ptr(), out, body.len());
                    if !node.is_null() {
                        ptr::copy_nonoverlapping(header.as_ptr(), node, header.len());
                    }
                    *status = s;
                    *hlen = header.len() as u32;
                }
                body.len() as i32
            }
            Err(()) => OS_HTTPS_ERROR,
        }
    })
    .unwrap_or(OS_HTTPS_ERROR)
}

unsafe fn borrow<'a>(b: OsHttpsBytes, max: usize) -> Result<&'a [u8], ()> {
    if b.len > max || (b.ptr.is_null() && b.len != 0) {
        return Err(());
    }
    if b.len == 0 {
        return Ok(&[]);
    }
    Ok(unsafe { slice::from_raw_parts(b.ptr, b.len) })
}
fn text(b: &[u8]) -> Result<&str, ()> {
    str::from_utf8(b).map_err(|_| ())
}
unsafe fn perform(r: &OsHttpsRequest) -> Result<(u32, Vec<u8>, Vec<u8>), ()> {
    let started = Instant::now();
    let origin = text(unsafe { borrow(r.origin, 2048)? })?;
    let ca = unsafe { borrow(r.ca_pem, 256 * 1024)? };
    let method = text(unsafe { borrow(r.method, 6)? })?;
    let path = text(unsafe { borrow(r.path, 2048)? })?;
    let body = unsafe { borrow(r.body, 16384)? };
    let bearer = text(unsafe { borrow(r.bearer, 43)? })?;
    if !matches!(method, "GET" | "POST" | "DELETE") {
        return Err(());
    }
    if !bearer.is_empty()
        && (bearer.len() != 43
            || !bearer
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
    {
        return Err(());
    }
    // Authority only; never normalize a user-info, path, query or fragment away.
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
    let (route, query) = path
        .split_once('?')
        .map_or((path, None), |(p, q)| (p, Some(q)));
    if let Some(query) = query {
        if method != "GET" || route != "/control/v1/me/nodes" {
            return Err(());
        }
        if query != "limit=100" {
            let cursor = query.strip_prefix("limit=100&cursor=").ok_or(())?;
            if cursor.len() != 36
                || !cursor.bytes().enumerate().all(|(i, b)| {
                    if matches!(i, 8 | 13 | 18 | 23) {
                        b == b'-'
                    } else {
                        b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                    }
                })
                || !cursor
                    .bytes()
                    .any(|b| matches!(b, b'1'..=b'9' | b'a'..=b'f'))
            {
                return Err(());
            }
        }
    }
    if !route.starts_with('/')
        || route.starts_with("//")
        || !route
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-~".contains(&b))
        || route.split('/').any(|p| p == "." || p == "..")
    {
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
    let remaining = Duration::from_secs(5)
        .checked_sub(started.elapsed())
        .ok_or(())?;
    let agent = ureq::Agent::config_builder()
        .https_only(true)
        .proxy(None)
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_global(Some(remaining))
        .max_response_header_size(16384)
        .max_idle_connections(0)
        .tls_config(tls)
        .build()
        .new_agent();
    let request = ureq::http::Request::builder()
        .method(method)
        .uri(format!("{origin}{path}"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        // Fixed protocol metadata, not authority; required by Node lease v2.
        .header("X-OrangeSpace-Lease-Schema", "2");
    let request = if bearer.is_empty() {
        request
    } else {
        request.header("Authorization", format!("Bearer {bearer}"))
    };
    let request = request.body(body).map_err(|_| ())?;
    let mut response = agent.run(request).map_err(|_| ())?;
    let status = response.status().as_u16() as u32;
    if status != 204 {
        let mut types = response.headers().get_all("Content-Type").iter();
        let kind = types.next().ok_or(())?.as_bytes();
        if types.next().is_some()
            || !matches!(
                kind,
                b"application/json" | b"application/json; charset=utf-8"
            )
        {
            return Err(());
        }
    }
    let mut headers = response.headers().get_all("X-OrangeSpace-Node").iter();
    let header = headers
        .next()
        .map(|h| h.as_bytes().to_vec())
        .unwrap_or_default();
    if headers.next().is_some()
        || header.len() > 64
        || !header
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(b))
    {
        return Err(());
    }
    let bytes = response
        .body_mut()
        .with_config()
        .limit((MAX_RESPONSE + 1) as u64)
        .read_to_vec()
        .map_err(|_| ())?;
    if bytes.len() > MAX_RESPONSE {
        return Err(());
    }
    if started.elapsed() >= Duration::from_secs(5) {
        return Err(());
    }
    Ok((status, bytes, header))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn null_request_fails_without_publishing() {
        let mut out = vec![0xA5; MAX_RESPONSE];
        let mut head = [0xA5; 64];
        let mut status = 0x1234;
        let mut hlen = 0x5678;
        let code = unsafe {
            os_https_request_v1(
                ptr::null(),
                out.as_mut_ptr(),
                out.len(),
                &mut status,
                head.as_mut_ptr(),
                head.len(),
                &mut hlen,
            )
        };
        assert_eq!(code, OS_HTTPS_ERROR);
        assert_eq!(status, 0x1234);
        assert_eq!(hlen, 0x5678);
        assert!(out.iter().all(|x| *x == 0xA5));
        assert_eq!(head, [0xA5; 64]);
    }
}
