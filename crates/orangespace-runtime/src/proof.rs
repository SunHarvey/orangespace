use orangespace_core::Binding;
use serde::Deserialize;
use std::io::Read;

/// Narrow HTTP/1 response parser: no redirects, TE, compression, duplicate
/// framing, unbounded headers/body, unknown proof fields, or trailing bytes.
/// The request asks for Connection: close; EOF is part of accepted framing.
pub(crate) fn verify_http(
    reader: &mut impl Read,
    binding: Binding,
    expected: &str,
) -> Result<(), ()> {
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        if headers.len() >= 8192 {
            return Err(());
        }
        let mut byte = [0];
        reader.read_exact(&mut byte).map_err(|_| ())?;
        headers.push(byte[0]);
    }
    let text = std::str::from_utf8(&headers).map_err(|_| ())?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    let status = lines.next().ok_or(())?;
    if !["HTTP/1.1 200", "HTTP/1.0 200"]
        .iter()
        .any(|prefix| status == *prefix || status.starts_with(&format!("{prefix} ")))
    {
        return Err(());
    }
    let mut length = None;
    let mut content_type = false;
    for (n, line) in lines.enumerate() {
        if n >= 32 {
            return Err(());
        }
        let (name, value) = line.split_once(':').ok_or(())?;
        if name.is_empty()
            || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
            || value.bytes().any(|c| c < 32 && c != b'\t' || c == 127)
        {
            return Err(());
        }
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "content-length" => {
                if length.is_some()
                    || value.is_empty()
                    || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(());
                }
                let size = value.parse::<usize>().map_err(|_| ())?;
                if size > 2048 {
                    return Err(());
                }
                length = Some(size);
            }
            "transfer-encoding" | "content-encoding" => return Err(()),
            "content-type" => {
                if content_type || value != "application/json" {
                    return Err(());
                }
                content_type = true;
            }
            _ => {}
        }
    }
    if !content_type {
        return Err(());
    }
    let mut body = vec![0; length.ok_or(())?];
    reader.read_exact(&mut body).map_err(|_| ())?;
    let mut extra = [0];
    if reader.read(&mut extra).map_err(|_| ())? != 0 {
        return Err(());
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Proof {
        tunnel_id: String,
        proof: String,
    }
    let proof: Proof = serde_json::from_slice(&body).map_err(|_| ())?;
    if proof.tunnel_id != binding.tunnel_id.to_string() || proof.proof != expected {
        return Err(());
    }
    Ok(())
}
