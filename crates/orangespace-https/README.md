# Narrow app-CA HTTPS C ABI

`include/orangespace_https.h` is the integration contract. `OsHttpsRequest` contains
six borrowed `{const uint8_t*, size_t}` slices, in order: origin, ca_pem, method,
path, body, bearer. Link `liborangespace_https.a`; the symbol is
`os_https_request_v1`. There is no allocator/free ABI and no size-query request.
Caller supplies 1 MiB response and 64-byte node-header storage. All negative
results are the single generic `-1`; outputs remain unchanged on any failure.
4xx/5xx are successful transport results preserving exact status/body. Optional
nodeHeader=NULL/headercap=0 discards the validated header. `headerLen` is required.
No trailing NUL is written. See header for pointer lifetime/non-overlap contract.

Only HTTPS with an explicit authority is accepted. PEM CA bytes are supplied by
C++; this library has no file-path, command or executable parameters. Only the
supplied CA roots are trusted; rustls verifies chain, hostname and time. No root
installation, public root fallback, native TLS, skip-verify, redirects, cookies,
proxy environment use or decompression. Each call creates a fresh agent, uses a
5-second global timeout (including DNS, TLS, headers and body), then discards it.
Origin/path <=2048 bytes, CA <=256 KiB, body <=16 KiB, response <=1 MiB, response
headers <=16 KiB. Paths reject percent escapes, backslash, fragment, absolute URLs
and dot segments. The only query exception is canonical central-node pagination
on `/control/v1/me/nodes` with validated `limit` and optional UUID `cursor`.
The caller owns JSON/schema validation;
opaque body bytes are sent as `application/json` for GET/POST/DELETE. Bearer is
empty or 43 ASCII URL-safe characters. Node header may be absent; duplicate or
comma-combined values, invalid characters and values over64 bytes are rejected.

## Dependencies and MSRV

This crate is a member of the repository root workspace. Build from the root and
use the committed root `Cargo.lock`; a nested lock or old standalone target is not
an input to the development packages. The workspace toolchain floor is Rust 1.89.

- `ureq =3.3.0`: defaults disabled, only `rustls-no-provider` enabled; MSRV1.85.
- `rustls =0.23.35`: defaults disabled, only `std,ring,tls12` enabled; MSRV1.71.
- Explicit ring0.17.14 provider; no aws-lc, system roots, webpki-roots or cookies.
- The crate's standalone manifest declares MSRV1.85, and an earlier standalone
  test passed on 1.85. That historical result does not lower the integrated
  workspace's 1.89 minimum or validate its root lock on 1.85.
- Official primary references checked: versioned docs.rs pages for ureq
  `tls::RootCerts`, `config::ConfigBuilder`, and rustls `RootCertStore`; downloaded
  official crate Cargo manifests/features and ureq tls/rustls.rs were inspected.
  Specific roots construct `RootCertStore::empty()` and add only provided certs.

## Verified outputs and commands

From the repository root, set `TMPDIR=/var/tmp/hermes-runtime/tmp` and run
`cargo test -p orangespace-https --locked -j1`. The real TLS fixture is checked in
at `tests/tls_fixture.py` and needs Python 3 and OpenSSL in PATH. Use the shared
`/var/tmp/hermes-runtime/tmp/orangespace-build.lock` when coordinating with other
builds. Old standalone `tests/verify.sh` and generated logs are not build inputs.

- Linux staticlib/rlib: `target/release/liborangespace_https.{a,rlib}`.
- Windows GNU staticlib/rlib:
  `target/x86_64-pc-windows-gnu/release/liborangespace_https.{a,rlib}`.
- Actually linked C ABI binaries: `target/ffi-smoke`, `target/ffi-smoke.exe`.
- Windows native link dependencies reported by rustc:
  `-lbcrypt -ladvapi32 -lkernel32 -lntdll -luserenv -lws2_32 -ldbghelp`.
- Earlier standalone SHA256SUMS/build logs are retained operator evidence, not
  repository files required by a clean checkout. New packages carry their own
  source commit, dependency versions and payload hashes.
- TDD evidence: red/green null-request, actual TLS positive, duplicate-header;
  inclusive 1MiB boundary regression initially failed and was fixed to permit
  exactly1MiB while rejecting1MiB+1.
- Current tests: 1 Rust unit +12 real TLS integration tests; independent OpenSSL ephemeral
  roots and Python TLS server, positive/private CA, wrong CA, wrong hostname,
  expired leaf, duplicate/comma header, body bounds, global header/body deadlines,
  401 exact body/status, 302 not followed, empty204, centre header absent, all
  methods/JSON bodies, invalid origins/paths/tokens. Proxy env points at a dead
  local port during tests; real TLS still succeeds. Linked C harness checks
  malformed pointer/length descriptors, caps, atomic unchanged outputs, real401
  exact body/status, optional node output, and empty stderr/no secrets printed.

These local TLS tests do not establish Windows GUI, MSVC, production endpoint or
full C++ bridge acceptance; those remain separately evidenced parent gates. Unwinding
panics cannot cross FFI; abort/OOM and invalid caller pointers are not recoverable.
The library installs no global panic hook/logger; a host-installed panic hook
retains its own behavior. No production trust settings or existing code changed.
