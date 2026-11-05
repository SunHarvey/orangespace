# Production TUIC private-CA bridge (bounded slice)

`os_runtime_new_with_ca_v1(path, path_len, timeout_ms, ca, ca_len)` is a private
in-process Service constructor, not IPC. It copies 1..65536 UTF-8 PEM bytes
before publishing its handle. Null, empty, oversized, NUL, non-UTF-8 or invalid
certificate framing is rejected. Full certificate parsing stays in sing-box;
malformed/untrusted certificates cannot produce verified forwarding. No retry
with system roots, insecure TLS, or trust-store installation is added.

Legacy `os_runtime_new` retains normal default TLS behavior. Core's new
`TunnelSettings.certificate: Option<String>` defaults to None for old serde
inputs and is emitted as TLS `certificate` only when explicitly supplied. It
travels with existing config via private stdin, never a new file/argv/env.

WindowsBackend reads only `TrustedCatalog::federation_node(binding.node).ca_pem`,
checks the returned node identity, and confines each reserved realm to its
initial node. The static protected catalog already owns an immutable snapshot;
no SDK accessor change was needed. UI, lease and central response cannot supply
this trust. Original HTTP/common-clock budgets, ACK, renewal, and helper
lifecycle are unchanged.

## Executed evidence

Strict RED→GREEN: core missing field; runtime missing production constructor;
exact C++ backend injection rejected missing static CA propagation. Ordinary
core/runtime tests and Clippy passed. All 13 opt-in runtime Go/TUIC tests passed,
including the new production ABI matrix: correct CA succeeds; wrong CA, absent
CA (legacy constructor), and wrong TLS name reject with zero probe requests.
The matrix mutates the caller's CA after construction to check snapshot ownership;
free/failed-proof cleanup leaves no returned root PID or SOCKS listener.
These tests reuse the real existing TUIC node/probe fixture, not ordinary TLS or
`test_certificate` overrides. Existing test-only overrides are unchanged.

Approved Linux helper SHA-256:
`1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a`.

Reproduction (all builds use the shared lock and `-j1`):

```sh
export TMPDIR=/var/tmp/hermes-runtime/tmp
flock "$TMPDIR/orangespace-build.lock" cargo test -p orangespace-core -p orangespace-runtime --offline --locked -j1
ORANGESPACE_TEST_SING_BOX=/var/tmp/hermes-runtime/tmp/orangespace-dev-delivery-ixrznt39/node-runtime-dependency/sing-box \
  flock "$TMPDIR/orangespace-build.lock" cargo test -p orangespace-runtime --offline --locked -j1 -- --ignored --test-threads=1
flock "$TMPDIR/orangespace-build.lock" python3 apps/windows-service/tests/tuic_private_ca_tests.py "$TMPDIR/tuic-private-ca-bridge"
```

GNU Windows Service compilation/linking passed against the single unified runtime
archive (which also exports HTTPS). Portable CMake tests: 19 passed, one real-ABI
fixture skipped because its archive environment variable was not configured.
C++ injected evidence and GNU PE linkage are not native Windows HTTPS/SCM/WFP
acceptance. Parent independent review, final unified three-PE rebuild, and native
acceptance remain required. No remote, DB, SCM, system trust or commit changes.
