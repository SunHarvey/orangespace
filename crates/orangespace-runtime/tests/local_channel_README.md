# Explicit mixed helper / Service-private channel v1

This freezes the new ABI for the bounded prototype Service adapter. It is not
public IPC, Node authentication, browser authorization, WFP containment or a
replacement for OS peer/root/instance-bound admission. The Service still verifies
its fixed target-platform helper pin and protected installation before constructing
or calling this library. The Linux ELF fixture must never replace the Windows pin.

## Constructor

`os_runtime_new_with_local_proxy_v1(path,path_len,start_timeout_ms,ca,ca_len,protocol)`

- Protocol `0` is legacy authenticated SOCKS; `1` is authenticated mixed
  HTTP/CONNECT plus SOCKS on one `127.0.0.1` port, with `set_system_proxy=false`.
  Every other integer rejects with null. Selection is immutable, typed through
  Runtime -> HelperSupervisor -> actual stdin config, never lease/start JSON.
- `ca=NULL,ca_len=0` retains normal system TLS verification. Otherwise use the
  existing 1..65536-byte protected-catalog PEM validation/copy contract. No CA
  paths or TLS bypass. Existing constructors and start wrappers default to SOCKS.
- Existing startup/lease budgets, exact-child Jobs, TUIC-only outbound, proof,
  cleanup and no retry/no direct fallback behavior remain unchanged.

## Once-only private handoff

`os_runtime_take_local_channel_v1(handle,binding_json,binding_len,out,capacity)`

Input is **only** the existing full five-field tuple, not a schema envelope:

```json
{"user_id":"11111111-1111-4111-8111-111111111111","sandbox_id":"22222222-2222-4222-8222-222222222222","node_id":"33333333-3333-4333-8333-333333333333","generation":1,"tunnel_id":"44444444-4444-4444-8444-444444444444"}
```

These are documentation placeholders, never real deployment identities. UUIDs must
be canonical, nonzero, unescaped strings; generation an exact integer 1..2^53-1.
Duplicate/unknown/missing fields, schema wrappers, floating generations and trailing
JSON reject. Input length is 1..4096. Output capacity must be at least **4096**,
checked before any ownership mutation; no size-query or partial-output mode.

Successful output has exactly these fields (illustrative placeholders only):

```json
{"schema":2,"binding":{"user_id":"11111111-1111-4111-8111-111111111111","sandbox_id":"22222222-2222-4222-8222-222222222222","node_id":"33333333-3333-4333-8333-333333333333","generation":1,"tunnel_id":"44444444-4444-4444-8444-444444444444"},"host":"127.0.0.1","port":19080,"username":"DOCUMENTATION_ONLY","password":"DOCUMENTATION_ONLY","clock":"windows-gettickcount64-ms-v1","request_started_ms":1000,"remaining_ttl_ms":30000,"deadline_ms":31000,"proof_observed_at_ms":1500}
```

Windows clock is GetTickCount64 (`windows-gettickcount64-ms-v1`); Linux is floored
CLOCK_MONOTONIC (`linux-clock-monotonic-ms-v1`). Start's original request anchor,
TTL and deadline are preserved (`deadline_ms=request_started_ms+remaining_ttl_ms`).
Renewing the helper does **not** extend this private channel grant's deadline.
A late take rejects without cancelling an independently renewed healthy helper.
No TUIC password/UUID, CA, probe secret or API bearer is included.

A take requires the exact active binding, current owned helper root alive, original
grant unexpired, and the last successful actual SOCKS/TUIC forwarding proof strictly
less than 3000 ms old. This is a fresh historical establishment observation, not
continuous forwarding or OS network-isolation proof. A failed probe clears proof
eligibility. Fresh proof may restore eligibility before the original deadline,
never reset that deadline or an already consumed take.

Return is a positive exact UTF-8 byte length, without NUL; `-1` invalid/ineligible,
`-2` short capacity, `-3` stale/unknown handle, `-4` failed closed. Error leaves caller
output untouched. Complete serialization into fixed guarded storage, capacity checks
and the final exact-root/lease/original-grant/proof-age fence precede consumption
and copy under the same runtime lock. Successful take consumes only the per-binding
Service-copy flag; internal probe credentials remain available for proof/renewal.
Close/expiry/exit destroys the exact context. No wrong/stale tuple can select a newer
context. General dispatch/start/probe/poll/diagnostics remain credential-free.

The caller exclusively owns successful secret output and must use guarded Service
storage, authorize the OS peer/root and exact instance separately, deliver only over
that protected IPC channel, and wipe output after use. Failed delivery does not allow
another take; close/revoke the provisional binding instead of retrying/reanchoring.
Do not log, persist, place in argv/environment or serialize into general status.

The dedicated successful parse + serialization + handoff path performs no heap
allocation (observed with the Rust test allocator, also exercised under sticky
thread-local heap denial with an actual allocation-failure positive control); borrowed fields go directly into
a 4096-byte guarded buffer, not a secret-bearing JSON Value/String/Vec. Owned context
strings and temporary output/SOCKS-auth buffers are explicitly overwritten on drop.
This is not a claim of physical erasure of all earlier core/serde/helper copies;
existing core configuration/lease allocator-copy limitations remain. Process-wide
allocation abort and invalid C memory cannot be recovered by catch_unwind.

## Local verification

```sh
cargo test -p orangespace-core -p orangespace-runtime --locked
cargo clippy -p orangespace-core -p orangespace-runtime --all-targets --locked -- -D warnings
ORANGESPACE_TEST_SING_BOX=/absolute/archive-verified/linux/sing-box \
  cargo test -p orangespace-runtime --locked local_channel_tests -- --ignored
```

The local fixture uses actual verified sing-box 1.14.4, generated disposable CA/TUIC
credentials, local-only TUIC Node and probe listeners. It exercises the actual new C
ABI, exact mismatched tuples, invalid JSON, short capacity/no consumption, one success,
repeat rejection, close/expiry/stale handle, exited owned helper, proof freshness/failure, original immutable
deadline across helper renewal, HTTP CONNECT 407 without/wrong credentials and 200 plus
actual TUIC proof with the returned credentials. Subsequent SOCKS/TUIC proof survives
the take. The allocation observer first found eight successful-handoff allocations;
borrowed canonical binding parsing removed them. These are Linux ELF/local-process
results, not Windows mixed-helper execution, Service IPC, CEF or WFP acceptance.

The Linux asynchronous-exit fixture waits with non-reaping `waitid(WNOWAIT)` before
calling take; `/proc/<pid>/stat` root state Z was observed before the multithreaded
Go process became waitable, and was not a sufficient completed-exit witness. This
fixture correction does not change production poll/Job/liveness behavior.
