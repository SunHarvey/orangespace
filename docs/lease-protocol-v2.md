# Lease protocol v2 — approved implementation contract

## Historical integrated development evidence (not all code published)

This server-source milestone includes the Node half of this contract. The corresponding C++/Rust service-runtime changes remain local work in progress; the retained Windows development candidate described below is not an installed release or a claim that those changes are present in this published Git tree.

The coordinated v2 Node update and an unsigned GNU Windows development candidate have passed one real same-authorization, same-node, two-sandbox service-chain case. The case exercised public HTTPS authentication, interactive-user DPAPI save/restore, LocalSystem service authorization, both helpers' authenticated forwarding establishment, stopping A while B remains live, and rejection of stale authorization after logout. Native and controller exit codes were both zero. Separate post-case Windows and Linux readbacks confirmed exact fixture/credential cleanup, zero test database rows and no remaining node helper children.

This closes that positive chain slice, not the complete first phase, a signed release, cross-user/expiry/crash acceptance, two physical egresses, managed DNS, WFP isolation or browser readiness. Browser startup remains denied; publication is not yet verified.

Scope: approved plan B fixes short-lease clock skew without changing OS clocks, shortening configured server leases, adding skew tolerance, or opening browser/WFP gates. Existing unrelated WIP and security fixes must be preserved. Protocol v1 and v2 must not silently interoperate.

## Node HTTPS protocol

- Creating a tunnel (`POST /v1/tunnels`) and renewing it (`POST /v1/tunnels/{id}/renew`) require the exact request header `X-OrangeSpace-Lease-Schema: 2`. Missing/other versions fail closed with HTTP 426 before generation reservation, child creation, or renewal mutation. Login/session/logout/revoke/probe/file routes are unchanged.
- Add exactly `lease_schema: 2` and integer `remaining_ttl_ms` to each successful lease response. Creation therefore has exactly 17 fields; renewal has exactly 5. Existing tuple, node header, expiry, and secret-relation checks remain mandatory. Reject old/missing/extra/wrong-type schema fields; do not invent fallback TTLs.
- `remaining_ttl_ms` is a conservative downward-rounded positive integer in 1..30000. Compute it only after successful child startup/renewal, immediately before returning, under the existing authority/operation boundary. It is no greater than each of: live lease monotonic remaining lifetime, node wall-clock remaining lifetime to `expires_at`, authenticated session wall-clock remaining lifetime, and 30 seconds. Never return configured lease duration as remaining lifetime. Exhausted/zero budgets fail closed, retaining existing exact-child cleanup guarantees.
- Keep `expires_at` in the node's time domain and bounded by its authenticated session expiry. Do not rewrite timestamps into a client time domain. Keep node-side expiration and revocation enforcement.

## Client budget and common monotonic clock

Capture `request_started_ms` immediately before the actual creating/renewing HTTP operation, after preceding session revalidation. At receipt derive `deadline_ms = request_started_ms + remaining_ttl_ms` using checked arithmetic. Reject if the budget has already expired. Preserve that same deadline through service queueing, FFI admission, proof completion and runtime polling; never restart it at receipt or FFI entry and never re-anchor cached replies.

The deadline is expressed in an explicitly named OS monotonic clock, not raw C++ `steady_clock` or Rust `Instant` representations:

- Windows: `clock = "windows-gettickcount64-ms-v1"`, using `GetTickCount64` in both languages.
- Linux test/runtime: `clock = "linux-clock-monotonic-ms-v1"`, using `clock_gettime(CLOCK_MONOTONIC)` converted downward to milliseconds in both languages.
- Reject mismatched/unsupported clock names. All integer JSON timing fields must be exact, nonnegative and <= 9007199254740991; use overflow-checked arithmetic. TTL must be positive and <=30000, start <= current clock, and deadline strictly greater than current clock. Equality at deadline is expired.

Budget JSON object (exactly four fields):

```json
{"clock":"windows-gettickcount64-ms-v1","request_started_ms":100000,"remaining_ttl_ms":29000,"deadline_ms":129000}
```

The numbers above are illustrative format data, not acceptance results. Validate `deadline_ms == request_started_ms + remaining_ttl_ms`. For a start request the budget TTL must exactly equal the authenticated node lease's `remaining_ttl_ms`.

Replace cross-host `expires_at - client_wall <= 30` checks with the authenticated budget. Lease epoch values must remain positive and bounded by authenticated server session expiry where available; do not use client wall time to derive lease lifetime. Existing session wall-clock rejection remains an additional conservative veto; this is not a redesign of session clock handling.

Use typed, owned timing results internally so the service cannot lose a request's time anchor or recover it from a cached reply. Preserve secret ownership/wiping and prepared reply/ACK boundaries. No credential enters argv/environment/log/plaintext storage.

## Private runtime JSON dispatch schema 2

C ABI function signatures remain unchanged; explicitly document JSON dispatch schema 2 in `orangespace_runtime.h`. Every request requires `schema: 2`, including close/poll; missing/old schemas are rejected without work, not translated.

- Start: exactly `schema`, `op`, `binding`, `lease`, `budget`; `lease` is the unchanged authenticated node v2 response (17 fields).
- Renew: exactly `schema`, `op`, `binding`, `expires_at`, `budget`.
- Close: exactly `schema`, `op`, `binding`.
- Poll: exactly `schema`, `op`.

The runtime validates the common clock and original budget on admission and immediately before publication. Convert remaining common-clock time into local I/O waits without assuming `Instant` shares an epoch. Retain the absolute common-clock deadline as an authoritative fence throughout active lifetime; wall-clock jumps cannot extend it.

Renew only a live exact binding whose OLD deadline has not expired. Reject expiry regression. The effective new deadline is no later than both the new request's original `deadline_ms` and `old_deadline_ms + (new_server_expiry - old_server_expiry)*1000`, with checked arithmetic. Equal server expiry never grants more local lifetime. Recheck liveness, old deadline, new deadline and exact tuple after blocking work. Expired/closed/switched/revoked bindings and late replies never resurrect.

The logical deadline is an authorization bound; it is not a promise of precisely timed kernel process termination between polls.

## Ownership of implementation slices

- Node owner: Python lease issuing/renewal routes, manager and relevant Python tests/docs only.
- C++ owner: node session client/header, service chain/backend, C++ active tests and necessary native-diagnostic callers only. No Rust/Python/CMake workflow ownership.
- Runtime owner: Rust runtime/validation/proof tests and private C header; minimal monotonic-clock platform support only. No C++/Python ownership. Do not change Cargo.lock without notifying parent.
- Parent owns this contract, integration/build/deployment evidence and coordinated native acceptance. Do not edit paused guardian/updater/fixed4 tools to make them pass.

## Required evidence before coordinated deployment

TDD per defect; subsecond positive/negative wall skew and integer boundaries; zero/missing/too-large/noninteger TTL; old schemas; short sessions; helper startup consuming TTL; response/queue/FFI/proof budget exhaustion; clock mismatch/overflow; equal/backward renewal expiry; renewal at/after old deadline; late close/switch/revoke; wrong node/user/tuple. Preserve prior sticky allocation/receipt/ACK regressions and all browser denials.

Independent review plus source/build pinning precedes deployment. Coordinate both test nodes and Windows components; keep original 8080 service, SSH, unrelated services, TLS trust/DNS/firewall and source history unchanged. Do not run known-broken staging rollback operators. Real Windows two-sandbox success and precise cleanup, not model/compile output, determine closure of the failed native slice.
