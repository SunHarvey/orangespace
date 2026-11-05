# Service-owned Rust runtime (private static C ABI)

This library owns `orangespace_core::helper::HelperSupervisor` and never opens a browser or grants browser/network-isolation readiness. Its only executable path comes from the privileged service constructor, **not public IPC**. All API operations are private, in-process calls from that service.

## Trust and lifetime contract

Before construction, the service verifies the fixed approved helper hash and protects the executable, ancestor directories, dependencies and system trust roots against replacement for the entire runtime lifetime. Rust's `TrustedExecutable` only canonicalizes an absolute regular-file path; it does **not** validate Windows ACLs or close a replacement race. The service authenticates the node session, derives identity from that session, authorizes the complete binding and validates the node catalogue before delivering an API lease transiently. Matching a caller-supplied `user_id` is not authentication.

Each start requires the exact node API lease schema and exact `(user_id,sandbox_id,node_id,generation,tunnel_id)` equality. UUIDs are canonical/nonzero; generations are integers `1..2^53-1`; `lease_schema` must be exactly integer 2, `remaining_ttl_ms` must be integer `1..30000`, and the positive server-domain epoch must be at most `2^53-1`. The runtime does not compare node lease epochs to the client wall clock; the authenticated service remains responsible for the server-session expiry bound. Endpoints must be literal IPs; TLS identity must be a DNS name or the endpoint's matching canonical IP-SAN identity, with certificate verification always enabled. Only the node's `127.0.0.1` probe target is accepted. A caller cannot supply a CA path, local SOCKS credentials or an executable through dispatch JSON. Production private-CA nodes use `os_runtime_new_with_ca_v1`: the service supplies 1..65536 PEM bytes from the immutable protected catalog entry for the bound node. The constructor copies the CA before publishing the handle; only helper stdin receives it. No system trust modification or insecure fallback is needed or permitted. One runtime remains confined to that catalog node.

A fresh ephemeral loopback SOCKS port and independent CSPRNG-backed local username/password are generated per start. Configuration goes through the existing supervisor's private stdin, never argv/environment/files/logs. Credentials are not returned. This is transient privileged memory, not a guarantee that every allocator copy in the existing core or JSON library is zeroized.

After stdin delivery, the runtime authenticates SOCKS, sends a TCP CONNECT **through its TUIC-only outbound** to the node loopback API, and issues `POST /v1/tunnels/{tunnel_id}/probe` with `X-OrangeSpace-Probe: <probe_request>`. There is no API bearer on this request. The expected `probe_response` is never sent. Success requires HTTP 200, bounded unambiguous Content-Length framing, JSON with exactly `tunnel_id` and `proof`, exact tunnel/expected-secret equality, EOF, a still-live owned helper, and a still-valid lease. Headers are bounded to 8192 bytes/32 fields, body to 2048 bytes; redirects, chunking, content encoding, duplicate framing and trailing bytes are rejected. A single monotonic deadline bounds socket work even if a peer drips bytes.

`process_started` only means spawn/stdin succeeded. `tunnel_authenticated` and `forwarding_verified` are established by the authenticated node proof, not a local SOCKS handshake or stdin delivery; both remain false without that proof. `running` is true only on that verified path. Proof failure synchronously closes/reaps that helper before returning `ok:false`. A cleanup/lifecycle error returns a generic negative code and invalidates/drops the complete runtime instead of publishing a false state.

The service must serialize authorization and runtime lifecycle calls, call `poll` periodically, revoke grants/local authentication on returned exact exit tuples or lifecycle errors, and maintain durable generation/tunnel replay policy across runtime/service restarts. Runtime tombstones last only for one instance. Private `renew` accepts only an exact live, unexpired binding and an expiry from the service's successfully validated node API renewal. It cannot revive an expired/closed binding, exceed a 30-second TTL, or gain extra time from a clock rollback or repeated identical expiry. Renewal is lease metadata, not a new forwarding proof. Poll detects natural exits and expires helpers using the original common-OS-clock deadline; exits detected by renewal remain queued for one subsequent poll. Local cleanup is polling, not an autonomous scheduler.

Runtime limits: 64 handles/process, 64 active helpers/runtime, 4096 attempted starts/runtime, request/output 65536 bytes. Exceeding the attempt budget requires authenticated service-owned teardown/reconstruction; no tombstones are evicted to permit replay.

## ABI and ownership

The authoritative header is `include/orangespace_runtime.h`:

```c
void* os_runtime_new(const uint8_t* path, size_t path_len, uint32_t timeout_ms);
void* os_runtime_new_with_ca_v1(const uint8_t* path, size_t path_len,
    uint32_t timeout_ms, const uint8_t* ca, size_t ca_len);
int32_t os_runtime_call(void* handle, const uint8_t* request, size_t len,
                        uint8_t* out, size_t capacity);
void os_runtime_free(void* handle);
```

`timeout_ms` is `1..30000`; path is bounded absolute UTF-8, without a terminator. New returns null on failure. Calls require output capacity **at least 65536 before any side effects**; there is no size-query or partial-output mode. Positive return values are exact JSON byte counts, without NUL; negative values are generic: `-1` invalid request/binding, `-2` capacity, `-3` unknown/freed handle, `-4` failed closed. The caller owns valid, non-overlapping request/output ranges throughout the call and wipes the incoming lease buffer afterwards. No function formats secret-bearing inputs or parser/OS errors into diagnostics.

Handles are monotonically issued, never-reused opaque tokens, not dereferenced Rust pointers. Unknown/stale/double-free tokens are safe. A registry and per-runtime mutex serialize access; concurrent free waits for in-flight runtime operations, including another free. Poison or caught panic invalidates the slot and drops its supervisor; mutated state is never resumed. Unwinds are caught at all three C entry points, with an additional catch while holding the runtime mutex. Host process panic hooks are not replaced: callers must not install hooks that dump privileged memory. Allocation abort, `panic=abort`, invalid C memory and native process death are not recoverable unwinds.

Core helper limitations remain: OS spawn/native-call latency is not a hard real-time bound; supervisor Drop bounds waiting and can transfer an uninterruptible child to a waiter. The service must retain the outer kill-on-close Job for crash coverage and existing protected foreground-helper deployment assumptions. Existing per-helper Windows single-member Jobs remain unchanged. This crate adds no direct fallback, browser features, WFP/DNS containment or CEF startup permission.

Responses are documented in the header. Start includes only flags, full binding, helper PID and local SOCKS port; close requires exact tuple equality and cannot stop another helper. Poll returns `{"ok":true,"exited":[{"binding":{...},"pid":123}]}` and consumes each event once. Caller must treat all results as snapshots, not future process-liveness guarantees.

## Build/link

The root workspace and `Cargo.lock` include this crate and `orangespace-https`.
The runtime static archive re-exports the HTTPS ABI, so the production service
links one runtime archive. Platform clock calls live entirely in this crate using
native C/system ABIs. Core's absolute I/O deadline API does not change Windows
Job/root ownership. Use the root lock and Rust 1.89 or newer; do not use a nested
standalone lock or generated target directory as a source dependency.

```sh
cargo build -p orangespace-runtime --release --locked
cargo rustc -p orangespace-runtime --release --locked --lib -- --print native-static-libs
```

Crate/library names are `orangespace-runtime` / `orangespace_runtime`; outputs include `liborangespace_runtime.a` on Linux (and GNU targets) and `orangespace_runtime.lib` for MSVC. Build the same Windows target/architecture/CRT configuration as the C++ service, point its `ORANGESPACE_RUNTIME_LIBRARY` to that static library, and include this crate's `include/`. Determine native linker libraries from the exact target/toolchain's `--print native-static-libs`; this implementation did not execute a Windows build/deployment.

The actual Linux toolchain reported:

```text
-lc -lm -lrt -lpthread -lgcc_s -lutil -lrt -lpthread -lm -ldl -lc
```

Linux C-link smoke recipe (the checked-in C fixture now sends `schema:2` and checks rejection of legacy requests):

```sh
cargo build -p orangespace-runtime --locked
cc -std=c11 -Wall -Wextra -Werror -I crates/orangespace-runtime/include \
  crates/orangespace-runtime/tests/c_abi_smoke.c target/debug/liborangespace_runtime.a \
  -lc -lm -lrt -lpthread -lgcc_s -lutil -lrt -lpthread -lm -ldl -lc \
  -o "$TMPDIR/orangespace-runtime-c-abi-smoke"
"$TMPDIR/orangespace-runtime-c-abi-smoke" /absolute/path/to/verified/sing-box
```

## Test evidence and reproducibility

Protocol-v2 RED→GREEN was observed for legacy poll acceptance, valid v2 leases with node/client wall skew, expired queued start budgets previously reaching helper work, and a real Go/TUIC successful reply still serializing/publishing after its original deadline. Additional strict-schema, exact-integer/clock/TTL boundaries and renewal arithmetic regressions cover the same contract. The previous eight real Go/TUIC tests were ported to schema 2 and original per-operation budgets, including waiting for an actual original deadline rather than forging an active deadline.

All private JSON operations now require integer `schema:2`; C symbols/signatures/error codes are unchanged. Start has exactly `schema,op,binding,lease,budget`; renew exactly `schema,op,binding,expires_at,budget`; probe exactly `schema,op,binding,budget`; close exactly `schema,op,binding`; poll exactly `schema,op`. No v1 translation is provided. The exact four-field budget, platform clock identifiers and checked equation are documented in the header. Keep the original actual HTTP operation's anchor through receipt, queueing and FFI; do not regenerate it from a cached reply.

On Windows both caller and runtime use `GetTickCount64`; on Linux both use `clock_gettime(CLOCK_MONOTONIC)` rounded downward to milliseconds. Rust `Instant` is not used as a wire clock. Socket waits are computed from remaining common-clock time before each operation. Start admission, pre-spawn preparation, proof completion, active poll and both sides of renewal's helper poll retain the absolute deadline. Typed reply ownership retains a publication fence through FFI output serialization; the exact root and deadline are checked again before the byte copy. Renew publication also retains the OLD live deadline, not only the newly calculated deadline. Server epoch is used only for positive trusted metadata and renewal increment limits, never to derive client lifetime. Equal expiry never extends; expired, closed, superseded or exited bindings cannot revive.

**Core I/O boundary:** `HelperSupervisor::start` remains the source-compatible fixed-timeout wrapper. Runtime uses `start_until` with one absolute local `Instant` deadline, conservatively paired by sampling `Instant` **before** sampling remaining common-OS-clock time, capped by the operation timeout. Core checks that original deadline before preparation, after config preparation, before spawn, after spawn/Job assignment, in the writer immediately before delivery, immediately before its bounded receiver wait, and after delivery. The wait is at most the lesser of configured timeout and remaining original I/O budget; preparation cannot restart it. Expired precalls do not spawn or reserve core generations. Common OS D remains authoritative for proof, active lifetime and final FFI publication, not `Instant` or a C++ clock origin. Cleanup retains the existing separate kill/reap budget and exact-child ownership on uncertainty; no precisely timed kernel termination is promised.

```sh
cargo test -p orangespace-runtime --locked
cargo fmt --package orangespace-runtime -- --check
cargo clippy -p orangespace-runtime --all-targets --locked -- -D warnings
rustup run 1.89.0 cargo test -p orangespace-runtime --locked
ORANGESPACE_TEST_SING_BOX=/absolute/path/to/verified/sing-box \
  cargo test -p orangespace-runtime --offline --locked -- --ignored
```

Real tests use isolated loopback TCP/UDP listeners, fixture-only temporary OpenSSL certificates, TUIC node configuration via stdin and owned child cleanup. Supply an archive-verified sing-box 1.14.4 explicitly; no fixture silently skips as a pass when the variable is missing. The cached Linux executable was compared byte-for-byte with the archive whose SHA-256 is `699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968`.

Evidence is Linux runtime/control-plane forwarding only: actual TUIC node-loopback proof, distinct proof secrets/echo rejection, stdin-only rejection, independent A/B close, exact unexpected-exit/expiry events, failed-child reaping and real C ABI output preflight. It is not Windows native service acceptance, production node deployment, WFP/DNS isolation, browser startup or a completed delivery phase. Independent review/integrated service acceptance remains the parent's delivery gate.

### Existing-binding fresh forwarding observation (2026-11-01)

Private `probe` accepts only the full existing binding and the existing exact four-field
bounded budget. It neither starts a helper nor advances generation or lease deadline.
It repeats the same fixed Node-loopback SOCKS/TUIC HTTP proof, checking the exact
owned helper and live lease before and after network work. Each active binding retains
only its generated local port/username/password and validated fixed probe port/request/
expected response in transient privileged memory, separately from lease authority;
no full lease, TUIC password, arbitrary target, or proxy credentials are exposed.
The context is removed with the binding on close, exit or expiry (at most 64 contexts).
Existing allocator-copy/zeroization limitations above still apply.

Every structured observation contains exactly `ok`, `binding`, `process_alive`,
`forwarding_verified`, `observed_at_ms`, `lease_deadline_ms`, `expires_at` and `reason`.
A verified observation has `ok == forwarding_verified == true`; it is a snapshot,
not browser authorization. Missing/stale bindings return `not_active`; an observed
expired lease or stopped helper returns `expired` or `helper_stopped`. These absent
results have false liveness/proof and zero lease deadline/expiry. A failed network
proof with a healthy helper returns `probe_failed`, false proof, true liveness and
unchanged lease metadata, without stopping that helper.

The observation deadline stays internal: it is the minimum of the current lease
deadline, original caller budget and runtime timeout. Serialization retains both
lease and observation publication fences. Invalid schema/budgets and an expired
positive publication return Invalid without retiring a still-live lease. Actual
helper exit or lease expiry retains existing exact cleanup/event behavior. Start
and renew semantics are unchanged. Retained secret Strings are dropped with their
context, not explicitly zeroized; no guaranteed physical memory erasure is claimed.

The existing real A/B test first failed because `probe` was missing, then passed:
after exact A close it traverses actual Linux Go/TUIC again on the same B binding,
increments the Node probe counter and keeps B's PID, generation and lease deadline.
It also checks wrong/stale bindings, a deliberately wrong expected response, expired
queued budget, secret-free reply and delayed serialization rejection without B cleanup.
The wrong expected-response mutation is test-only negative injection; positive proof
and Node counter are real local network evidence. Header review and Service/SDK
integration remain separate parent work; no Windows native/GUI/SCM claim is made.

### Local v2 verification (2026-10-30)

- Stable `cargo test --offline --locked`: 13 ordinary tests passed; 12 explicitly opt-in real tests ignored in this invocation.
- Explicit archive-verified Go/TUIC invocation: all 12 opt-in tests passed, none skipped. The original eight regressions remain, plus delayed proof, delayed FFI publication, old-deadline renewal publication and cancelled-root/new-generation tests.
- `cargo fmt --package orangespace-runtime -- --check`, explicit rustfmt of the included renewal tests, and all-target `cargo clippy --offline --locked -- -D warnings` passed.
- Installed Rust 1.89.0 `cargo test --offline --locked`: 13 passed (12 opt-in tests separately exercised on stable).
- Linux static C-link smoke previously passed using a scratch-only v2 copy; the parent has since ported the checked-in C fixture to v2, including explicit legacy rejections. This fixcycle does not own that C source.
- No Windows build/run, remote request, dependency install, lockfile edit, browser/WFP enablement or phase-completion claim.

### Bounded stdin-deadline fixcycle (2026-10-30)

- A real re-executed controlled child never reads stdin; a validated 512 KiB settings payload (serialized config below 1 MiB) fills its pipe. The fixed-timeout RED took 3.031 seconds. With an original 250 ms absolute I/O budget, ten consecutive GREEN runs returned in approximately 253 ms, reaped the exact child (socket termination plus Linux `/proc` absence), and kept an unrelated owned binding alive. The witness socket carries only the child PID, never credentials; the child has no timed self-exit.
- Expired precall and preparation-exhaustion regressions fail on the unchanged fixed-timeout wrapper and pass on `start_until`. Preparation exhaustion is a `cfg(test)` callback after real config serialization, waiting on a connected channel until the real original deadline; it is injected scheduling delay, not a measured slow production serializer. No arbitrary sleep is used in the new regressions.
- Runtime's focused conversion test exercises the real common clock and real `Instant`, with an expired original deadline and a bounded positive conversion. Conservative sampling order, post-spawn/Job checks and writer admission are source-reviewed boundaries, not forced native Windows scheduling/kernel-failure experiments. Runtime's added helper API first failed compilation while absent; the principal behavioral RED is the real core blocked-pipe test, not a simulated runtime helper-readiness result.
- Stable and installed Rust 1.89.0 workspace tests passed: core ordinary unit tests 18 (original 14 retained), runtime ordinary tests 14 (original 13 retained). Workspace formatting and all-target Clippy with warnings denied passed on stable; all-target Clippy also passed on 1.89.0. All 12 opt-in real Go/TUIC runtime tests passed, including post-serialization original/old-renewal deadline gates; the separate real core sing-box lifecycle test and checked-in v2 static C ABI smoke also passed.
- Only core `helper.rs`, runtime `lib.rs`, focused runtime tests and this README changed. Existing exact-child, sticky ownership, generations, Windows single-root/no-breakaway Job policy and credential-only-stdin contract remain intact. This is Linux real-clock/local-process evidence plus explicit test interleavings, not Windows native acceptance or a hard kill/reap deadline. No dependency/protocol/wire-header changes or external network access were introduced.
