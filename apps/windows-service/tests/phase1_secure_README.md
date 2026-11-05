# Isolated secure transport candidate — NOT an approved bootstrap

**Partial delivery. S1's protected provenance and S3's protected image/report scope remain blocked. Do not integrate, transmit credentials, remove the old quarantine, or run the old Selftest/Accept entrypoints.** Independent review **rejected hard-bounded S2 approval**: the Windows-executed duplex/OS-peer candidate limits frame size and progress, but cancellation completion can block its caller indefinitely. It also does not reject or restore a pre-existing server-thread impersonation context. It is not a completed S1/S2/S3 repair or approved privileged transport. There is no fake `ScopeMetadata` or `ProtectedReportSink` stub.

## Files / build

`phase1_secure_channel.hpp` is a standalone C++20 Windows fixture header. Six independent `phase1_secure_*_tests.cpp` executables have no Node, HTTP, SCM, task, account, profile, RDP, or production dependency. Only known NONSECRET sentinel bytes are sent. Parent CMake and production files are untouched.

From repository root, for each `kind` in `channel io peer token buffer type`:

```sh
x86_64-w64-mingw32-g++ -std=c++20 -Wall -Wextra -Werror -static -municode -D_WIN32_WINNT=0x0A00 apps/windows-service/tests/phase1_secure_${kind}_tests.cpp -ladvapi32 -o /root/.hermes/cache/scratch/phase1-secure-${kind}.exe
```

Run `channel.exe` with no args, then `--bound`; other exes with no args. `peer`'s internal `--child` mode is an owned, nonsecret self-child protocol, not a controller role launcher. All binaries ran directly through authorized SSH, with strict known-host checking. No PowerShell scripts or execution-policy changes were used.

Final actual commands, exit codes, stdout and remote SHA-256 readbacks: `/root/.hermes/cache/scratch/phase1-secure-final-build-native.json`. Source/artifact hashes: `/root/.hermes/cache/scratch/phase1-secure-final-manifest.json`. Reproducer/build runner: `/root/.hermes/cache/scratch/phase1-secure-final-verify.py` (review before reuse; remote owned directory must be freshly provisioned).

## APIs and exact guarantee

- `HeldPeer::capture(HANDLE held_process)`: duplicates QUERY_LIMITED_INFORMATION + SYNCHRONIZE, records OS SID, session, authentication LUID, integrity, elevation type, restricted status, PID and creation time. Move-only; no JSON/argv identity claims. `verify_live(actual_pid)` checks the retained process is live, creation matches and current primary token equals that snapshot. **Capture is not authority/provenance**: arbitrary caller-selected handles are not a protected expected-role source.
- `create_server(name, canonical_numeric_sid)` / `open_client(name)` return move-only `Pipe`, whose private adoption constructor prevents passing arbitrary synchronous handles to `SecureChannel`. Both factories use OVERLAPPED; client requests individual data/read-attributes/read-control/synchronize rights. Server is FIRST_INSTANCE, single instance, local-only byte mode. Protected DACL grants only those narrow rights, with OWNER RIGHTS read-control to suppress implicit owner WRITE_DAC; medium mandatory label NW. Canonical SID validation rejects SDDL aliases/injection. No generic-write/0x4/WRITE_DAC/WRITE_OWNER ACE. OS administrator privileges remain outside discretionary ACL protection.
- `SecureChannel::client(Pipe, HeldPeer, Deadline)` and `::server(...)`: nonsecret hello/ack, reciprocal kernel pipe-process-ID check against independently retained expected objects. Server reads before impersonating the **actual named-pipe connection**, verifies impersonation level and compares actual connection SID/session/LUID/integrity/elevation/restricted status. It does not substitute the process primary token for the connection token. Client authenticates the known held server process, not a claimed server PID. Every framed receive rechecks before releasing its buffer; sends check before/after. On framing, auth, timeout or disconnect failure the channel permanently closes. No endpoint handle delegation or malicious mutation of the trusted processes is in the primitive's threat model; kernel opener PID is not a provenance proof for arbitrary delegated writers.
- `send(const SecretBuffer&, Deadline)` / `receive(Deadline)` share one absolute deadline across header/body and every partial progress, including already-buffered/immediate completion. Private per-operation event/OVERLAPPED. On timeout/failed wait, CancelIoEx then GetOverlappedResult(TRUE) joins cancellation before buffers/events/OVERLAPPED leave scope. This preserves operation-storage lifetime but introduces an unbounded completion wait: there is no second deadline, so neither caller return nor complete channel closure has a proven hard time bound. Fast sentinel runs do not close this review blocker. No synchronous pipe write, FlushFileBuffers or Peek-based timeout.
- `SecretBuffer`: fixed 32768-byte owned RAII storage, noncopyable/noexcept move, whole-source/destructor wipe, alias-safe assignment plus tail wipe. It does not erase arbitrary caller copies or registers. The existing fixed 257-byte `Bootstrap` was not modified.
- Low-level raw HANDLE transfer/framing functions are fixture primitives for tests and assume the module-created OVERLAPPED endpoints; use `SecureChannel`, not arbitrary synchronous handles, at any future reviewed integration boundary.

## Observed RED → GREEN

Observed in actual Windows tool execution, in vertical order (earlier RED outputs are transcribed observations; final GREEN execution is captured mechanically in JSON):

1. First minimal duplex test: exit1 `RED: bounded authenticated channel missing`; implementation then native GREEN, session0.
2. Bound framed owner/timeout-close test: exit1 `RED: authenticated framed channel with fail-closed ownership missing`; implementation then native GREEN.
3. Read-only original `phase1_native.hpp::read_exact` baseline: exit1 `expired_buffered_read_must_reject`; new transfer passes. Baseline executable was an isolated marker-only repro, not execution of any quarantined driver.
4. Fixed buffer alias regression: exit1 `assign_self_view_preserves_marker`; memmove/tail-wipe fix then GREEN including move-source/destructor full-capacity checks.
5. Canonical SID boundary: exit1 `self_asserted_sddl_sid_alias_rejected`; canonical validation then GREEN.
6. Synchronous-handle adoption: exit1 `RED: channel can adopt arbitrary synchronous pipe handles`; private `Pipe` adoption then compile-time-contract GREEN. This is a type-system assertion, not runtime scheduler evidence.

Additional actual native regressions cover stalled read/write, slow positive byte progress, partial header, peer loss, oversize length, cancellation/completion races, first-instance collision, discretionary ACL checks, wrong client/server PID with same SID/session/LUID, and restricted impersonation of a client thread while its held process primary token remains unchanged. Broader regression probes were added after the initial general transport implementation; do not label each of those a separate behavior-first RED/GREEN cycle.

A genuine initial ACL test failure was caused by the SSH token's enabled ownership privilege: WRITE_OWNER AccessCheck succeeded despite no ACE grant. The production pipe ACL was NOT relaxed. The ACL-only test uses a duplicate impersonation token with privileges disabled solely for AccessCheck, never launched or assigned to a process/thread. The separate connection-token test does impersonate a locally restricted client **thread** to verify rejection; no linked token or new process role is launched.

Final mechanically counted run set: 16 executable invocations, including the compile-time-contract reporter; 12 exact owned child process exit-signal observations and 160 cancellation/completion race attempts. Race attempts are not 160 guaranteed cancellations or exhaustive interleavings. Atomic JOB_LIST admission and HANDLE_LIST parent-only inheritance are required, no post-spawn assignment fallback. The child test retains its independent kill-on-close Job and exact process object; releases only after an observed exact signal, with exact-object termination cleanup on failure, never PID kill. It creates no inherited stdin/stdout pipe pairs; communication is through the same private OVERLAPPED factories.

## Concrete STOP premises / role limits

Actual SSH process: UserA SID from OS, **session0, high integrity 12288, administrator-enabled**. It was already that token; no elevation/linked-token launch was attempted. This is not normal limited-token acceptance, not session0→session2, not a full-token interactive controller launch, and not a distinct-logon-LUID test. The module compares each side to its own expected snapshot; it does not incorrectly require runner and legitimate interactive controller LUIDs to match.

S1 requires a separately authoritative prelaunch expected-runner receipt and an authoritative expected-controller source. A held, verified logged-on process/protected bootstrap producer may supply the latter; an ordinary caller-supplied PID/SID/session/LUID/path may not. No such protected producer/scope was provided. This module deliberately does not turn `HeldPeer::capture` into proof of a fixed role or protected image.

S3: the allowed current-user Temp artifact root and EXE both grant UserA inherited Full Control; real `icacls` readback is in `/root/.hermes/cache/scratch/phase1-secure-authority-evidence.json`. It is not an administrator-protected root against UserA. No permission was used to provision a different protected installation/report root or launch a session2 role. **Stopped before implementing/claiming a protected report sink** instead of adding a prefix check, ordinary SourceDirectory write or pretend protected-scope stub. No protected-path/report module or positive protected-root acceptance is delivered.

Smallest next authorization/premise: parent independently reviews this transport; supplies/approves one fresh admin-protected fixture root with fixed per-role image/hash manifest and protected nonsecret bootstrap receipt producer; defines the independently sourced expected runner and interactive controller identities; and approves an isolated normal-token execution path (current SSH is high). Until then real credentials, integration and old entrypoint unquarantine remain prohibited. No SCM/Tasks/accounts or production changes are necessary for reviewing this partial primitive.
