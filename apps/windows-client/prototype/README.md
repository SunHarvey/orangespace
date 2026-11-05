# Single offline CEF prototype — service interface v1

This is a distinct opt-in source target, NOT a completed security gate or native-GUI result. The old compile-only target and both old deny gates are untouched. There is no admission server in this directory. Admission failure returns a fixed nonsecret stage exit (80–100 below); other launch-denied checks retain exit 23. Do not start this candidate before the service/rule/native security review.

## Build

Portable focused policy: `cmake -S apps/windows-client/prototype -B <fresh>/policy -DORANGESPACE_PROTOTYPE_POLICY_TESTS_ONLY=ON`, `cmake --build <fresh>/policy`, `ctest --test-dir <fresh>/policy --output-on-failure`.

MSVC/clang-cl x64 + matching private SDK: `cmake -S apps/windows-client/prototype -B <fresh>/native -G Ninja -DCMAKE_BUILD_TYPE=Release -DCEF_ROOT=<verified-exact-minimal-root> -DCMAKE_TOOLCHAIN_FILE=<parent-toolchain>` then `cmake --build <fresh>/native --target orangespace_cef_prototype -- -j1`. Static CRT /MT, wrapper and official matching bootstrap; output `<fresh>/native/prototype/Release/client.exe` + `client.dll` and runtime. No bootstrap rebuild or cef_sandbox.lib. The existing package preflight and exact API/runtime version/hash checks are reused. Archive provenance remains the parent's mandatory verified extraction prerequisite; CMake header preflight alone is not archive integrity attestation.

## Runtime trust — fixed diagnostic runtime only

The operator additionally authorized this same pinned unsigned runtime for the
single Singapore online prototype, under the same protected installation,
sandbox and live per-instance admission requirements. This is not a release or
general unsigned-DLL exception. The currently implemented v1 admission and
surface remain Offline-only: this authorization does not itself enable network
access. Singapore mode still requires independently verified Service-side node
authority, the authenticated designated HTTP/CONNECT channel, actual installed
and read-back ProxyOnly restrictions, and fail-closed helper/lease ownership.
No configuration readiness boolean can substitute for those conditions.

For this fixed prototype only, the operator explicitly approved the official,
archive-verified but unsigned CEF runtime. The complete installed inventory must
be anchored by the independently recorded manifest SHA256, administrator-protected
and retained by the Service with deny-write/delete-share handles. Root and every
subprocess must finish the real OS-bound provisional/ACK/COMMITTED admission before
`libcef.dll` is loaded. The loader's unsigned allowance is derived from that retained
admission owner, not an argument, environment/configuration flag or readiness value.
The upstream loader still rejects invalid signatures, version mismatches and load
failures. A signed release is not claimed. Old targets, sandbox, WFP, process/Job
checks and system trust stores are unchanged.

Run `python3 apps/windows-client/prototype/tests/bootstrap_runtime_trust_tests.py`
for the narrow source-order regression; this is not native loader/sandbox evidence.

## Frozen service contract (parent integration owns implementation)

- SCM own-process LocalSystem service `OrangeSpaceSinglePrototype`; fixed local message pipe `\\.\pipe\OrangeSpace.SinglePrototype.Admission.v1`. Never share the old service/pipe or old Profile. Every instance uses protected DACL, first-instance protection, remote rejection. Ordinary clients get individual rights 0x12019b, never generic write/create-instance. Restricted CEF child identities may need a narrowly reviewed explicit ACL. If sandboxed children cannot access SCM/process metadata/pipe, admission MUST fail; do not bypass by --type.
- Exact packed little-endian Request (64 bytes) and Reply (160 bytes) from admission_protocol.hpp; reject oversize, short, trailing, unknown version/status/evidence/reserved. No text/JSON/config/credentials. Request identity fields are comparison hints ONLY. Server calls GetNamedPipeClientProcessId, impersonates at identification level to inspect TokenUser/logon LUID/session/restriction, opens and RETAINS exact client process handle and creation time, and compares every supplied field. Random 32-byte nonce binds a fresh pipe roundtrip, not a transferable permit.
- The client authenticates server PID against SCM before sending and again after reply, retains process handle, checks LocalSystem token and creation time, and checks Job membership locally. It does NOT independently inspect WFP or verify the particular Job; those are trusted service obligations. Reply fields cannot substitute for those actual checks.
- Before successful reply, service verifies protected immutable EXE/runtime install tree including all ancestors and exact runtime inventory, process image/file identity and authorized single sandbox owner/session. It creates/retains exactly ONE no-breakaway kill-on-close root Job and assigns the root before admission. All CEF descendants inherit that Job and same protected bootstrap EXE. Child authorization requires actual same Job membership and exact process-object creation lineage; never accepts a request-provided root PID/cookie as authority. No second root, other session or detached child. Reply root PID/birth are the retained root object. Service owns root cleanup regardless of IPC/process failures.
- Evidence bits 0..7, all required: OS token/session; exact retained caller process; protected EXE/runtime; single-root Job; actual installed/read-back persistent IPv4/IPv6 TCP/UDP/loopback deny; native-proven DNS/delegated-network containment; exact live SCM service instance; live revocation ownership. Each requires actual evidence. rules_epoch/generation monotonic, job_cookie random instance ID, rules_digest SHA-256 of canonical actual WFP snapshot (filter IDs/conditions/actions/provider/sublayer/weights/security). Nonzero fields merely prevent empty replies, NOT proof by themselves.
- All browser networking remains denied for this offline contract. Persistent deny must predate ANY browser start, survive service crash/restart and cover bootstrap and all network subprocess identities, local proxies and delegated DNS. Path AppId alone is NOT demonstrated DNS containment. Capability-less AppContainer remains only a candidate: bit 5 MUST remain unset / admission denied until native validation proves system DNS/broker delegation cannot escape. No full UDP framework prerequisite: unhandled UDP remains blocked.
- Reply status 1 is provisional; ACK write completion is NOT admission. After one-byte ACK 0x06, Service must send a distinct packed 160-byte COMMITTED Reply (status 2), byte-for-byte identical to the provisional reply except status, binding the full request nonce/caller, generation, root, Job, rules and exact server instance. Parent must bound ACK (1500 ms), revalidate retained caller/root/Job and live service objects, exact generation and actual installed/read-back rules AFTER receiving ACK, commit, then send COMMITTED within the client's separate 1500 ms receipt-read budget; kill/rollback the exact root on invalid ACK, disconnect, timeout, rule drift or failure. No automatic grant replay across service restart. The client precreates transfer/revocation events and a monitor thread blocked on a local start event before ACK. Acquire remains the sole pipe reader until a complete exact COMMITTED receipt and repeated live SCM/pipe/process/Job checks pass; only then releases the monitor and returns to CEF. Missing, malformed, stale, rejected, timed-out or disconnected commit fails admission; failure signals stop and joins the waiting thread. Service must treat failed receipt delivery as failed admission and terminate the exact Job. No server is implemented here; these are mandatory server obligations, not simulated enforcement. After COMMITTED, parent keeps pipe open with no success traffic: ANY subsequent byte, EOF or pipe failure means revocation. Client monitor kills its own process on service exit/revoke/disconnect; service must terminate the entire Job and retain persistent deny. Client graceful close closes its pipe after CefShutdown; service closes the root Job only after exact tree exit. No lease expiry renewal protocol exists in v1.

## Offline surface

Single data HTML page with default-src/base-uri/form-action 'none', JavaScript disabled; exact URL allowlist; all other navigation/resources/protocol execution, popup and downloads rejected. Fresh in-memory context, no old persistent cache/Profile. No online grant or proxy credentials implemented; auth callback is deferred. System WFP enforcement is required despite these application restrictions.

## Evidence and limits

The commit-order regression first failed behaviorally: a provisional reply alone was accepted without a committed receipt. Focused portable policy tests now reject absent/provisional receipts, each changed byte of the full committed reply, and wrong request/server identity. These are protocol-policy tests, not a Service timing or native IPC test. MinGW translation-unit compilation is a compatibility probe only, not MSVC ABI/link or Windows sandbox/GUI/network proof. Parent must compile matched MSVC candidate, inspect imports/exports/staged hashes and perform real LocalSystem/ACL/Job/WFP/DNS/interactive acceptance. No browser, remote Windows action, service call or filter installation was executed here.

## Fixed admission failure exits

`Admission::LastFailureStage()` is thread-local to the calling Acquire thread; diagnostics never authorize admission. Fixed stages cover API/check groups, not GetLastError or individual subcalls within a group. No secrets or runtime values are emitted.

| Exit | Stage |
|---:|---|
| 80 | `allocation` |
| 81 | `open_thread_token` |
| 82 | `open_sc_manager` |
| 83 | `open_service` |
| 84 | `query_service_status` |
| 85 | `open_process` |
| 86 | `system_token` |
| 87 | `process_birth` |
| 88 | `pipe_open` |
| 89 | `pipe_mode_scm_bound` |
| 90 | `nonce` |
| 91 | `provisional_write` |
| 92 | `provisional_read` |
| 93 | `provisional_validation` |
| 94 | `own_job` |
| 95 | `pre_ack_storage_thread` |
| 96 | `ack_write` |
| 97 | `committed_read` |
| 98 | `committed_validation` |
| 99 | `postcommit_live_checks` |
| 100 | `monitor_release` |

Unknown/unset stage falls back to 23. Monitor self-termination remains 71. Group failures retain the original null return, API/check order, cancellation and ACK/monitor ownership. In particular, OpenThreadToken rejection is unchanged. Portable tests validate real header mapping and existing negative policies, not native AppContainer compatibility.
