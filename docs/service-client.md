# Foundation service client: authentication prerequisite only

`orangespace/service_client.hpp` and `service_client_win.cpp` implement a fixed,
secret-free Windows status query. There is no credential argument, arbitrary SID,
service/pipe selector, browser-open command, readiness override, or reusable raw
pipe handle. Success returns only `FoundationStatus::locked_foundation`, never a
browser permit, application authentication, network readiness, or permission to
send credentials. The public pure validation helpers are testable policy, not OS
identity proofs; constructing their inputs never authorizes transport.

## Identity and wire contract

The client opens only the **local** SCM `OrangeSpaceFoundation` record with query
rights. Both configured and reported service type must be exactly
`SERVICE_WIN32_OWN_PROCESS`; the configured account must be `LocalSystem`, the
state `SERVICE_RUNNING`, and the PID nonzero. A synchronize/query-limited process
handle is held for the entire exchange and checked for termination.

The caller session is derived from the current process token and cross-checked
against `ProcessIdToSessionId`. Session zero and any impersonating calling thread
are rejected. No SID/session is supplied by the caller or serialized. The fixed
local path is `\\.\pipe\OrangeSpace.Foundation.v1.session.<OS session>`.
The existing server independently verifies the actual client's SID/session/logon.

The client opens with individual rights **0x12019b**, not `GENERIC_WRITE` (which
would include `FILE_CREATE_PIPE_INSTANCE`), and
`FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION`. It selects
message-read mode. After connection, **before any protocol bytes**, it re-queries
SCM configuration/status and requires `GetNamedPipeServerProcessId` to equal the
held SCM PID and the held process to remain alive. It repeats the pipe/SCM/process
binding check before ACK, and checks SCM/process again after ACK (the server may
already have disconnected the pipe then). A stopped/replaced service or failed
observation fails closed.

Exactly one 12-byte OSP1 status request is written:

```text
4f 53 50 31 01 00 00 00 00 00 00 00
```

Exactly one response message is read into a fixed 1024-byte buffer. Its four-byte
little-endian body length must exactly match the remaining message. The body must
be byte-for-byte the foundation's fixed response:

```json
{"ok":true,"service":"foundation","authenticated":false,"browser_allowed":false,"credential_ipc":false}
```

This deliberately strict canonical allowlist rejects malformed UTF-8/JSON,
truncation, oversized messages, trailing bytes, duplicate/unknown fields, alternate
spacing/order, `ready:true`, and true authentication/browser/credential claims.
There is no general-purpose JSON parser. A future response version needs an
explicit client protocol change; unknown capabilities never become permissions.
Only a valid response is ACKed with one byte `0x06`. No pipelining, secret payload,
or `FlushFileBuffers` exists.

## Bounds and trust limits

Pipe-busy connection retries have a 1500 ms deadline. Each request write, response
read, and ACK write has its own 1500 ms overlapped wait, also watching the held
service process for termination. Oversized-message `ERROR_MORE_DATA` is rejected,
not reassembled. On timeout/termination, `CancelIoEx` is followed by completion
draining before the buffer/OVERLAPPED is destroyed. These are I/O wait deadlines,
not a hard real-time deadline for every synchronous Windows/SCM API or kernel
cancellation completion. Call this synchronous API on a worker, not the UI thread.

**Required deployment preconditions, not verified by this primitive:**

- The local SCM and its service record/configuration must be protected against
  ordinary-user changes, including delete/recreate, image path/account changes,
  service security, and service registry manipulation.
- The service executable, all loaded dependencies, and their ancestor directories
  must have protected ownership/ACLs, no attacker-controlled replacement/search
  paths, and a trusted installer/update/signing provenance.
- The Windows kernel, LocalSystem, and administrators are trusted. This client
  does not verify Authenticode, hashes, the executable path, actual process token,
  ACLs, or image provenance. Matching an SCM PID is not independent proof of a
  trusted binary if those deployment preconditions fail.
- Existing service endpoint ACL, first-instance collision rejection, remote-client
  rejection, and token SID/session/logon checks remain required.

Process-handle retention and repeated SCM checks reject observable termination/
replacement, but do not promise a permanent trust lease after the query returns.
A future credential-bearing protocol must retain authenticated connection state,
revalidate identity/liveness at its own send boundary, define a reviewed schema,
and receive separate security acceptance. This status-only API must not be
repurposed to accept secret data.

## Build integration for the parent (no CMake edits in this change)

C++20 is required. Suggested parent-owned targets, from repository root:

```cmake
add_executable(orangespace-service-client-policy-tests
  apps/windows-client/tests/service_client_tests.cpp)
target_include_directories(orangespace-service-client-policy-tests PRIVATE
  apps/windows-client/include)
target_compile_features(orangespace-service-client-policy-tests PRIVATE cxx_std_20)
if(WIN32)
  add_library(orangespace-service-client STATIC
    apps/windows-client/src/service_client_win.cpp)
  target_include_directories(orangespace-service-client PUBLIC apps/windows-client/include)
  target_compile_features(orangespace-service-client PUBLIC cxx_std_20)
  target_link_libraries(orangespace-service-client PUBLIC advapi32)
  target_link_libraries(orangespace-service-client-policy-tests PRIVATE orangespace-service-client)
endif()
add_test(NAME service-client-policy COMMAND orangespace-service-client-policy-tests)
```

On Windows this test executable is intentionally a **negative-only** runner:
service absence or a session-zero rejection is expected. Do not run it as an
installed-service happy-path acceptance test. The library source itself sets a
minimum `_WIN32_WINNT` default of `0x0602` when none is configured; the intended
runtime validation host remains Windows 11. Link `advapi32` (Kernel32 is implicit).
No service-side library dependency, diagnostic executable target, or UI integration
is required. A production UI can link the library but must keep browser denial.

## Executed evidence and remaining gates

Tests were added before implementation and failed compilation on the missing
client header, service-binding policy, and native API, respectively, then passed
once those features were supplied. This records compile-time RED, not an invented
behavioral RED run against an existing implementation.

Executed on Linux with `g++ -std=c++20 -Wall -Wextra -Werror
-fsanitize=address,undefined`: canonical status; every truncation and each
single-byte mutation of it; oversized/trailing/overflow-length frames; zero-filled
frames of lengths 0 through 2048; malicious true capability claims; ready/duplicate
fields; and running/configuration/PID/liveness policy negatives. Exit 0.

Cross-built both Windows sources together with
`x86_64-w64-mingw32-g++-posix -std=c++20 -Wall -Wextra -Werror -static`, linked
`-ladvapi32`. The PE imports only Windows system CRT/Kernel32/Advapi32 DLLs.

On the real Windows 11 host over OpenSSH, `sc.exe query OrangeSpaceFoundation`
returned 1060 (not installed). The uploaded test binary's SHA-256 matched Linux:
`e1c5a2ed56c5927fb563cd7147df4bf6106ce010aa3dd60d306255306b038f24`.
It exited 0 and printed:

```text
PASS: native negative query error=1 session=rejected
PASS: portable frame and service binding validation
```

This verifies actual process/token session-zero rejection, actual fixed SCM
missing-service rejection, and the portable validation corpus running natively.
No service was installed, no session manipulated, no browser launched, no
credentials accepted. The temporary uploaded executable was removed afterward.

**Pending:** actual installed LocalSystem service + WTSActive caller handshake,
SCM/pipe PID mismatch against a live rogue endpoint, live stop/restart/replacement
races, native timeout/cancellation/oversized-server tests through this client,
nonzero-session success, cross-user failure, MSVC/Windows SDK builds, protected
installer/SCM/binary provenance validation. Native negative-only tests do **not**
prove a complete installed-service handshake or release readiness.
