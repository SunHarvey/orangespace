# Windows service foundation (Phase 1)

This is an independently buildable C++20 **SCM service foundation**, not an authenticated
broker replacement and not a usable secure browser. The existing management UI remains
on its offline/development path. Nothing here launches a browser, helper, shell, or network
connection. Browser-open always returns `browser_guard_unavailable`; there is no readiness,
console, unsafe, or sandbox-bypass option.

## Implemented boundary

- `OrangeSpaceService.exe` registers `OrangeSpaceFoundation` with the Windows Service
  Control Manager, handles interrogate/stop/shutdown, and cancels pending pipe I/O on stop.
  Direct execution fails with Windows error 1063; extra arguments fail with error 87.
- It requires LocalSystem. `WTSEnumerateSessions` + `WTSQueryUserToken` discover active
  interactive sessions; each endpoint binds the OS token's **SID, session ID and logon
  AuthenticationId/LUID**, not a client-supplied account UUID. Tokens are closed immediately.
  Up to 64 active sessions are supported. Session changes are reconciled every second;
  old logon tokens cannot authenticate to a new session's endpoint.
- Each endpoint is `\\.\pipe\OrangeSpace.Foundation.v1.session.<OS-session-id>`.
  `PIPE_REJECT_REMOTE_CLIENTS` enforces local transport. A protected, explicit DACL grants
  SYSTEM full control and **only that user's SID** mask `0x12019b`. The user is not granted
  `FILE_CREATE_PIPE_INSTANCE` (`0x4`), generic write, WRITE_DAC, or WRITE_OWNER.
  `FILE_FLAG_FIRST_PIPE_INSTANCE` + a single retained instance fail closed on name squatting;
  a failed worker stops the foundation rather than substituting a permissive endpoint.
- After reading a message, the server uses `ImpersonateNamedPipeClient` and the actual
  thread token to verify SID/session/logon and sufficient impersonation level. Failure
  never falls back to a JSON claim or process token. Failure to revert terminates the process.
- Request buffers, response buffers, accepted commands and per-I/O time are fixed/bounded.
  A client cannot request a path, select an identity, pass credentials, or execute commands.
  One endpoint handles one connection at a time; availability against a hostile process
  already running as the authorized user is not guaranteed.

Local administrators/SYSTEM and malware already running as the authorized Windows user
are not isolated from that user's identity or DPAPI data by this design. Client-side server
identity/capability authentication is **not yet integrated**; no UI client uses these pipes.
An eventual credential-bearing client must verify the SCM-owned server identity before
sending secrets. The current protocol deliberately carries no secrets.

## Wire protocol v1

Use message-mode pipes. Open client handles with individual access mask `0x12019b`
(and `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION`), not GENERIC_WRITE.
Wait for pipe availability between connections.

Exactly one **12-byte message** per connection:

| Offset | Bytes | Meaning |
|---|---|---|
| 0 | 4 | ASCII `OSP1` (protocol/version) |
| 4 | 2 | Little-endian command: 1 = status; 2 = browser-open |
| 6 | 2 | Reserved flags, must be zero |
| 8 | 4 | Little-endian payload length, must be zero |

Unknown commands/flags, any payload, undersized/oversized messages, or failed identity
checks are disconnected without dispatch. No JSON request parser exists, so fields such
as `sid`, `user_id`, `authenticated`, or `ready` cannot influence authorization.

A valid response is one message: a four-byte little-endian body length followed by static
UTF-8 JSON (total at most 1024 bytes). Status explicitly reports `authenticated:false`,
`browser_allowed:false`, `credential_ipc:false`. The client must read that message and send
one byte `0x06` ACK; the server then disconnects. This avoids an unbounded
`FlushFileBuffers` wait or discarding an unread response. Read, write and ACK phases each
have a 1500 ms deadline and are cancellable during stop. There is no command pipelining.

## User-bound credential primitive

`protect_credential` / `unprotect_credential` are Windows-only native library primitives,
not exposed over the foundation IPC. They call current-user DPAPI with
`CRYPTPROTECT_UI_FORBIDDEN`, **never** `CRYPTPROTECT_LOCAL_MACHINE`, and reject SYSTEM,
service accounts and session-0 execution. Calling code must already be running under the
intended interactive user's token with the appropriate loaded profile; failures propagate.
The service does not currently impersonate users to call these functions.

DPAPI entropy binds a versioned OrangeSpace purpose, the OS-derived user SID, and a
caller-supplied public scope (for example a future trusted node/credential-purpose binding).
Secret input is bounded to 1..4096 bytes, ciphertext to 1..16384 bytes, and scope to
1..256 printable non-space ASCII bytes. The unwrapped `Secret` is noncopyable and wipes
its DPAPI allocation before freeing it. Callers must separately wipe their own input buffers.
There are no secret-bearing logs, command-line arguments, environment variables or
plaintext persistence, and no plaintext fallback. **No persistent credential store is
implemented yet**; future storage must persist only protected blobs with per-user ACLs.

An authenticated server user UUID / trusted node registry / login and refresh integration
is unavailable here. Windows SID verification is not a server login. No credentials are
accepted or fabricated to make that integration appear complete. WFP/DNS enforcement,
CEF startup, signed installation, updater policy, and the Rust broker integration remain
outside this foundation.

## Build and tests

Portable policy tests (Linux/macOS/Windows):

```sh
cmake -S apps/windows-service -B build/service
cmake --build build/service
ctest --test-dir build/service --output-on-failure
```

The existing root/client CMake build also includes these tests and, on Windows, the native
service/library/tests. `scripts/build-windows.ps1` stages the service executable alongside
the development manager; it **does not install or start it**.

On a VS2022 + Windows SDK host:

```powershell
cmake -S apps/windows-service -B build/service-win -A x64
cmake --build build/service-win --config Release
ctest --test-dir build/service-win -C Release --output-on-failure
```

`service-native` exercises real DPAPI roundtrip, entropy mismatch/tamper rejection,
actual pipe DACL readback, denied second server instances, a denied Everyone-restricted
token, real same-user token verification, SID/session/logon mismatch rejection, malformed
frames, idle I/O timeout, cancellation and the browser denial response. It does **not**
create a second local account or prove cross-account DPAPI denial. It returns CTest skip
code 77 in session 0/SYSTEM instead of silently pretending user-bound tests ran.

For OpenSSH (session 0), with that same user already logged on, this non-GUI runner uses
one temporary **limited, interactive-token** scheduled task, no password and no elevation:

```powershell
./apps/windows-service/tests/run-interactive.ps1 -TestBinary ./build/service-win/Release/orangespace-service-native-tests.exe
./apps/windows-service/tests/check-scm-entry.ps1 -ServiceBinary ./build/service-win/Release/OrangeSpaceService.exe
```

The runner removes its task and temporary output in `finally` and verifies task deletion.
A disconnected RDP session is sufficient for these non-GUI tests, but not for browser/UI
validation. The SCM-entry test only checks direct-launch denial, never installs a service.

## Validation boundary (2026-10-29)

Portable tests were written first and observed RED for missing peer authorization,
strict frame decoding, browser denial, and protected SID-only ACL policy, then GREEN.
Root CMake/CTest passed on Linux. The service and native tests were cross-built for
Windows x64 with MinGW `-Wall -Wextra -Werror` and statically linked runtime libraries.
Native DPAPI/pipe tests and SCM-entry denial checks passed on Windows 11 build 26200
under a limited interactive user token (temporary task, disconnected desktop).
The integration pass additionally ran `tests/check-scm-lifecycle.ps1` with an elevated
test token: a fresh administrator-protected Program Files fixture, exact copied hash,
LocalSystem registration readback, actual SCM start/stop and process-path verification,
then verified service and fixture deletion. This did not alter existing product services.

**Not performed:** MSVC/SDK build, active-WTS endpoint enumeration and multi-session
lifecycle under the installed service, actual second-account denial, server
authentication mapping, any browser/network isolation gate. The desktop was disconnected
for the SCM lifecycle smoke test, so no active session endpoint was exercised.
The real SCM lifecycle must be tested on an explicitly authorized Windows test host with
the binary installed in an administrator-controlled, non-user-writable directory; do not
register a LocalSystem service whose executable/DLLs can be replaced by an ordinary user.

Microsoft API references:
- https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
- https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken
- https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata
