# Windows native login: stage-1 foundation slice

This is a standalone native C++20 component and console diagnostic, **not UI
integration or a completed Windows client**. The existing manager's manual user
UUID remains a development-only local workspace selector. This component does
not launch a browser, configure WFP/DNS, install a service, or bypass any guard.
No IdenGrid code or new third-party dependency is used.

## Authentication and trust boundary

`TrustedCatalog::load(explicit_absolute_path)` is the only way to construct a
transport-capable catalog. `detail::parse_catalog` is portable validation, not a
trust grant. Callers select an administrator-provisioned **alias**, not an
arbitrary endpoint/node-ID pair. The catalog is immutable to callers; each
`NodeSession` retains its own node and authenticated identity. There is no global
current node.

The Windows loader:

- Requires a local fixed drive with persistent ACL support and an explicit DOS
  absolute path, at most 240 UTF-16 code units. Rejects relative/UNC/device paths,
  ADS, traversal, ambiguous components and reparse points.
- Opens each ancestor and the file with `FILE_FLAG_OPEN_REPARSE_POINT`, retains
  those handles throughout the read, and does not share write/delete access.
  It checks ACLs on these handles, not a separately reopened filename.
- Requires SYSTEM/Administrators ownership and a non-null **protected DACL** on
  both the file and its immediate parent. Ordinary principals may read but may
  not write data/attributes/EA, append, delete, delete children, change the DACL,
  or take ownership. Unknown effective ACE types fail closed. Deny entries do
  not excuse a broad write allow; inheritance-only ACEs are not effective on the
  inspected object.
- Checks higher ancestors too. SYSTEM, Administrators, and the Windows
  TrustedInstaller service may own these ancestors. Child creation alone is
  allowed on higher ancestors, but mutation/deletion/ACL-changing grants are
  not. The loader deliberately refuses permissive ancestor layouts: on the
  tested Windows host the default `C:\ProgramData` grants Users attribute/EA
  writes and is therefore unsuitable. Use a dedicated protected directory
  directly below the fixed drive root; **do not weaken system-directory ACLs**.
- Reads at most 64 KiB and rechecks every handle's ACL after reading. Trust
  configuration contains no credentials. Only an administrator provisions or
  changes it; the diagnostic never silently repairs permissions.

WinHTTP uses **Windows platform certificate trust plus the protected HTTPS
origin**, not a separate certificate/SPKI hash pin. Normal chain, hostname and
validity checks remain enabled; TLS 1.2 is required (TLS 1.3 also enabled when
available in the SDK), and certificate revocation checking is requested. There
are no ignore-certificate flags, trust-on-first-use, HTTP fallback, or redirects.
Windows trusted-root policy is part of this trust boundary; this is not a
private CA-store or protection against a compromised administrator/root store.

The sequence is:

1. Select the pinned entry from the ACL-checked catalog.
2. Credential-free HTTPS `GET /healthz`; require status 200 and exactly one
   `X-OrangeSpace-Node` equal to the pinned UUID. TLS validation happens before
   credential transmission. A preflight failure prevents posting the password.
3. HTTPS `POST /v1/auth/login`, sending **only** username/password JSON.
4. Validate status 200, the pinned node header and body node ID, exact login
   schema, `bearer` token type, the server's 43-character URL-safe token format,
   and a future integral `expires_at`.
5. HTTPS `GET /v1/me` with that bearer token. Require the pinned node header and
   body node ID and the exact `user_id`, `username`, `node_id` schema. The user
   UUID is derived **only from this authenticated response**. An identity is not
   published unless this step succeeds and the token has not expired.

Duplicate/unknown JSON fields, wrong types, invalid UTF-8, invalid UUIDs,
trailing JSON, duplicate required HTTP headers and mismatched identities fail
closed. JSON bodies and response headers are bounded at 16 KiB. Response bodies
are read incrementally, including chunked responses, with a 30-second progress
check and 5-second WinHTTP resolve/connect/send/receive timeouts. A blocked
synchronous operation can run until its WinHTTP timeout; this is not an exact
30-second wall-clock cancellation guarantee. Only JSON content types are
accepted. Cookies, automatic HTTP authentication, redirects and proxy discovery
are disabled. Direct HTTPS here is solely the node control plane, not a browser
networking fallback. There is no automatic retry after failed login/429.

## Administrator provisioning

Provision a **new** directory from an elevated PowerShell session. The example
contains placeholders only; replace the UUID/origin with the administrator's
verified node values. Do not insert passwords/tokens into this file.

```powershell
$root = 'C:\OrangeSpaceTrust'
if (Test-Path -LiteralPath $root) { throw 'Choose a fresh dedicated trust directory' }
New-Item -ItemType Directory -Path $root | Out-Null
$directoryAcl = New-Object System.Security.AccessControl.DirectorySecurity
$directoryAcl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)')
Set-Acl -LiteralPath $root -AclObject $directoryAcl
$path = Join-Path $root 'nodes.json'
$configuration = '{"schema":1,"nodes":[{"name":"office","node_id":"11111111-1111-4111-8111-111111111111","api_origin":"https://node.example.invalid:443"}]}'
[IO.File]::WriteAllText($path, $configuration, (New-Object System.Text.UTF8Encoding($false)))
$fileAcl = New-Object System.Security.AccessControl.FileSecurity
$fileAcl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)')
Set-Acl -LiteralPath $path -AclObject $fileAcl
Get-Acl -LiteralPath $root | Format-List Owner,Sddl
Get-Acl -LiteralPath $path | Format-List Owner,Sddl
.\OrangeSpaceLogin.exe --check-trust $path
```

The strict catalog schema is version 1, with 1–64 nodes. Aliases use lowercase
ASCII letters/digits/`-`/`_` (1–64 characters). Node UUIDs use lowercase canonical
non-nil representation. Origin syntax is deliberately narrow: lowercase ASCII
DNS/A-label or IPv4 host, optional canonical decimal port 1–65535; no path,
trailing slash, query, fragment, userinfo, percent encoding, or IPv6 literal.
Absent port means 443. Alias, node ID, and effective host/port must each be
unique. UTF-8 without BOM is required. IPv6/IDN display support is not claimed.

Run as the ordinary interactive user, not as an elevated login process:

```powershell
.\OrangeSpaceLogin.exe 'C:\OrangeSpaceTrust\nodes.json' office
```

Username and password come from **console stdin**, using `ReadConsoleW`;
password echo is disabled and restored on ordinary unwinding. Redirected stdin
is refused, not treated as a plaintext password file. Only the trust path and
alias appear in arguments. Diagnostics print safe constant errors or verified
UUIDs/expiry; never passwords, access tokens, headers, or response JSON.

## Session lifetime and scope

This slice intentionally uses **ephemeral in-memory sessions**, not DPAPI or a
credential file. No tokens are accepted from argv/environment or written to
files/logs. Password buffers, serialized request bodies, response buffers,
parsed login strings and session token buffers are best-effort wiped by scoped
owners. The session is noncopyable, has no public token accessor and never
serializes itself. The console exits after reporting the verified identity,
destroying its local session. It does not revoke the server token on exit: the
server's existing expiry/revocation rules still apply. Refresh, persistence,
DPAPI restoration, UI wiring and authenticated file operations remain pending.
Memory wiping is not a guarantee against crash dumps, paging, injected code,
allocator remnants from malformed JSON parsing, or WinHTTP/OS internal copies.

## Build contract for the integrator

The integration pass has added these targets to
`apps/windows-client/CMakeLists.txt`; the equivalent build contract is:

```cmake
add_executable(orangespace-node-session-tests tests/node_session_tests.cpp)
target_link_libraries(orangespace-node-session-tests PRIVATE orangespace_client_model)
add_test(NAME node-session COMMAND orangespace-node-session-tests)

if(WIN32)
  add_library(orangespace_node_session STATIC src/node_session_win.cpp)
  target_link_libraries(orangespace_node_session PUBLIC orangespace_client_model
    PRIVATE winhttp advapi32)
  target_compile_features(orangespace_node_session PUBLIC cxx_std_20)
  target_compile_definitions(orangespace_node_session PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
  # Console subsystem: deliberately do not use add_executable(... WIN32 ...).
  add_executable(OrangeSpaceLogin src/login_win.cpp)
  target_link_libraries(OrangeSpaceLogin PRIVATE orangespace_node_session)
  target_compile_definitions(OrangeSpaceLogin PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
  target_compile_definitions(orangespace-node-session-tests PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
  target_link_libraries(orangespace-node-session-tests PRIVATE orangespace_node_session)
  if(MINGW)
    target_link_options(OrangeSpaceLogin PRIVATE -municode)
  endif()
  if(MSVC)
    target_compile_options(orangespace_node_session PRIVATE /W4 /permissive- /utf-8)
    target_compile_options(OrangeSpaceLogin PRIVATE /W4 /permissive- /utf-8)
    target_compile_options(orangespace-node-session-tests PRIVATE /W4 /permissive- /utf-8)
  endif()
endif()
```

Wrap the test target in the integrator's existing `BUILD_TESTING` guard and
conditionally link it when that target exists. Only Windows OS libraries
`winhttp` and `advapi32` are required in addition to the ordinary C++ runtime.
MinGW diagnostic builds can use `-static` to avoid shipping MinGW runtime DLLs.
MSVC/Windows SDK and signed release packaging are separate verification gates.

## Verification evidence and remaining gates

Portable strict TDD was run as successive RED/GREEN cycles: missing catalog
validation; rejection of ambiguous origins/duplicate entries; authenticated
response validation; control/invalid-UTF-8 rejection; and ACL/path policy.
Observed RED diagnostics included `catalog validation not implemented`,
`reject ambiguous origin`, `login validation not implemented`,
`reject invalid me body`, and `admin-owned protected ACL accepts users RX`.

```sh
g++ -std=c++20 -Wall -Wextra -Werror -I apps/windows-client/include \
  apps/windows-client/tests/node_session_tests.cpp \
  -o /root/.hermes/cache/scratch/node-session-tests
/root/.hermes/cache/scratch/node-session-tests
# node session: 95 checks passed

x86_64-w64-mingw32-g++ -std=c++20 -Wall -Wextra -Werror \
  -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -DNOMINMAX -D_WIN32_WINNT=0x0A00 \
  -I apps/windows-client/include apps/windows-client/src/node_session_win.cpp \
  apps/windows-client/src/login_win.cpp -static -municode -lwinhttp -ladvapi32 \
  -o /root/.hermes/cache/scratch/OrangeSpaceLogin.exe

x86_64-w64-mingw32-g++ -std=c++20 -Wall -Wextra -Werror \
  -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -DNOMINMAX -D_WIN32_WINNT=0x0A00 \
  -I apps/windows-client/include apps/windows-client/src/node_session_win.cpp \
  apps/windows-client/tests/node_session_tests.cpp -static -lwinhttp -ladvapi32 \
  -o /root/.hermes/cache/scratch/OrangeSpaceNodeSessionTests.exe
```

The cross-built self-test was actually executed on the supplied Windows 11 host:
`node session: 100 checks passed`. Its five additional checks create a harmless
user-owned temporary config, verify that the real native loader rejects it and
relative paths, then delete the fixture. No network or credential use is part
of this self-test. A separate one-shot native probe accepted a fresh
administrator-owned/protected directory+catalog, then rejected the same catalog
with Users write access; its fixture directory was removed in `finally`.
The native console import table contains only ADVAPI32, KERNEL32, msvcrt and
WINHTTP; it does not depend on MinGW runtime DLLs.

**Not yet verified:** MSVC/SDK build, interactive password entry/echo restoration,
real HTTPS login against the node API, successful/failed TLS chains and
revocation, adversarial redirect/chunk/header behavior over real WinHTTP,
concurrent file-replacement/reparse attacks, a separate ordinary local user's
write-denial exercise, session expiry on a live server, and UI integration.
Portable response fixtures are validation tests, not proof of an actual login.
No CEF/WFP/DNS safety claim follows from these tests.
