# Installed service/status IPC validation

## Scope and policy

2026-10-29, Windows 11 host `192.168.122.33`, baseline `31bbccc` plus the scoped changes in this document. This validates the **real installed LocalSystem service and the real limited status client**, not a fake pipe server. Session 2 remained logged on and `WTSDisconnected`; there was no logon, password collection, RDP/session manipulation, GUI interaction, profile change, certificate/trust change, or unrelated service change.

A disconnected desktop is not a logged-off user. Long-lived session/helper/file work must not depend on an attached RDP viewer. The service now considers only `WTSActive` or `WTSDisconnected`, and creates an endpoint only after successful `WTSQueryUserToken` and OS token extraction validate:

- nonzero enumerated session and matching `TokenSessionId`;
- `TokenUser` SID passing the existing strict user SID/SDDL policy;
- nonzero `TokenStatistics.AuthenticationId` (logon LUID).

Session 0, missing tokens, service account SIDs, mismatched sessions, zero logon LUID, logged-off/empty sessions, all other/transitional WTS states are denied. The one-second enumeration continues removing/replacing workers when the OS identity disappears or changes. This is a polling boundary, not instant logoff notification acceptance. A state observed as Disconnected without a valid logged-on token does **not** authorize anything. If token acquisition fails on the test host, the installed test fails; there is no manual SID/LUID, session-0, alternate-account, or reconnect fallback.

Every request still uses pipe-client impersonation to compare the exact SID/session/logon LUID. The protocol accepts no caller-supplied identities or payloads. Supporting background status IPC does not authorize a helper, broker, node identity, credentials, or browser.

Microsoft API references: [WTSQueryUserToken](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken), [WTS connection states](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ne-wtsapi32-wts_connectstate_class), [process access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights).

## Additional real-host finding: process observation access

The initial test also exposed `ClientError::process_rejected` (5). A limited user could not open the LocalSystem process with the status client's required `SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION`. Eligibility alone created the pipe but did not fix the handshake; the intermediate real-host RED below records that distinction.

The initial implementation replaced the process DACL with SYSTEM/Administrators full access plus peer observation grants. Independent review correctly rejected that replacement: it discarded pre-existing deny/allow policy and minted Administrators rights. **That implementation and its historical artifact hashes below are superseded by the DACL-preserving correction recorded next.**

The corrected service snapshots the original process owner/group/DACL/control state once, before publishing any observation grant. Each update copies the original ACEs byte-for-byte in their original order and appends only deduplicated OS-validated user SID grants of **`0x101000` (query-limited + synchronize)**. It never synthesizes SYSTEM/Administrators grants, reorders baseline policy, or uses the previous published ACL as the merge source. New allows go after **all** baseline ACEs, including inherited denies; the Windows native tests below check actual `AccessCheck`, not merely ACE text. Unsupported object/callback/conditional ACEs and absent/null/invalid DACLs are rejected instead of replaced. Owner/group/SACL are not written; baseline DACL default/protection/auto-inheritance flags are retained and readback checks owner/group/control and the exact ACE stream. A baseline explicit deny can therefore make status observation unavailable; there is no bypass.

The last descriptor actually read back is the expected state, not a new baseline. An unexpected owner/group/control/DACL change poisons the publisher; it does not overwrite that external policy, and the service's existing exception path tears down its workers and exits. Unchanged peer sets do not write. Copies/refreshes are bounded to 64 distinct eligible user SIDs and a 65535-byte ACL.

**User SID observation grants are user-wide across logons and sessions, not logon-LUID-scoped and not pipe authentication.** The pipe still impersonates every client and compares the exact SID/session/logon LUID; no SID/LUID eligibility, request, or protocol security was changed. Removing a peer removes only service-managed new-handle rights at the next refresh; pre-existing baseline grants (even to the same SID) and already-open observation handles remain. No mutation/VM/duplicate-handle rights are added by the publisher.

Microsoft primary references: [sequential AccessCheck semantics](https://learn.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object), [AddAccessAllowedAceEx appends an ACE](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-addaccessallowedaceex), [SetKernelObjectSecurity](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-setkernelobjectsecurity).

## DACL-preserving correction: native RED / GREEN (current)

2026-10-29, same Windows 11 host, same existing Disconnected session 2. Before editing production publication code, the existing policy test was extended to install a real process DACL with baseline BA `PROCESS_TERMINATE` deny, unrelated Everyone `PROCESS_VM_READ` allow, and bounded administrative security access. Its initial native `AccessCheck` confirmed the fixture deny/allow, then called the **old actual `publish_observation_acl`**. The rebuilt executable ran on Windows and failed behaviorally (exit 1):

```text
FAIL: publication weakened baseline BA PROCESS_TERMINATE deny
```

RED executable: `/root/.hermes/cache/scratch/os-acl-red.exe`, SHA-256 `34792451725baa29fbad6a0678cbc628c680bcb7261dde573a68ae97a7cec40e`; output `/root/.hermes/cache/scratch/os-acl-red.txt`. The final native policy executable uses the same production `ProcessObservationAcl` utility as the service, without including a duplicate service entry point.

Current Windows GREEN (exit 0) includes actual native `AccessCheck` assertions for:

- baseline BA terminate deny and unrelated allow surviving publication;
- add/remove peers, exact original descriptor restoration with no peers, unchanged-peer byte idempotence, and duplicate user SIDs across session entries;
- removed managed query/synchronize rights disappearing, without removing baseline same-SID query rights;
- external DACL drift rejected without any overwrite, including a second attempt with the permanently poisoned publisher;
- inherited BA query-limited denial remaining effective after adding the matching user's observation allow; synchronize remains permitted, unrelated read remains permitted;
- exact baseline owner/group/control/ACE restoration with protected, unprotected, auto-inherited and auto-inherit-request fixture inputs;
- null DACL and object-specific unsupported ACL rejected without mutation.

The installed secure fixture script was then rerun unchanged with the corrected service and the real non-elevated production client. Exact fixture `C:\Program Files\OrangeSpace-Ipc-5831a842aa3841739d192ca563b02730`: LocalSystem, own-process, exact quoted binary path; initial PID 3588, restart PID 4248. Output (exit 0):

```text
PASS: service stopped with old client read pending
CLIENT initial-stop-restart exit=0
OBSERVED: session endpoint available=1 win32=0
OBSERVED: installed query error=0 session=2
PASS: client non-elevated; service process mutation rights denied
PASS: installed SCM + actual pipe PID + canonical locked_foundation + ACK
PASS: pending old read closed error=233; stopped query error=4
PASS: old connection stays dead; fresh installed handshake after restart
WTS after: unchanged Disconnected session=2
CLEANUP: task absent
CLEANUP: service absent
CLEANUP: fixture binary processes absent
CLEANUP: fixture absent C:\Program Files\OrangeSpace-Ipc-5831a842aa3841739d192ca563b02730
CLEANUP: WTS still Disconnected session=2
PASS: installed service IPC initial/restart and cleanup
```

The limited client actually attempts `OpenProcess` separately for terminate, VM-write, duplicate-handle and WRITE_DAC and requires all to fail. The normal `0x101000` status handle, SCM/pipe PID binding, canonical locked status and ACK succeed. After cleanup, the production absent-service negative test passed from SSH session 0. Exact task, service, fixture process/path, Program Files directory and upload directory were independently read back absent; the standalone RED/GREEN uploads were removed as well. Session 2 remained Disconnected; no account, profile, RDP, trust store or unrelated service was changed.

Current artifacts, under `/root/.hermes/cache/scratch/os-acl-mingw/` (MinGW x64, static GCC/C++ runtimes; Windows system DLL imports remain):

| Relative path | SHA-256 |
| --- | --- |
| `apps/windows-service/OrangeSpaceService.exe` | `4f2de3ef13cf96386b70e75e0d4777fb743e7a477337743dec1a6c8249e4d0d0` |
| `apps/windows-service/orangespace-service-policy-tests.exe` | `6365bd94ba1fc4f349f58e2b98c022b05f449f8a4738835b214041e37d3fbbf9` |
| `apps/windows-client/orangespace-service-client-tests.exe` | `d50b0fdb0e986a3d6b386f0d6284b44eaa4d16a8328fa230d613e402aa59519c` |

The installed/copied service and client hashes matched. Linux root CMake/CTest **6/6 passed**; Windows cross-build completed with the existing warning-as-error policy. The minimal CMake change links Windows policy tests against the already-existing Windows service utility library.

Raw current logs/manifests in `/root/.hermes/cache/scratch/`: `os-acl-installed-green.txt` (native policy GREEN plus installed service/restart), `os-acl-final-readback.txt`, `os-acl-artifacts.json`, `os-acl-linux.txt`, `os-acl-crossbuild.txt`. `run-os-acl-validation.py` is the local upload/run/cleanup driver. An initial driver's UTF-8 decoding error lost its captured localized SCM output; the driver was corrected to retain replacement characters and the full native/installed run repeated successfully. Localized `sc.exe`/`quser` text may contain replacement characters; the script's explicit English assertions and native return codes are the acceptance evidence.

Remaining ACL limits: this is conservative support for ordinary allow/deny ACEs, not conditional/object ACL interpretation. Absence/null checks are explicit in production; a null process DACL and object ACE were exercised natively, not a separately manufactured absent-DACL kernel representation. Fail-closed drift checks occur before writes and on readback; there is no atomic DACL compare-and-swap against a concurrent privileged security writer. This does not defend against an administrator racing/mutating the process security policy. Revocation cannot invalidate existing handles. Peer lifecycle add/remove tests use the native publisher with OS-derived/synthetic SID entries; they do not log users off or create additional sessions. Native ACL tests ran under the SSH administrator token; the installed positive/mutation-denial tests ran under the existing limited interactive token. No MSVC rebuild is claimed for this correction; no new Phase 1/WFP/browser acceptance is implied.


## Earlier eligibility/IPC RED → GREEN evidence (historical)

Harness bring-up initially rejected an unquoted `sc.exe` ImagePath on readback and cleaned the fixture; the final harness uses `CreateServiceW` directly rather than relying on Windows PowerShell native argument quoting. That harness/configuration failure is not counted as the behavioral RED below.

Production eligibility was unchanged when the first installed Windows RED and pure policy RED ran. The first pure policy executable used a test-side missing-policy detector to fail behaviorally before the API existed; after GREEN that detector was removed in favor of direct policy calls.

### Actual installed baseline RED (exit 1)

Running fixed SCM service, LocalSystem own-process, exact protected executable path, PID 6952:

```text
SCM Running LocalSystem OwnProcess PID=6952 Path=C:\Program Files\OrangeSpace-Ipc-1501ff220dc94009945188e80f5b9832\OrangeSpaceService.exe
CLIENT initial exit=1
OBSERVED: session endpoint available=0 win32=2
OBSERVED: installed query error=5 session=2
```

The assertion was `FAIL: installed LocalSystem SCM/actual pipe PID/canonical locked_foundation/ACK handshake`. `win32=2` means the existing Disconnected session's pipe was absent. Error 5 here is the application's process-rejected enum, **not** Win32 error 5. Cleanup read back task/service/process/fixture absence on failure.

Baseline service SHA-256: `de39e95c327c7447b59a49152dfd153ec9f5a6b0df16637217ff605504c9bd11`.
RED client SHA-256: `38917e81f3ec46f86d050a2eafc4945d673f60c7f638b10aed4c0eef6272bf81`.

Pure policy RED (exit 1), before production changes:

```text
FAIL: validated logged-on Disconnected token must retain background IPC
```

### Eligibility-only intermediate RED (exit 1)

```text
SCM Running LocalSystem OwnProcess PID=4176 Path=C:\Program Files\OrangeSpace-Ipc-63f5aa3e2a7e492fa7bae13916d4511f\OrangeSpaceService.exe
CLIENT initial exit=1
OBSERVED: session endpoint available=1 win32=0
OBSERVED: installed query error=5 session=2
```

This demonstrates that `WTSQueryUserToken` succeeded for the disconnected session, while the real limited process-observation requirement still failed. Service SHA-256: `39df84c4d4bcba90d68676aacc58b5f26f364336f8b40c7ee641e7d615c1966a`. Same RED client as above. Cleanup again passed on failure.

### Earlier actual Windows GREEN (exit 0; superseded ACL implementation)

Final fresh protected fixture: `C:\Program Files\OrangeSpace-Ipc-df6021d1331d4d85b67b8e228e889f59`. SCM verified exact quoted ImagePath, LocalSystem, own-process, executable path and PID 5836; after restart PID 9120.

```text
WTS before: Disconnected session=2 user=win11\win11-pc
PASS: service stopped with old client read pending
CLIENT initial-stop-restart exit=0
OBSERVED: session endpoint available=1 win32=0
OBSERVED: installed query error=0 session=2
PASS: client non-elevated; service process mutation rights denied
PASS: installed SCM + actual pipe PID + canonical locked_foundation + ACK
PASS: pending old read closed error=233; stopped query error=4
PASS: old connection stays dead; fresh installed handshake after restart
WTS after: unchanged Disconnected session=2
CLEANUP: task absent
CLEANUP: service absent
CLEANUP: fixture binary processes absent
CLEANUP: fixture absent C:\Program Files\OrangeSpace-Ipc-df6021d1331d4d85b67b8e228e889f59
CLEANUP: WTS still Disconnected session=2
PASS: installed service IPC initial/restart and cleanup
```

The normal query runs the production SCM + actual named-pipe-server-PID checks, retains the live service process against PID reuse, requires the canonical `locked_foundation` response and writes the application ACK. Lifecycle mode then retains a second real connection with an outstanding overlapped read. The administrator script stops the service, the old read fails with `ERROR_PIPE_NOT_CONNECTED` (233), the retained old process exits, and querying the stopped service returns application enum 4 (`service_rejected`). After restart, the old pipe cannot write and a fresh production query succeeds. This exercises cancellation/teardown of an idle connection, not every possible concurrent stop/ACK timing race.

Historical artifacts under `/root/.hermes/cache/scratch/os-ipc-mingw/` (not the corrected current binaries):

| Relative path | SHA-256 |
| --- | --- |
| `apps/windows-service/OrangeSpaceService.exe` | `c4530d2c1a2e31b52e465add02a920f99b1893cc5ecc167d0419c7458c09eb1f` |
| `apps/windows-client/orangespace-service-client-tests.exe` | `8322ebbd97a488a983dd1c68f13b01d1286f6a0e1955032354b5234f0b811c45` |

These are MinGW x64 static C++/GCC runtime builds (Windows system DLLs are still imported). The temporary installation received identical hashes; source/upload locations were never registered with SCM. Test fixture ACL: protected SYSTEM/Administrators full control, Users read/execute only; only the separate result directory allowed the OS-derived user's writes. Test executables/runner remained administrator-protected.

Additional actual results:

```text
PASS: Active/Disconnected require validated OS token; zero/transitional/logoff denied
PASS: native negative query error=1 session=rejected
PASS: portable frame and service binding validation
FINAL READBACK: service/tasks/ProgramFiles fixtures/processes absent
FINAL READBACK: upload staging absent
```

The Windows default negative mode was rerun after removing the service, from SSH session 0. Linux root CMake/CTest: **6/6 passed**; `service-client-negative-and-policy` still has `policy;windows-negative-requires-absent-service` labels. No CMake/CTest behavior was changed.

Local raw logs (scratch, not permanent release evidence): `/root/.hermes/cache/scratch/os-ipc-red.txt`, `os-ipc-policy-red.txt`, `os-ipc-acl-red.txt`, `os-ipc-green.txt`, `os-ipc-final-readback.txt`. The Windows upload staging directory `C:\Users\win11-pc\os-ipc-stage` was also removed and checked absent. No IdenGrid service or Profile was selected for modification or cleanup.

## Reproduce explicitly

Build the normal service and client test targets; the test mode is opt-in. Do not run the default negative test while the fixture service is installed.

```sh
cmake -S . -B /absolute/scratch/ipc-mingw \
  -DCMAKE_TOOLCHAIN_FILE=/absolute/path/to/mingw-toolchain.cmake \
  -DCMAKE_EXE_LINKER_FLAGS=-static
cmake --build /absolute/scratch/ipc-mingw --target \
  OrangeSpaceService orangespace-service-client-tests orangespace-service-policy-tests
```

In administrator **Windows PowerShell 5.1**, after reviewing the script and supplying actual expected hashes:

```powershell
./apps/windows-service/tests/check-scm-ipc.ps1 `
  -ServiceBinary C:\staging\OrangeSpaceService.exe `
  -ClientBinary C:\staging\orangespace-service-client-tests.exe `
  -ServiceSha256 <exact-service-SHA256> `
  -ClientSha256 <exact-client-SHA256>
```

The script requires exactly one existing logged-on Disconnected nonzero session, refuses to change an existing `OrangeSpaceFoundation`, creates a fresh protected Program Files directory, checks copied hashes, and uses the SCM API with an explicit quoted path, LocalSystem account, own-process and demand start. It creates a uniquely named **limited interactive-token** scheduled task for the OS-enumerated user, without a stored password. The task invokes `--installed-service --lifecycle-dir <fixture-results>`; `--installed-service` alone also runs the real positive query without orchestration. Lifecycle markers are test-only files, not protocol inputs or readiness flags.

`finally` stops/removes only the owned task/service, checks the owned service path before cleanup, reaps only fixture binary/runner processes, removes the fixture, and reads back absence and WTS state, including failures. Cleanup errors return 2 rather than success; validation failures return 1. Upload staging remains the caller's responsibility (it was removed in this acceptance run). Force-killing the administrator script/host is outside PowerShell `finally` guarantees; inspect exact emitted fixture/task paths before any manual recovery, never blanket-clean unrelated services or profiles.

## Limits unchanged

- Version 1 remains secret-free: status says `authenticated:false`, `browser_allowed:false`, `credential_ipc:false`; browser-open always denies. No ready/unlock flags.
- This does **not** complete credential IPC, persistent credentials, broker/helper authorization/integration, authenticated node login, restricted browser identity, CEF sandbox, WFP/DNS capture, or Phase 1.
- No full TLS node origin was chosen or bypassed.
- No independent second Windows account, active-WTS/multi-session runtime, real logoff/LUID replacement, exhaustive malformed live-client matrix, or all stop/ACK race schedules were exercised here. Existing malformed frame/native tests remain separate coverage, not new installed-service evidence.
- No GUI/browser was launched and no RDP state was changed. No commit or push was made.
