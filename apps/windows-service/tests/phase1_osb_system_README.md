# OSB SYSTEM admission-only candidate — NOT approved for host execution

Only these new `phase1_osb_system_*` test files are in scope. No production/OSB9/Base7/CMake/Git/SCM/remote changes. No Windows binary was executed, no service installed, no account/Profile created, no token/session/RDP policy changed. This is source plus GNU-static cross-build evidence, not SYSTEM runtime evidence or B acceptance.

## Fixed first slice

`phase1_osb_system_service.exe` is a one-shot, own-process SCM fixture. Console execution has no fallback: only `StartServiceCtrlDispatcherW` can enter ServiceMain, which additionally requires the compiled exact nonce service name and actual LocalSystem SID/session0. No executable paths, SIDs, commands or service targets are accepted through its CLI or ServiceMain arguments. No listener/pipe, Node/API, credentials, arbitrary command runner, installer or self-uninstaller exists.

The service reads its own actual SeAssignPrimaryToken/SeIncreaseQuota presence and enabled SeTcb, without enabling/granting privileges. It validates the compiled fixed root, held ancestors, self executable path, protected plan and fixed worker. Plan SHA-256 is compiled into the externally pinned service binary. The protected four-line plan is nonce / approved existing A SID / literal 2 / worker SHA-256, LF-terminated, with no other fields. This is public metadata, not a secret. The root must initially contain exactly the service, plan and `phase1_osb_system_probe_worker.exe`; DLLs, prior receipts and extra files deny admission. There is no B-worker mode, even dormant, in this slice.

All trust-chain handles use OPEN_REPARSE_POINT, no write/delete sharing, owner/effective DACL checks, canonical exact path comparison and single-link regular files, and are retained through child cleanup. The module root and files require protected DACLs; SYSTEM or built-in Administrators own them. TrustedInstaller ownership is permitted only for preexisting ancestors. Unknown effective ACE types fail closed. Ordinary-user effective writes, attribute/EA writes and delete-child permissions fail closed, including on ancestors. This deliberately conservative ancestor policy may reject a normal C: root ACL (e.g. create-subdirectory grants). The guardian must preflight it; **do not change system ACLs or quietly weaken the policy**. A policy refinement, if necessary, requires independent review before native execution.

A protected immutable intent receipt is written, flushed, read back and handle-renamed before token/process operations. Stage receipts are CREATE_NEW and atomically promoted without replacement; failure may retain `.pending` evidence. Receipts are created only in the held verified module root, explicit protected SYSTEM/Administrators DACLs, no raw service ImagePath/environment/token content. They carry plan/worker hashes, actual token SID/session/logon LUID, actual child PID/creation time, held worker file identity, job membership, exit/wait result, cleanup uncertainty, and explicitly `os_b=false`, `full_acceptance=false`, `scm_removal_verified=false`. Missing terminal receipt is **unknown**, never success. Flush/rename is not claimed to be a reboot-transaction guarantee.

The actual OS adapter obtains `WTSQueryUserToken(2)` and requires a primary TokenElevationTypeLimited token, session2 and the approved SID. It separately resolves WTS domain/user through LookupAccountName and compares the actual SID. No full-token/link-token substitution, LogonUser, account creation, profile loading, SetTokenSessionId/SetTokenInformation or RDP operation exists. If WTS returns a full token, the fixture stops rather than substituting one.

The only child is the hash-held fixed probe worker. `CreateProcessAsUserW` uses the real existing limited A token, explicit application path and only public expected SID/session/nonce args, scrubbed SystemRoot-only environment, no handle inheritance and CREATE_SUSPENDED with **PROC_THREAD_ATTRIBUTE_JOB_LIST at creation**. The unnamed non-inheritable job has KILL_ON_JOB_CLOSE, active-process-limit 1 and no breakaway. There is no post-assignment fallback. Only the SYSTEM creator retains the job handle; it is never duplicated to A. The actual hProcess/hThread are captured before any proof/resume, creation time/job membership and actual process token SID/session/logon/image are queried. The held child token is checked again for final proof. The worker executes its own OS token/session/limited/job checks and returns fixed success exit 63; stdin or a fabricated callback is not proof.

Stop is an event, not an arbitrary-PID kill: creator closes its job and bounded-waits its exact held child object. Normal child wait and cleanup wait are 10 seconds each. SCM/WTS/LSA/filesystem RPC calls are not real-time cancellable, so these waits are **not** a total service-wallclock bound. The external guardian needs bounded polling and honest unknown state, not guesses from PID reuse. On service process death the creator-only kill-on-close job is the containment mechanism; its actual SCM behavior is UNRUN. No self-job helper is imported or represented as approved.

## Portable tests and rebuild (Linux, no Windows execution)

From `/root`:

```sh
g++ -std=c++17 -Wall -Wextra -Werror \
 /root/projects/orangespace/apps/windows-service/tests/phase1_osb_system_policy_tests.cpp \
 -o /root/.hermes/cache/scratch/phase1_osb_system_policy_tests
/root/.hermes/cache/scratch/phase1_osb_system_policy_tests
PYTHONDONTWRITEBYTECODE=1 python3 /root/projects/orangespace/apps/windows-service/tests/phase1_osb_system_contract_tests.py
PYTHONDONTWRITEBYTECODE=1 python3 /root/projects/orangespace/apps/windows-service/tests/phase1_osb_system_build_tests.py
```

Builder takes an explicit approved SID, 24 lowercase hex nonce and fresh direct scratch output child. It does not install/run anything. Example compilation fixture SID below is **not the actual session2 SID and is not approval for native execution**:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 \
 /root/projects/orangespace/apps/windows-service/tests/phase1_osb_system_build.py \
 --nonce 4ad26b9f0736c18d52a0e7bf \
 --approved-sid S-1-5-21-1-2-3-1001 \
 --out /root/.hermes/cache/scratch/phase1_osb_system_REVIEW_BUILD_FRESH
```

GNU cross-builds use -static/-static-libgcc/-static-libstdc++, warnings-as-errors and deterministic PE timestamp flag. The scratch provenance JSON records exact source hashes, generated config hash, plan/EXE hashes and sizes, complete compiler command/version and DLL imports; full objdump import output is retained. No libgcc/libstdc++/winpthread/VCRUNTIME/MSVCP dynamic runtimes are allowed. System DLL imports, including Windows msvcrt, are not evidence of native execution or MSVC release qualification.

TDD: portable orchestration/identity was first observed failing to compile due to missing policy; source adapter contract failed with the missing service; builder validation failed with missing builder; later ACL, child-proof and plan-parser tests each failed for missing functions before implementation. API-error separation and receipt-metadata contracts likewise failed before changes. Native-source assertions are secondary inspection only, **not** a substitute for native WinAPI fault-injection/runtime tests. Portable tests exercise the same policy predicates and sequencing used by the actual adapter; they do not emulate Windows security.

## Exact future guardian adapter contract — after independent parent review

No installer is provided or authorized to run here. The separately reviewed `phase1_guardian_*` owner must consume the immutable profile from `phase1_osb_system_provenance.json`:

* Exact tuple: `service_name`, `module_root`, service leaf+external expected SHA-256, manifest leaf+external expected SHA-256, worker leaf+external expected SHA-256. Hashes must come from the protected parent-approved build report, **not** a manifest supplied by an ordinary caller. Rebuild with the protected approved **actual existing session2 SID**, new nonce and fresh root. Independently verify source/config/PE digests/imports before provision.
* Pre-provision only the compiled `C:\Program Files\OrangeSpace-OSB-Admission-<nonce>` root with protected SYSTEM/Administrators ownership/DACL and limited A RX (no write) on worker/root as required. Hold and verify exact ancestor/root/file objects; reject reparse/hardlink aliases and extra DLLs/files before service startup. Do not stage a LocalSystem executable under ordinary Temp. Existing ancestors must pass without policy changes; failure is a STOP/review requirement.
* Create only `OrangeSpaceOSBAdmission-<nonce>` as SERVICE_WIN32_OWN_PROCESS, LocalSystem, demand-start, no recovery/restart actions, no interactive flag, protected service DACL, explicitly quoted exact image path and **no arguments**. Refuse collisions rather than taking over an existing registration, never use OrangeSpaceFoundation, never accept arbitrary service-control targets. Read back config, object ownership, SID/account, image hash/root and exact service process object/creation time before attribution.
* Independently retain the exact service process handle and recover using exact objects, not PID names. Exercise normal completion, STOP before/during spawn, job-list unsupported/failure, ACL/hash/SID/limited/session mismatch, receipt write/rename failure and exact service hard-death containment, with truthful unknown handling. No forced kill of unknown/reused PIDs; no kill of A's existing session or shell.
* Reconcile protected receipts with exact process handle/token/session/image, creation and actual exit observations. On missing receipt or uncertain wait, keep an error receipt/evidence and never claim cleanup. Stop/remove only the owned fixture registration; independently read back SCM absence and exact child/service exit, then remove and read back only the owned test root/files. Service code cannot assert SCM removal, so full cleanup remains parent-owned and false until externally verified.

## What this does NOT resolve

Actual read-only evidence already established session2 linked full A lacks SeAssignPrimaryToken while SeIncreaseQuota is present, and limited/full logon LUIDs differ. Nothing here changes the old OSB9 guard or uses high A to bypass it. B accounts/credentials/Profile/IPC are absent. Authentic SYSTEM privileges, WTS token identity, atomic job-list creation, stop/death cleanup and SCM removal all remain native **UNRUN** gates. The first native positive result can only establish SYSTEM admission and a real limited-A atomic-job child, never cross-user B or product-service acceptance.

Future B placement requires a separate explicit reviewed decision: an actual B primary token obtained by an authorized route must be shown to occupy the intended session under sufficient existing authority, with correct logon/profile/account lifecycle and guardian recovery. A LogonUser B token cannot be presumed to inherit session2, and full A's different LUID cannot be treated as limited A's identity. Do not mutate A's token, grant SeAssign to A, change RDP or weaken the original guard to make B run. No such future capability is enabled by this candidate.
