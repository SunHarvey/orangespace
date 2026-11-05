# Phase1 guardian slice B — review candidate, NOT fixture acceptance

`full_acceptance=false` unconditionally. Existing phase1 client/controller/runner quarantine is untouched. No native EXE, SCM operation, account, Task, remote command, production service or controller-crash experiment was executed to build this slice.

## Delivered boundary

- `phase1_guardian_policy.hpp`: executable portable cleanup policy and write-ahead intent cache, independent of Win32.
- `phase1_guardian_policy_tests.cpp`: real policy exercised against forced adapter states; these are models, NOT native SCM evidence.
- `phase1_guardian_intent_tests.cpp`: executable write-ahead cache/failure isolation tests.
- `phase1_guardian_win.hpp`: real Win32 protected-scope, receipt, identity and SCM adapter; no successful/no-op OS substitute.
- `phase1_guardian_driver.cpp`: independent, elevated guardian entry point; fixed own-service operations only.
- `phase1_guardian_fixture_service.cpp`: separate bounded dummy own-process LocalSystem service. NOT the production service and NOT helper/outer-SelfJob proof.
- `phase1_guardian_native_tests.cpp`: parent-review-only native identity/hash primitive tests, no SCM or persistent writes. Built, not run.
- `phase1_guardian_build.py`: offline Linux portable execution plus GNU static PE builds; never executes a PE or connects remotely.

## Exact APIs

Namespace `phase1_guardian`:

- `Report cleanup(Adapter&, unsigned poll_budget=20, bool remove_registration=true)`.
- `Report::{removed, quiesced, errors}` are separate observed outcomes, not an aggregate full-acceptance boolean.
- `Adapter`: `query`, `capture`, `has_root`, `start_attempted`, `valid_root`, `root_exited`, `helpers`, `valid_helper`, `helper_exited`, `before`, `stop`, `terminate_root`, `terminate_helper`, `remove_and_verify_absence`, `pause`, `record`.
- `IntentSet::prepare(bool known_root, unsigned helper_bitmask, Writer)` writes all current exact-object cleanup intents before the first effect. `permits(Action,index)` can survive a subsequent report failure, but a failed/missing prewrite never authorizes its own mutation.
- `State::{unknown, stopped, start_pending, stop_pending, running}`.
- Fixed public `Code` values: 0 ok, 1 inspection_unknown, 2 ownership_unknown, 3 journal_failed, 4 stop_failed, 5 terminate_failed, 6 exit_unknown, 7 delete_failed (reserved), 8 absence_unknown, 9 capture_failed. No raw Win32 exception/config/argv dumps.

Namespace `phase1_guardian::win`:

- `Scope(nonce)`: verified, held, non-reparse Program Files ancestor chain; protected approved metadata and hash-verified fixed EXEs. Fails closed; never changes existing permissions.
- `Approval`, `Identity`, `FileId`, `SelfClaim`, `Entry`: explicit packed binary metadata contract in the header, NOT an assumed secure-bootstrap module API.
- `describe(HANDLE)` / `same(Identity,Identity)` bind PID, creation FILETIME, image-path digest, SID/session/logon-principal digest, session and SYSTEM identity. No token bytes, handles, raw logon identifier, secrets, credentials or capability strings are persisted.
- `Journal(Scope&)`, `append(event,generation,identity,index,code)`: CREATE_NEW protected receipt, write-through + FlushFileBuffers, monotonically ordered records. A write/flush/inspection failure poisons further journal writes. Already durable narrow cleanup intents remain usable; new authority cannot be minted after poison.
- `WinAdapter(Scope&,Journal&,HANDLE actual_controller)`, `provision()`, `start()`, `owned()`, `generation()`, `next_generation()`, plus Adapter operations. The adapter duplicates and validates the actual approved controller object itself.
- `retain_helper(HANDLE actual, const Identity& approved)`: duplicates the actual object, verifies approved identity/SYSTEM/fixed guarded `sing-box.exe` + approved hash, and retains it before return. False is not enrollment success; previously retained objects remain tracked. This is in-process integration only, NOT a handle-transfer transport. The standalone dummy driver rejects `expected_helpers!=0`; helper transport/enrollment/outer-job guarantees are NOT implemented or claimed here.

## Parent approval and launch contract — no implicit authority

The parent must independently review source and artifacts BEFORE creating the fixture or running any native EXE. There is no installer/launcher in this slice, intentionally. No integration with another actor's unwritten guardedScopeMetadata/Channel/ReportSink is assumed.

For an approved root-only native fixture, the already-authorized elevated parent must supply:

1. A NEW `%ProgramFiles%\\OrangeSpacePhase1Guardian-<32 lowercase hex nonce>` root, owned/protected by SYSTEM/Administrators (trusted Windows ancestors may be TrustedInstaller-owned). Root and every held artifact must not grant untrusted write/delete/DACL/owner rights, and no component may be a reparse point. No ordinary SourceDirectory report destination is accepted.
2. Exactly named `phase1_guardian_driver.exe`, `phase1_guardian_fixture_service.exe`, and parent-written protected `phase1_guardian_approval.bin`, with parent-verified SHA256s and the real root volume/file ID. Artifact copies themselves remain hash-pinned and read-held. The guardian never creates or modifies this approval.
3. `Approval` fields: magic exactly 8 bytes `OSGAP001`, version 1, raw 32-byte lowercase nonce, real root FileId, raw 32-byte service and guardian SHA256s, zero helper hash for root-only tests, OS-derived expected controller `Identity`, immutable lease 1000..120000 milliseconds, expected_helpers 0. Build the structure with the reviewed header; do not guess ABI packing or identity digests from usernames.
4. An actual inherited controller process object with QUERY_LIMITED_INFORMATION and SYNCHRONIZE, matching that approval, and a byte-mode anonymous control-pipe read handle. Use an explicit HANDLE_LIST; inherit no secrets or unrelated handles. Parent closes its copies of the guardian's read end; only the guardian reads, and only the intended controller keeps the writer. This exclusive-reader premise is necessary for the peek/read-one-byte loop. This is a trusted fixture channel, NOT completion of quarantined S1/S2 credential IPC.
5. Launch the guardian with the existing authorized elevated token OUTSIDE EVERY Job. The guardian checks IsProcessInJob and refuses if in any Job; it never silently requests breakaway or enables privileges. Parent must independently verify it is not in the controller's KILL_ON_JOB_CLOSE Job. A controller-owned process HANDLE alone is not a kill-on-close Job.
6. Entry point: `phase1_guardian_driver.exe --guard <nonce> <decimal controller HANDLE> <decimal pipe-read HANDLE>`. No service names, executable paths, command lines, user configs, remote endpoints or lease renewals are accepted as control operations.

**Authority pause:** if the parent cannot provide this outside-Job elevated launcher, protected root/approval, or actual required SYSTEM-process observation/terminate access using the EXISTING authorized highest-user fixture authority, STOP. Ask narrowly for an approved outside-Job launcher/access premise. Do not add breakaway, SeDebugPrivilege, process/service DACL grants, another privileged service, scheduled Tasks or a user-writable fallback. No such additional authority was exercised or established by this Linux build.

## Fixed operations and ownership

Control bytes: `A` start, `S` final stop/cleanup, `C` crash the exact retained dummy root then cleanup, `R` quiesce/restart same owned registration, `Q` append current own-service state to the protected report. Unknown bytes fail closed and trigger cleanup. There are no free-form commands or handle/path import commands.

The guardian, not the controller, owns CreateService's returned SC_HANDLE, exact config readback and all retained actual process objects. It creates ONLY `OrangeSpaceFoundation`, own-process, LocalSystem, demand-start, error-ignore, no dependencies, exactly quoted fixed dummy path with no executable arguments. Existing service, inaccessible inspection, any prior receipt, or any generation-claim collision is refused; there is no adoption based on service name or 'looks like ours'.

The immutable provision intent, protected root ID/nonce, config digest, approval digest and guardian identity are durable BEFORE registration. Conditional stop/delete intents are prewritten before CreateService; root/helper identity and exact-object intents are prewritten as soon as acquired, before any kill. Post-effect records are attempted after each effect. A later reporting failure does not cancel the attempts against independently preauthorized known objects; it prevents a clean-success report and preserves the ledger. A failed inspection remains UNKNOWN, not absent.

A pending SCM PID is NOT process-ownership authority. The fixed dummy emits a CREATE_NEW protected generation-specific self-claim from INSIDE its SCM ServiceMain, with OS-derived identity. The guardian reads that exact claim, opens and validates the actual object, verifies SYSTEM + exact image/creation/principal identity and protected config, retains it, and receipts it. It cross-checks SCM PID in RUNNING, but does NOT require RUNNING to acquire during START_PENDING/STOP_PENDING, and does NOT kill a pending PID snapshot. Missing/zero/invalid/unprovable ownership is bounded wait then REFUSE, retaining receipt and registration for reviewed recovery.

Cleanup explicitly polls pending/running/stopped/unknown, attempts graceful stop when accepted, then conditional exact-held-object termination. SCM STOPPED is never process exit: actual retained root AND all enrolled helper objects must signal before delete. DeleteService, close the service handle, reopen readback must yield precisely ERROR_SERVICE_DOES_NOT_EXIST; access denied or marked-for-delete is not absence. Restart keeps the same first-provision receipt, increments a bounded generation (0..15), and retains historical exact exited process objects; it never deletes/recreates/reset-imports the ledger.

## Failure model and bounds

- Intended recovery model: ONE controller loss while the independently launched guardian remains healthy. Pipe loss, exact held controller exit, explicit stop and immutable lease expiry all enter guardian-owned cleanup. Root unexpected exit also enters cleanup. This is implemented source, NOT yet native-controller-loss evidence.
- Guardian itself must not be in the controller Job. No claim is made about the production service's outer SelfJob, native helper job shutdown, descendant completeness, WFP or final service acceptance.
- Simultaneous guardian loss, host power loss, storage failure, malicious elevated administrator, unknown helper history or Win32 permission failure is NOT magically solved. Receipts are retained, including partial/unknown outcomes. Existing receipts always refuse automatic re-adoption in this slice: post-guardian-loss takeover/replay requires a separate reviewed recovery decision, not a name/PID snapshot guess.
- Poll counts are bounded: watch 50ms, acquisition up to 40 failed watch polls, cleanup up to two 20-poll phases at 100ms, deletion readback up to 20 polls. These bounds do NOT bound SCM WinRPC, StartService, filesystem calls, scheduling or whole recovery wall-clock time. No hard cleanup deadline is claimed.
- Dummy deliberately exposes 750ms START_PENDING, 750ms STOP_PENDING, and 250ms process lifetime after SCM STOPPED; its own normal RUNNING wait is at most 30 seconds. Dummy timing does not prove production timing or any native interleaving until the parent actually tests it.
- Every receipt Entry has `full_acceptance=0`. Driver exit 0 means only its observed own-fixture cleanup and durable reports were clean; never full acceptance. Exit 20 means cleanup/report/watch failure/unknown; 21 prerequisite/native exception; 64 invalid invocation. No stdout writes are on the guardian critical path.
- The guardian never deletes its receipt, approval or root. Parent final forensic/fixture removal must be separately exact and verified after all held processes exit. No Linux personal data or profiles are touched.

## Actual local evidence and remaining native gates

Run offline only:

```
python3 apps/windows-service/tests/phase1_guardian_build.py
```

The scratch build manifest records exact argv, compiler versions, stdout/stderr, exit codes, current source SHA256s, PE SHA256s, sizes and import tables. It builds 3 real PE EXEs using GNU `-static -municode` and rejects dynamic libstdc++/libgcc/libwinpthread/VCRUNTIME/MSVCP imports; Windows system DLL imports remain. Both real portable suites execute on Linux. Sanitized portable runs were also executed; native EXEs were NOT run.

Observed vertical behavioral RED→GREEN cycles: pending PID/process-exit cleanup, independent protected self-claim capture even with pending PID zero, restart quiesce preserving registration, and durable intent cache surviving later report failure. Exact RED messages and commands are in the scratch handoff. Extended forced-state regression cases cover failed inspection/report/first helper cleanup without suppressing another known helper, PID-zero unknown ownership, journal denial, RUNNING→STOP_PENDING and write-ahead order. They do not emulate native SCM.

Native adapter changes are **compile-only**, NOT a claim of native RED→GREEN/TDD completion. Native identity/hash unit approval and then isolated protected-root/receipt/SCM tests remain required. Parent must separately test: ACL/reparse/collision/unknown-receipt refusal; real argument delivery and pending self-claim provenance; retained SYSTEM object identity; controller pipe loss and real held-parent death outside the controller Job; every side-effect/report fault; real STOPPED-before-exit; DeleteService/open-handle delay/readback; lease behavior; in-run restart preserving first ledger; and exact service/process/root cleanup. No controller crash or whole fixture Accept before those independent gates. Production-root handshake and helper enrollment are NOT integrated by this dummy-only module.
