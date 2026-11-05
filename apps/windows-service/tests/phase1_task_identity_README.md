# Fixed NONSECRET Task identity premise diagnostic — NOT ACCEPTED

**Source/compile candidate only. No Windows run is authorized by this document. Independent parent review is required first.** This is neither a guardian, P/J sentinel, Store/credential launcher, SCM service nor a generic executor. No other phase1 module is imported or approved by it.

## What this slice actually attempts

One externally fixed existing-admin UserA observer, one fixed limited UserA InteractiveToken Task and one fixed action image. Both images accept **no arguments**. The action only sleeps and exits; it has no pipe, file/report writer, credentials, child launcher, self-PID report or exit-code witness. The observer alone produces protected NONSECRET records using actual OS/COM observations. Its result is **always INCOMPLETE / further_admission=false**, including the most favorable comparison. There is no READY/success/worker-body-executed state.

This explicitly uses the **cooperative, existing-admin trusted-foreground synthetic-fixture model** selected by the parent. It does **not** resist a hostile same-SID process terminating or injecting into the observer/action through default process/thread security, a concurrent privileged namespace/ACL writer, a compromised scheduler/OS/build chain, observer/SSH loss, or host/storage loss. Nothing hardens existing process/thread DACLs. An exit status, Task result, self PID, image pathname, different PID/parent or account membership is not evidence that the worker body executed, Job independence, or SYSTEM-process rights. No explicit privilege-enabling call is made; that is **not proof that every OS API avoids temporarily enabling an already-held privilege internally**.

### Binding finding: deliberately incomplete

`IRunningTask::EnginePID` is documented as the engine process ID, not as a returned retained handle to an executable action process.[1] The protocol description associates an instance GUID with a task-instance PID and current action ID, but the inspected contract does not supply this implementation with a retained actual action-process/mapped-image object or a reviewed bridge when the engine is a different process.[2] This is a concrete missing premise here, **not a claim that no Windows solution exists**.

The candidate calls actual COM `RunEx`, captures its returned instance GUID/path, reads actual `EnginePID`, opens **only that OS-returned process**, and retains that process object through cleanup/report readback. It queries actual process creation time, full image path and token SID/session/authentication LUID/integrity/elevation type/elevated/restricted/AppContainer status and privilege LUID/attribute observations. Only if the engine's actual image path equals the locked fixed probe path does it compare the separately supplied probe token expectations, creation window, repeated instance GUID/EnginePID, running state/current action and process-object liveness. The locked fixed-image object's volume/file identity and digest are separately recorded and rechecked; pathname equality is **not promoted to proof of the mapped image/action object**.

- Different/unknown engine: INCOMPLETE; no parent/child snapshot search, self-report PID adoption or guessed action-process kill.
- Favorable engine/image/token/creation recheck: still `action_binding_unproved`; no inference that EnginePID must be the executable-action PID.
- No independent actual action-process acquisition/mapped-image binding producer is implemented. Therefore exact action-process cleanup remains UNKNOWN even if an engine object signals or Task cleanup succeeds. **Stop here: no further work, guardian, service or credential admission.** This missing producer needs an independent source/API/native disposition; it must not be replaced by another self-report or exit-code witness.

`RunEx` returning success alone need not mean execution occurred; documented settings/disabled-task cases can suppress execution.[3] Flags are fixed to the documented session-ID and SID values (0x4 and 0x8); the installed MinGW header omits their enum declarations, so local named constants use those documented values.[6] No constraints-ignore/as-self option is provided.

## Fixed storage and authority contract

Build input is an externally protected **NONSECRET assertion**, not authentication merely because the parser accepts it. Its exact fields are:

```
purpose: compilation-fixture | external-os-input
nonce: exactly 32 lowercase hex characters
program_files: actual OS canonical drive-letter Program Files path
sid: actual existing UserA account SID, not a username or SYSTEM SID
observer_session, observer_luid: actual admin observer primary-token observations
probe_session, probe_luid: independently OS-derived existing interactive UserA expectations
root_volume, root_file_id, evidence_volume, evidence_file_id: actual fresh NTFS root identities
```

Only the conservative `X:\Program Files` spelling is supported. A different actual OS location is a STOP, not normalization or a request to change it. Probe session must be nonzero and fit RunEx's signed LONG. Each LUID is compared to its independently supplied role expectation; equal/different LUID numbers authenticate neither value. The observer role is fixed high-integrity/full-elevation/enabled-Administrators membership, and the action role is fixed medium-integrity/limited/non-elevated; both require the exact UserA SID, no restricting SIDs and no AppContainer. Unknown or different native facts stop this attempt. Privilege snapshots are observations, not inferred new rights.

Roots/basenames are fixed, with no runtime path/mode/command input:

```
<OS ProgramFiles>\OrangeSpacePhase1TaskIdentity-<nonce>\
    phase1_task_identity_observer.exe
    phase1_task_identity_probe.exe
    plan.bin
<OS ProgramFiles>\OrangeSpacePhase1TaskIdentityEvidence-<same nonce>\
    recovery.bin
    report.bin
Task: \OrangeSpacePhase1TaskIdentity-<same nonce>
Action ID: fixed-nonsecret-probe
```

The trusted external bootstrap/operator must independently authenticate the reviewed source/build provenance and the **external seal digest plus both image and plan digests**, before starting the observer at the exact fixed path. The builder first compiles the probe, fixes its digest in a canonical plan, then embeds that plan digest/expectations in the observer. The final external `seal.json` pins observer/probe/plan separately. The observer digest is intentionally **not** inserted into its own compiled plan hash. The observer's held self-digest is only a continuity observation; it cannot authenticate its own bootstrap. Root ACL protection does not manufacture this external producer's provenance. No bootstrap/provisioning script or external authority producer is implemented here.

The observer retains non-reparse ancestors, both directory objects, plan and both image files without write/delete sharing; checks final paths, volume/file identities, owner/DACL/control/effective mutating allows; hashes held files before launch and rechecks continuity through final readback. Leaf objects must be owned by SYSTEM/Administrators with protected non-null DACLs. TrustedInstaller is an ancestor-only privileged-owner/ACE exception. Ordinary read/execute allows are permitted; effective ordinary mutation/delete/parent-delete/ownership/DACL authority, unknown ACE kinds and unknown protection are rejected conservatively. Inherit-only ACEs are evaluated as ineffective on that held object, not silently treated as a broad current-object grant. This is a conservative rejection policy, **not** a complete native AccessCheck/effective-access proof.

**Normal drive/Program Files ancestors or existing sharing handles may fail this conservative policy. STOP and report. Never repair existing ACLs, enable privileges, switch roots to user-writable paths or quietly relax this predicate.**

Both fresh records are created/read back **before** Task creation. They have explicit protected SYSTEM/Administrators-only full-access DACLs, no ordinary writer, `CREATE_NEW`, no inherited handles, held identity/path/ACL readback, write-through/flush and an 8192-byte bound each. Existing records/root collisions are not adopted. These are bounded diagnostic snapshots, not a crash-transactional enrollment/recovery journal. A failed write/readback/size/continuity check is incomplete; it does not prove durable final recovery, and no remaining record/root is deleted. The action writes nothing: no privileged writer follows a worker-controlled output pathname or treats worker bytes as authority.

## Exact Task ownership and limited cleanup

The source uses fresh `TASK_CREATE` only, `TASK_DONT_ADD_PRINCIPAL_ACE`, a protected SYSTEM/Administrators-only Task SD, existing UserA SID/InteractiveToken/LUA, no triggers, one fixed executable action, no arguments, fixed protected working directory, one-instance policy and a fixed execution-time-limit setting. Creation/readback warnings are incomplete, not successful absent-object assertions. The source independently reads back principal, actions/cardinality, settings, XML and Task owner/DACL before run and cleanup. The no-principal-ACE flag and existing-interactive-token semantics are documented contracts, not native observations from this delivery.[4]

Cleanup uses only the retained returned running-instance COM object and the newly registered fixed Task after unchanged-definition/SD checks. `IRunningTask::Stop` targets that instance.[5] If stop/readback succeeds, own-task instance count is zero, configuration remains exact, deletion succeeds and exact-name absence is read back, Task cleanup alone may be recorded absent. This is not action-process exit proof. Unknown registration/start/configuration/stop/deletion outcomes retain recovery state; no pre-existing Task, guessed PID, process name, broad task listing or recursive directory deletion is adopted. Concurrent privileged byte-identical replacement is outside the explicit trusted-foreground model; Task name/XML comparison is not an atomic namespace identity primitive.

No actual action process has been authoritatively bound, so no generic process termination is attempted. The fixed sleep and scheduler execution-time-limit setting are not kernel-exit witnesses or a hard wall-clock guarantee. COM/RPC, synchronous filesystem/token/security operations and cancellation/stop completion can block. Finite polling counts do not establish a total real-time bound. Both roots and all records remain for the external owner; complete cleanup is **not** claimed.

## EXACT future preflight/provisioning requirements — NOT execution instructions

1. Independent parent review of these exact new sources/tests/builder and all missing-premise statements, before **any** Windows run. Current compilation-fixture PEs must never be substituted for an actual-identity approved build. A source/build pass is not native authorization.
2. Trusted external parent, in the already-existing authorized UserA administrative context only, independently obtains actual SID and **both** primary-token role expectations from trusted OS process/token objects under existing query access. Do not use a worker claim, copy the SSH LUID into the interactive expectation, require SYSTEM/WTSQueryUserToken, grant rights, enable privileges, create an account or change/reconnect RDP. If these actual independent token observations are unavailable: STOP; the `external-os-input` label does not fix that missing producer. Existing disconnected nonzero UserA session is only for non-GUI diagnostics.
3. The external owner creates **fresh**, nonce-scoped, local fixed-disk NTFS roots at the above names with protection from creation, records actual directory volume/file IDs, verifies no reparse ancestor, no untrusted existing write/mapping handles, no pre-existing exact Task/record, and tests conservative ancestor policy **without modifying existing ancestor ACLs**. Parent provisioning happens only after review; it is not done by this source. Required query/security/file-share access must already succeed.
4. Build afresh from protected actual inputs. Re-review any generated actual configuration and resulting source/dependency/artifact hashes. Externally pin/authenticate the resulting seal and the exact two images/plan; provision only those three inventory files into the image root, with SYSTEM/Administrators ownership/protected DACLs and only ordinary read/execute rights needed by the limited action. Evidence root must have no ordinary mutation authority. No prior build/root/record is reused. If actual root identities are not yet obtainable, remain at compilation-fixture stage rather than inventing them.
5. The external bootstrap authenticates its **own** execution chain, exact observer image, fixed paths/held roots and trusted OS DLL/COM dependencies and controlled launch environment/current directory. Installed MinGW import-library hashes/import names are not Windows runtime DLL provenance. The bootstrap must not authenticate itself by checking an untrusted copy of its own hash/plan. No handle-inheritance or credential transport route is supplied here.
6. Only after independent review **and separate native execution approval**, a future run may collect the OS/COM diagnostic observations. Any SID/session/LUID/elevation/restriction/ACL/path/hash/sharing/access/Task/configuration uncertainty stops. Engine/action binding uncertainty always leaves admission false. Native denial controls and actual exact Task/process/root cleanup must be independently observed before claiming them; none were run here. Do not reinterpret ordinary inaccessible-engine/query failures as security success.
7. Independently acquire/verify an authoritative actual Task-instance-to-action-process/mapped-image object binding, or retain the explicit missing premise and stop. No self PID/exit witness, child snapshot, task name/path, RunLevel or fresh nonce can replace it. The current source deliberately has no success path for this gate.
8. After exporting and externally verifying any protected records, the external owner alone resolves exact remaining objects. Keep unknowns/recovery; no guessed PID kill, name adoption, broad delete or deletion of the sole unresolved evidence. Source only attempts the exact own Task cleanup described above. P/J crash sentinels, controller-specific Job membership/survival, full protected producer/enrollment, actual disposable/future service SYSTEM-object rights, SCM/Store/credential execution and hostile-peer security remain separate future gates.

## Local-only build/tests

The builder requires an already installed GNU MinGW compiler and Python standard library. It installs nothing, does no Git/CMake/remote work and never executes a PE. `--out` must be a fresh local scratch directory; it is not a runtime/external task command destination.

```
python3 apps/windows-service/tests/phase1_task_identity_builder_tests.py
python3 apps/windows-service/tests/phase1_task_identity_source_tests.py
g++ -std=c++20 -Wall -Wextra -Werror apps/windows-service/tests/phase1_task_identity_policy_tests.cpp -o <own-scratch>/policy-tests
<own-scratch>/policy-tests
python3 apps/windows-service/tests/phase1_task_identity_build.py --input <protected-local-input.json> --out <new-own-scratch-build>
```

`purpose=compilation-fixture` is marked in plan/config/seal, and both native entries refuse it before filesystem/COM/token/Task side effects. A volatile read preserves compilation/linking of the authored Windows body for meaningful import/dependency inspection; it is not a supported bypass or a hostile-memory-tamper defense. The builder captures compiler dependency closure and traced stable linker inputs, hashes them before the fresh final GNU-static builds and after artifacts/import inspection, and fails on drift. Transient compiler-owned object bytes are not falsely represented as independently hashed stable inputs. Final readback after local tests must recheck the same manifest. External provenance of installed tools/libraries is a separate trust requirement.

Tests label compiler/source-contract absence REDs as such, never native behavior. Portable policy/ACE tests and deliberate scratch-only negative-control mutants exercise actual local decisions, not Windows ACLs, Task Scheduler, process identity, worker execution or cleanup. Windows authored diagnostics remain unrun and unapproved. See the task-specific scratch handoff for exact RED/GREEN outputs, artifacts, imports and hashes.

## Sources

[1] https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-irunningtask-get_enginepid
[2] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/a2a53b07-b2f7-477c-a30c-46613f40519f
[3] https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-iregisteredtask-runex
[4] https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itaskfolder-registertaskdefinition
[5] https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-irunningtask-stop
[6] https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_run_flags
