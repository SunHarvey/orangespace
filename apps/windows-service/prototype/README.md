# Independent offline Service — native acceptance candidate

Only this prototype directory changed. Frozen SCM name, admission pipe, client,
manifest TSV contract, runtime pins, old gates and Foundation remain unchanged.
No proxy/Node grant, remote action, SCM install or privileged filter execution.

## Actual source path

* LocalSystem SCM instance PID readback; waits for exactly one active unlocked WTS
  session without creating a root while WTS is unavailable. OS token user/session/LUID.
* Closed protected SHA256/size/path TSV inventory, 1 MiB/4096 entries. Retained handles
  deny write/delete sharing; strict app directory/files; single-link files; reject
  reparse entries before recursive traversal. Ancestors alone accept TrustedInstaller
  ownership, skip inherit-only ACEs, and distinguish ADD_SUBDIRECTORY from replacement.
* Persistent exact four-layer AppID Offline policy before root creation. Never remove
  policy on failure or destructor. Fresh AppContainer, no capabilities, suspended root,
  unnamed noninheritable kill-on-close/no-breakaway Job and exact process assignment.
* Explicit scrubbed environment from OS directories, WTS profile/known folders and
  own AppContainer Temp; no inherited SYSTEM environment or user secret variables.
* ProcessObservationAcl reused unchanged: append user and exact package query-limited
  plus synchronize grants after baseline ACEs/denies, with actual readback.
* Live proof computes eight individual evidence bits from retained kernel objects,
  exact root token, user/session/LUID, WTS state, Job limits/member, pinned runtime,
  four Offline filters, zero-capability package SID, self SCM/System, and stop state.
  DNS bit denotes the same kernel premises as the independently reviewed native DNS
  ACCESS_DENIED case; it is NOT packet trace or CEF compatibility acceptance.
* CSPRNG 16-byte Job cookie and per-root generation/epoch. Bounded length-prefixed
  SHA256 snapshot includes verified filter IDs, rule kinds/layers, native keys/action,
  AppID, path/image hash, explicit/effective weights/flags and actual filter security
  owner/group/DACL SDDL. Re-enumerates exact policy after by-ID readback.
* Live proof and listener precede SERVICE_RUNNING, which precedes ResumeThread.
  Provisional -> ACK -> exact peer/process and same snapshot revalidation -> complete
  status-2 frame. Replay registration/ownership prepared before provisional grant.
* At most 64 retained concurrent worker connections (lifetime bound, no recycling).
  Each retains exact process and pipe; disconnect, unexpected bytes, process exit,
  root/session/stop or proof drift revokes the owned Job, retaining persistent deny.
  No process-name killing or PID lookup cleanup. Exact root TerminateProcess and
  bounded wait also cover failures before Job assignment.

## Evidence and remaining acceptance

Portable request/binding/snapshot tests exercised RED then GREEN for new snapshot
comparison and bounded canonical encoding. They cover identity/nonce/ACK drift,
rule digest/generation/epoch/cookie/owner drift, ambiguous concatenation, null/oversize
fields and 1 MiB cap. These are policy tests, not native Windows execution.

Parent owns the native build lock. This completion deliberately does not run a
parallel native build, SCM, remote host, browser or WFP mutation. Native SDK build
and independent review are required before privileged execution. Keep actual client
OpenThreadToken, SCM access, System process/token observation, restricted lowbox pipe
access and CEF child compatibility as tests; do not bypass any of them. Packet/CEF
acceptance remains pending but is no longer a circular pre-Resume hardfalse.
Profiles conservatively retained even after exit; no guardian prerequisite or unsafe
cleanup. OS process-token access and lowbox environment/Temp ACL compatibility need
real Windows evidence. Large payload hashing occurs once under retained deny-write
handles, not on each bounded ACK.

Portable tests:
```
cmake -S apps/windows-service/prototype -B <private-build>
cmake --build <private-build> --target orangespace-single-binding-tests
ctest --test-dir <private-build> --output-on-failure
```
Windows target `OrangeSpaceSinglePrototype` links existing WFP implementation and
windows_security primitive plus advapi32/bcrypt/userenv/wtsapi32/fwpuclnt/shell32/ole32.
Do not describe this source candidate as a tested working offline CEF product.
