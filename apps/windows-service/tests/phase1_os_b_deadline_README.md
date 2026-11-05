# OS-B deadline acceptance regression (portable injected seams)

This is the second and final automatic narrow OS-B repair candidate, not native acceptance.
Only `phase1_os_b_win.hpp` changes transport behavior; capture/profile/launch and the retained-operation policy remain unchanged.

Run from any directory, with output under an approved scratch directory:

```
python3 phase1_os_b_deadline_tests.py SCRATCH sync-read sync-write pending-event pending-result pending-transfer-event pending-transfer-result prep-read prep-write connect-ok connect-already connect-prep connect-pending-late final-progress final-write initial-expired sync-after ontime-read ontime-write ontime-pending ontime-connect ontime-connected ontime-connect-pending
```

Add `--sanitized` for ASAN/UBSAN or `--no-elide` for disabled copy elision. The runner extracts current helper/await/transfer/connect bodies verbatim on every invocation, compiles them with injected Win32/clock seams, and records commands, exits and source/body hashes. It does not emulate native cancellation timing or replace the existing ownership tests. The direct-await cases independently test acceptance after wait/result; transfer variants verify late bytes never reach the caller. The fourth clock observation in `final-progress` expires specifically after progress advancement and before final read-copy/success. All expiry seams use equality; `sync-after` also covers strictly later completion. Positive read/pending-read controls require actual caller copy; positive write/connect controls require success.

Evidence directory: `/root/.hermes/cache/scratch/osb-deadline-cycle2/`. Sequential behavior RED/GREEN results are in `sync-*`, `pending-direct-red`/`pending-green`, `prep-*`, `connect-*`, and `progress-*`. The original independent exact-body probe is separately reproduced in `original-exact-reproduction.log`; its successful exit means it reproduced both unacceptable late successes, not that deadline enforcement passed.

Checks use the original absolute deadline, never a renewed per-chunk budget: after operation allocation/handle/event preparation and write staging but before submission; after synchronous completion; after event wait and result retrieval; immediate connect success/ERROR_PIPE_CONNECTED; and after final progress before exposing bytes/success. Pending flags are established before any timeout throw on a submitted pending operation. Existing IoLease destruction retains exact operation/payload/event/pipe and permanently poisons admission if completion is uncertain. Terminal late completion remains a failed operation and can release terminal storage. Capacity one, max payload 98,308, finite 50ms cancellation grace, serialization and no detached thread remain unchanged.

SC1 exact-cipher/real-DPAPI+restore protocol, SC2 unknown-profile cleanup gates and LE1 retained lifetime keep their previous source-under-serialization review scope; this document grants no independent review approval. Whole B remains false. Original SeAssignPrimaryToken launch preflight remains before account creation. Native A relay, audit callbacks, protected recovery sink, privileged launch and Windows acceptance remain outstanding. Parent independent review is required. Any remaining blocker ends automatic repair: stop/escalate, no third cycle.
