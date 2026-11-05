# Extra UI stop/cleanup cycle — injected policy evidence, NOT native

Authorization: `/root/.hermes/cache/scratch/orangespace-extra-stop-cleanup-cycle-authorization.md`.
Exactly one additional production repair cycle; independent final review is still required.
Backend stop acceptance is blocked independently; these results do not approve the chain.

## Changes and retained owners

- `Drain::begin` preallocates the final optional resource node before worker/RPC dispatch. Failure of the second (pending) node allocation rolls back the empty node. `finish` finds that node, nothrow-constructs the actual Resource there and only then erases pending. No postcompletion map insertion or allocation; no GNU container-move assumption. Resource move construction/destruction are statically checked.
- `Drain::retry` constructs its fallible snapshot before setting `cleaning_`, catches snapshot exceptions and leaves every retained node intact. Cleanup callbacks remain outside the lock, callback exceptions remain handled, and a failed attempt never reports ready. Recovery retries remain possible.
- The receiver retains its mailbox and busy gate until pending-stop insertion succeeds. A throwing insertion restores the exact Completion to that mailbox without allocation and returns; a later poll can retry. Joining an already joined worker is guarded as before. Late-generation handling still occurs AFTER stop-owner retention.
- Tunnel-map adoption copies the shared owner into the fallible map slot BEFORE erasing pending-stop ownership, then resets the completion owner. Pointer copy/reset and vector erasure do not depend on GNU map move guarantees.
- Connect and broker setup copy, rather than remove, the old map owner. After successful dispatch they erase the UI map entry. The actual worker adopts the old owner into Completion BEFORE copying operation/local fields. Fallible capture/startup/thread setup therefore leaves the original map owner; fallible worker-field copying leaves the completion owner.
- The preallocated SharedReturnSlot Grant repair and immediate returned TunnelLease adoption are preserved. The only previous-test runner change is its exact tunnel extraction end delimiter (`});` instead of `}); return;`) because successful dispatch now has the map erasure afterward. The two previous test bodies and all lifecycle/source tests are unchanged.

No backend, DTO API, Store/JSON/server/native fixture/installer/CMake/Git/remote change. Theme/layout/browser denial, logout erasure versus ordinary-close saved DPAPI, stale-generation save gate and exact service binding calls are unchanged. No kill fallback or new framework.

## RED/GREEN evidence actually executed

Evidence root: `/root/.hermes/cache/scratch/ui-cleanup-cycle/`.

The finish and retry RED/GREEN slices ran first, followed by receiver, map adoption, Connect setup and analogous broker setup. Each selected production path was observed RED before its corresponding production change and GREEN immediately afterward. `red-*` and `green-*` logs/generated sources remain. The caller runner initially contained several case templates together; cases were activated one at a time. Thus **test execution and production changes were vertical, but caller test authoring was not fully one-case-at-a-time strict vertical TDD**; do not conceal that process limitation.

Final `run_final.py` produced `results.json`: 27 command checks matched their expected exit codes. This includes six old-order positive controls expected to exit 1, not 27 passing behavior tests. Old header controls are compiled from the exact entry header reconstructed and SHA-256-verified; old caller controls rerun the actual pre-fix extracted binaries. Retry control specifically reproduces `calls==1 && d.ready()` failure after allocation recovery, proving the latched cleaning state, not merely a propagated exception.

- Actual shared Drain: transient/persistent allocation sweeps, finish retention, predispatch rollback and retry after recovery; normal and ASAN+UBSAN.
- Actual extracted receiver/map-adoption/Connect/broker setup statements: transient/persistent allocation sweeps, recovery retry and an unrelated sibling owner; normal and ASAN+UBSAN. An injected `start` seam substitutes local completion allocation/call for native threading. The operation/lease fixtures are deliberately minimal; these are ordering/ownership tests, not actual RPC/native UI acceptance.
- Existing lifecycle behavior tests: normal and ASAN+UBSAN.
- Existing two return-ownership tests: normal and ASAN+UBSAN; old-order positive controls, sticky failure and cancellation still pass.
- Existing supplemental source wiring: 5/5.
- All C++ test builds use `-fno-elide-constructors`. ASAN+UBSAN uses non-PIE, leak detection and halt-on-error. The allocation hooks use real global `operator new` failure; allocation failure stays enabled through ownership checks. Sanitizers here do not establish Microsoft STL runtime behavior.

Reproduce:

```sh
python3 apps/windows-client/tests/ui_cleanup_callers_tests.py --slice receive --output "$TMPDIR/ui-cleanup-receive"
# Likewise --slice adopt, dispatch, broker; append --sanitize for ASAN+UBSAN.
g++ -std=c++20 -Wall -Wextra -Werror -pthread -fno-elide-constructors \
  -Iapps/windows-client/include apps/windows-client/tests/ui_cleanup_drain_tests.cpp \
  -o "$TMPDIR/ui-cleanup-drain"
"$TMPDIR/ui-cleanup-drain"
"$TMPDIR/ui-cleanup-drain" retry
python3 apps/windows-client/tests/ui_ownership_tests.py --output "$TMPDIR/ui-cleanup-return-owners"
python3 apps/windows-client/tests/ui_lifecycle_source_tests.py
```

## GNU Windows build and hashes

`gnu-current/OrangeSpace.exe`: real GNU Windows GUI PE compile/link, NOT native execution or MSVC acceptance. Existing real archives were only read and their SHA-256 checked unchanged across build. Their hashes identify build inputs, **not provenance proving that those archives match current source**. No archives were rebuilt by this UI task.

- main_win.cpp: `0de12fe21f38f89179c55959bba3a75f8f0330940e2e5058d86467db76a79910`
- ui_lifecycle.hpp: `2749ffc907496d14a1dc6819a4db46e51c3952ce4f546accf499dc0ada833b9f`
- OrangeSpace.exe: `f0c98e4ccb33b1bf0b524a9515a9e65da52e9658cbc74b5eef82970701cfe1b2`
- GNU full closure `gnu-current/sha256.json`: `76ba7a5f7a023d5850ab28b32cd69c99b86349484ef1c4bf8c6289bb731706ba`

A concurrent backend actor changed `service_chain.hpp` after the first `gnu/` build. The drift check detected this, and `gnu-current/` plus `ownership-current-normal/` and `ownership-current-asan/` were freshly rebuilt. Preserve the original build as historical evidence, not current closure.

Per-run manifests contain generated source, transitive compiler dependencies, compiler binary, traced persistent link inputs and output hashes. `delivery-sha256.json` consolidates the final test/build evidence; `main-only-cycle.patch` and `header-only-cycle.patch` isolate this task from the already dirty tree. `verify_scope.py` reconstructs the exact entry hashes `65b0cfb4573e98105362fdc063fa72c8490f720aff074d8a31297866c82ed814` and `43815966096dd70879250fec3cbcd2f89bb532896606697f1d7e3f1867d517ab`.

## Caller limits / unresolved acceptance

- Persistent allocation failure can prevent the retry snapshot or the RPC implementation from making progress. Ownership and the not-ready gate are retained; eventual cleanup requires memory/service recovery. No guaranteed progress under permanent OOM is claimed.
- Existing retained-grant/ticket history has no newly chosen cap/eviction/restart policy. Admission allocation failure happens before dispatch. This change does not establish whole-process memory boundedness or an exhaustion policy for the existing uint64 ticket namespace; no arbitrary resource cap or drop policy was added.
- Tests do not prove Win32 message-pump behavior, real SCM/HTTPS/helper stopping, DPAPI erasure, process-kernel errors, Microsoft STL runtime allocation behavior, WFP/DNS isolation or forced-process-termination safety.
- Backend stop was separately blocked and remains a separate verdict. Ordinary-close drain can confirm cleanup only when the service actually confirms retirement.
- No independent final reviewer has approved this delivery yet. Parent must independently inspect source/fault coverage and rebuild exact hashes before integration. No further production patch cycle was started after these named neighboring repairs.
