# UI return-ownership repair — injected policy evidence only

This slice fixes **only** the two confirmed worker return handoffs in
`src/main_win.cpp`; it does not claim end-to-end allocation-failure safety.
No backend/client DTO API, Store, JSON, CMake, native fixture/launcher,
logout/password flow, theme or browser gate is changed.

## Changes

- `SharedReturnSlot<Grant>` allocates its optional storage and shared control
  block before `authorize`. Its single-use `adopt(...) && noexcept` moves the
  returned non-default-constructible/non-assignable Grant into that storage and
  returns an aliasing `shared_ptr<Grant>` without allocating. Static assertions
  enforce nothrow move construction and destruction. Slot allocation failure
  precedes any authorize call.
- The tunnel worker immediately moves the acknowledged lease into `out.tunnel`
  before releasing the old capture and copying the Cursor's sandbox string.
  A compile-time check enforces nothrow Binding move assignment. Cursor-copy
  failure therefore leaves the exact new binding in the failed completion.

## Vertical RED / GREEN actually executed

Scratch prefix: `/root/.hermes/cache/scratch/`.

1. `ui-ownership-red-grant/result.log`: exit **1** on unchanged caller:
   `FAIL grant retention: acknowledged Grant missing after postreturn allocation failure`.
   The OLD-order positive control reproduced first.
2. Add only the preallocated ownership helper and authorize caller change.
   `ui-ownership-green-grant/result.log`: exit **0**, normal and cancelled
   successful-return cases retain/retire exact Grant with zero postreturn
   allocation attempts.
3. Extend the test to the exact tunnel worker body, before changing its order.
   `ui-ownership-red-tunnel/result.log`: exit **2**:
   `FAIL tunnel retention: cursor-copy exception loses new binding or cleans wrong generation`.
   Both OLD-order positive controls reproduced; the Grant regression stayed green.
4. Change only the lease transfer order and add its nothrow assignment assertion.
   `ui-ownership-green-tunnel/result.log`: exit **0**.
5. Final fresh runs: `ui-ownership-normal-final/` and
   `ui-ownership-asan-final/`, both exit **0**. Each compiles with
   `-fno-elide-constructors -Wall -Wextra -Werror`; the latter additionally uses
   ASAN+UBSAN with leak detection and non-PIE. Final tests include failing slot
   preallocation without reaching authorize, sticky allocation failure after
   returned Grant, exact retained Grant retirement, exact full Binding cleanup
   after real string-copy `bad_alloc`, old-generation owner release, and
   cancellation injected at each return seam. Allocation failure remains enabled
   throughout catches, retention checks and injected cleanup callbacks.

The runner extracts the actual production Grant, Binding, Cursor and TunnelLease
 declarations plus the actual two caller slices. It compiles the real shared
helper, not a reimplemented ownership algorithm. The authorize/start/cleanup
seams are deliberately injected local policy operations; the NodeSession input
is an unused test placeholder, **not a synthetic login accepted as real**.
OLD-order positive controls intentionally demonstrate lost logical cleanup
ownership; they do not leak real remote resources. No real RPC, HTTPS, DPAPI,
Windows GUI, remote grant retirement or helper stopping is exercised here.

## Reproduction

```sh
python3 apps/windows-client/tests/ui_ownership_tests.py --output "$TMPDIR/ui-ownership-normal-final"
python3 apps/windows-client/tests/ui_ownership_tests.py --output "$TMPDIR/ui-ownership-asan-final" --sanitize
python3 apps/windows-client/tests/ui_lifecycle_source_tests.py

g++ -std=c++20 -Wall -Wextra -Werror -pthread -fno-elide-constructors \
  -Iapps/windows-client/include apps/windows-client/tests/ui_lifecycle_tests.cpp \
  -o "$TMPDIR/ui-ownership-existing-lifecycle"
"$TMPDIR/ui-ownership-existing-lifecycle"

python3 apps/windows-client/tests/ui_ownership_gnu_build.py \
  --output "$TMPDIR/ui-ownership-gnu-final" \
  --archive-root "$TMPDIR/os-chain-parent-win"
```

Existing lifecycle behavioral tests passed fresh normally and under ASAN+UBSAN;
existing supplementary source wiring checks passed **5/5**. Existing tests were
not edited. The extraction runner is additional source-to-behavior wiring.

GNU Windows rebuilt `main_win.cpp`, `broker_win.cpp` and the real resource from
source with `-fno-elide-constructors`, then linked the existing real production
NodeSession/credential-store and service-client archives. Output is a Windows
x86-64 GUI PE; **not native Windows execution**, not MSVC STL acceptance, and not
re-attestation that those pre-existing archives match today's source. Archives
were read-only and their hashes checked unchanged across the build. Initial
manual linkage omitted `uuid`, producing undefined `FOLDERID_LocalAppData`; the
build script now explicitly supplies the existing required `-luuid` (no CMake or
dependency changes). Initial failure log is preserved as
`ui-ownership-gnu-final/initial-missing-uuid.log`.

Each final output directory contains `sha256.json`: source snapshots, generated
source, transitive compiler headers, compiler binary, traced persistent linker
inputs and output artifacts. GNU build also records commands and linker trace.
Current source snapshots for existing archives are explicitly not build-provenance
claims. Scope reverse-verification reconstructs the exact entry main hash
`801a4185fe5a8a30a5c5d98b6548154ed63e85fcf5fdfe3f57517d77a772b79a`;
`ui-ownership-scope/main_win.only-this-task.patch` contains only this task's hunks.

## Adjacent risks found — reported, NOT silently repaired

Current final-source references:

- `main_win.cpp:272` / `ui_lifecycle.hpp` `Drain::finish`: publication is followed
  by fallible map insertion **after** erasing the pending ticket. Persistent
  allocation failure can escape the worker and terminate the process. Grant
  retention at this repaired return seam does not make that later handoff safe.
- `Drain::retry` sets `cleaning_` before allocating/copying its batch; failure can
  leave the cleanup state latched and prevent future retirement.
- `main_win.cpp:481-482`: `pending_stops_.push_back` allocates outside the receiver
  try block. Its failure can lose the just-received lease's local stop ownership.
- `main_win.cpp:504-505`: erase from pending stops precedes potentially throwing
  tunnel-map insertion; failure can destroy the completion with no retained
  exact-binding stop owner.
- Earlier dispatch/completion setup still has fallible cursor/operation/string
  copies after taking an existing tunnel out of `tunnels_` and before assigning
  it to completion ownership (`:394-398`; analogous broker setup at `:441-442`).
  These are pre-existing old-lease handoffs, not the two newly acknowledged
  return sites authorized for this patch.

Those are concrete limits on the ownership premise. No fallback or broader
receiver/drain rewrite is included. Full-application persistent-OOM cleanup
acceptance remains blocked; parent independent review is required before
integration. No remote/Git mutation or native launch was performed.
