# Per-node pending logout (focused Store delta)

## Production API and commit semantics

No new public methods or caller identity/path inputs: `save`, `load`, `erase`
remain the only `CredentialStore` API. `erase(catalog, alias)` is now a transaction:

1. Acquire a private per-node cross-process file lock (erase has a 2-second retry
   budget; save/load fail immediately on contention rather than queue through a
   successful erase and miss an already-cleared marker). Failure never bypasses
   protection.
2. Commit a current-user DPAPI protected **nonsecret** logout intent with the
   existing protected-directory/held-ancestor/native-relative atomic promotion
   pattern. Flush before and after promotion, read back ciphertext, reopen and
   DPAPI-verify the intent with user SID + catalog API origin + node UUID entropy
   and a separate logout-purpose suffix. No credential is written into this file.
3. Only after that commit, attempt deletion of the exact UUID `.dpapi` leaf.
4. Close the deletion handle and reopen that exact leaf under held ancestors to
   verify absence. Delete-pending, sharing violations and every uncertain state
   fail closed. Only then may the verified original-node marker be deleted.
5. Verify marker absence before returning success.

`load` checks marker presence **before reading/decrypting the API blob or making
HTTP requests**; `save` checks before extracting/encrypting the session envelope.
Both hold the same lock for their complete operations (including restore HTTPS),
so pending-marker creation cannot interleave between their check and use. Access
calls never wait behind a logout owner and then resume against a cleared marker. A load
that already owns the lock linearizes before logout; logout cannot claim commit
until it obtains the lock. UI generation/cancellation remains responsible for not
adopting an already-running result after a user click. Failed erasure leaves the
marker; queued loads/saves either time out or see it and fail. This is a logout
intent fence, not global revocation of already-returned in-memory sessions or a
fence against a separate future explicit save after cleanup has completed.

Any exception is **NOT COMPLETE**. It can also mean **NOT COMMITTED** if lock,
DPAPI, staging, promotion, flush or verification failed. The UI does not claim
cross-restart protection for an uncommitted attempt. If neither intent persistence
nor blob erasure nor remote revocation is possible, no durable offline guarantee
is claimed. A promoted marker is retained even if later verification fails.
The process-crash invariant starts at the successful commit point; no general
power-loss/hardware-cache guarantee is asserted.

Presence/corruption/unreadability/ACL drift/reparse state blocks restoration and
saving. Unknown marker bytes are **not** reset or removed, including on retry or
password login. `erase` only clears a marker it can authenticate under the
original node scope, after exact-blob absence. After restart, explicit logout
retries cleanup before a fresh password login can be saved. Normal close/op6
retirement does **not** invoke `erase` and preserves ordinary saved-login restore.
Existing UI all-alias retry and local-before-remote cleanup wiring are retained.

## Disk layout for the parent's real A-cipher/B-restore fixture

Existing current-user-only root stays unchanged:

```
%LOCALAPPDATA%\OrangeSpace-Credentials-v1\
    <catalog-node-UUID>.dpapi          existing user API credential ciphertext
    <catalog-node-UUID>.dpapi.logout   DPAPI nonsecret logout intent ciphertext
    <catalog-node-UUID>.dpapi.lock     persistent empty private lock leaf
    stage-<random-128-bit-hex>.tmp     transient protected ciphertext staging
```

The UUID filename is not identity authority. Scope comes from existing trusted
catalog entries plus OS-derived current-user identity; no username federation,
custom SID, alternate user-writable ledger or readiness permission is introduced.
A marker for A never gates B's different UUID. Same-UUID changed-origin state is
conservatively blocked and cannot clear the old scope's marker automatically.
Do not delete unknown production markers to make a test pass.

## Explicit build/run commands (no CMake changes)

From the repository root:

```sh
g++ -std=c++20 -Wall -Wextra -Werror -pthread -fsanitize=address,undefined -fno-omit-frame-pointer -g -Iapps/windows-client/include apps/windows-client/tests/credential_pending_logout_tests.cpp -o "$TMPDIR/pending-logout-asan"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 "$TMPDIR/pending-logout-asan"
python3 apps/windows-client/tests/credential_pending_logout_source_tests.py
x86_64-w64-mingw32-g++ -std=c++20 -O2 -Wall -Wextra -Werror -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -DNOMINMAX -D_WIN32_WINNT=0x0A00 -static -static-libgcc -static-libstdc++ -Iapps/windows-client/include apps/windows-client/tests/credential_pending_logout_native_win.cpp apps/windows-client/src/node_session_win.cpp -lwinhttp -ladvapi32 -lcrypt32 -lshell32 -lole32 -lbcrypt -luuid -o "$TMPDIR/credential-pending-logout-native.exe"
```

TDD evidence: missing transaction/access-policy/native helpers first failed the
focused compile, followed by passing builds; the UI stale-durability contract
failed before the narrow comment/message correction. Portable tests execute the
same production transaction ordering and pending gate with explicitly synthetic
fault storage. They cover commit/delete/absence/clear failures, copied disk state
across a modeled restart, cleanup retries and forced queued save/load ordering.
They do **not** prove DPAPI, Windows sharing/ACLs, HTTPS or GUI behavior. Supplementary
source tests check production gate ordering and no erase on ordinary close.

## Parent-owned native gates, NOT executed by this actor

Run the built EXE with **no arguments** through the already verified limited-user
interactive-token runner, not SSH session 0. No account/task/service creation is
performed here. The executable only creates random synthetic UUID fixtures,
self-spawns non-GUI children with nonsecret UUID/mode argv, and verifies exact
fixture cleanup. It never supplies credentials, calls a live login, or prints
secret material. Its synthetic plaintext is explicitly `SYNTHETIC-NOT-CREDENTIAL`;
it is a crypto/file unit, not a canonical real API session or password login.

The default executable includes real Windows cases for held-blob delete denial
**after marker commit**, abrupt self-`TerminateProcess`, another process checking
marker and surviving right-entropy ciphertext, retry recovery/idempotence,
bounded erase-lock contention and fail-fast access-lock denial, concurrent gate denial, origin/node
isolation, directory/malformed marker denial, actual rename-denied marker write,
marker ACL drift rejection/restoration and exact cleanup. The file-symlink
negative prints **SKIP** if ordinary-user symlink creation is unavailable; native
reparse acceptance remains pending in that case. A failing fixture must not be
counted as a pass, even if earlier lines printed success.

Still required separately: actual native execution and independent security
review; the parent's real A-cipher public API restore attempt under B/restart;
ordinary manager close retaining a real saved session; real trusted HTTPS fresh
password login only after successful pending cleanup; actual UI/service-down
logout/local-helper retirement/remote-revocation behavior. A GNU-static linked
artifact is not evidence that these native or end-to-end gates passed. The build
is provisional with respect to independently owned JSON/service changes.
