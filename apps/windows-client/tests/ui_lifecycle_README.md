# UI lifecycle regression scope (S2 / L3)

Portable policy evidence only, not Windows IPC/DPAPI/HTTPS or GUI acceptance.
No CMake files are changed; run these focused tests explicitly:

```sh
g++ -std=c++20 -Wall -Wextra -Werror -pthread -fsanitize=address,undefined -fno-omit-frame-pointer -g -Iapps/windows-client/include apps/windows-client/tests/ui_lifecycle_tests.cpp -o "$TMPDIR/ui-lifecycle-asan"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 "$TMPDIR/ui-lifecycle-asan"
python3 apps/windows-client/tests/ui_lifecycle_source_tests.py
cmake --build /root/.hermes/cache/scratch/os-chain-parent-win --target OrangeSpace -j2
```

## Behavioral IDs

- S2-AUTH-LATE: a startup completion after close contributes its grant to retirement, not UI adoption.
- S2-RETIRE-RETRY: failed cleanup retains ownership and prevents completion until retry succeeds.
- S2-LOCAL-ONLY: ordinary exit invokes local retirement, never explicit remote logout.
- S2-PENDING-START: close waits for an outstanding start response as well as late authorization.
- S2-MULTISOURCE: two independently gated startup sources must both settle before drain completion.
- S2-REPEAT-CLOSE: repeated close is idempotent; new dispatch is denied.
- S2-ONE-OWNER: concurrent cleanup callers cannot duplicate retirement.
- S2-UNLOCKED-CALLBACK: cleanup can inspect/reenter lifecycle methods without holding its state lock.
- L3-ERASE-SERVICE-DOWN: erasure failures retain the restore gate independently of local-service cleanup.
- L3-IN-PROCESS-RESTORE-GATE: failed erasures block restore until successful retry in this process.
- L3-REMOTE-BEST-EFFORT: explicit remote logout failure is recorded; it does not suppress local retirement.
- L3-ALL-ERASES: attempt remaining aliases even when one erase throws.
- L3-BLOB-FAIL-SERVICE-DOWN: combined failed erasure and failed service cleanup cannot report completed logout.
- L3-LOCAL-REMOTE-SEPARATE: successful local retry never fabricates remote success.
- L3-RETRY: retry only unresolved erasures; retirement also retains its exact resource owner.

Thread barriers force completion ordering. Injected operations intentionally throw;
these are not mock assertions of successful real HTTPS or Windows cleanup.
The Python checks are supplementary source-wiring checks only.

## Still blocked / not claimed

1. CredentialStore now implements write-ahead, node-scoped current-user DPAPI
   pending intent inside its existing protected storage, without changing the
   public save/load/erase API. After intent commits, load/save reject the pending
   node before credential access; erase clears intent only after verifying exact
   original-node blob absence. See `credential_pending_logout_README.md` for the
   focused implementation, synthetic native unit and evidence boundaries. Source
   review and portable policy tests passed; actual limited-interactive Windows
   execution, real saved-session restoration and trusted HTTPS login remain
   unverified. Precommit failures have no durable guarantee. This is not remote
   revocation, power-loss acceptance, cancellation of already-returned sessions,
   or a ban on every explicit fresh-password authentication request.
2. Service op6 must idempotently acknowledge an already locally retired exact
   grant within the authenticated OS-peer boundary, including alias supersession,
   lost retire reply, and op4 remote failure after local detachment. Otherwise the
   UI truthfully retries forever; it cannot interpret an exception as stopped.
3. Native manager-close, direct DestroyWindow, WM_ENDSESSION, saved-DPAPI restore,
   service-down recovery, real helper/NodeLease disappearance and measured wall
   clock bounds need the parent's exact-artifact Windows fixture. Forced Windows
   shutdown/termination is not prevented by UI code. Individual calls use bounded
   typed transport attempts, but total cleanup retry time is deliberately unbounded
   on unresolved failure. UI IPC work is synchronous and may temporarily block the
   window; this is not an instant/cancellable shutdown claim.
4. Cursor hints survive in-process logout now, but persistence across manager
   restarts is deferred/nonblocking per clarified scope. No DB schema/protocol or
   local-identity authority is added.

Entry baseline already contained uncommitted service/UI work. This delta preserves
its brand/layout/browser gate; it does not own changes by parallel actors.
