# Logout-initialization / callback-report recovery

Focused portable actual-caller evidence, **not Windows UI/DPAPI/IPC acceptance**.
No CMake, credential/backend API, native fixture or dependency changes.

## Product delta

- `LogoutState::request()` admits in-process logout intent without allocation.
  Uninitialized enumeration remains restore-blocked and cannot be mistaken for
  an empty, processed alias list. `cleanup_step` retries catalog enumeration
  independently of grant cleanup, and retries only unresolved erasures after
  successful initialization. Repeated logout and close preserve that intent.
- Literal failure notices contain both `wstring` construction and notice-body
  exceptions. The actual `window_procedure` also catches exceptions from the
  dispatched application callback without attempting an allocating error
  report. This prevents continued OOM in the idle identity refresh after a
  handled stop failure from escaping into Windows. Cleanup ownership is not
  cleared by the callback guard; zero vetoes cooperative logoff on failure.
- The existing exact return owners, mailbox/dispatch ownership, Drain pending
  tickets, retry snapshot, local-retirement versus server-logout semantics and
  pending-logout disk policy are preserved.

## Reproduce

```sh
python3 apps/windows-client/tests/ui_logout_recovery_tests.py \
  --case logout --output "$TMPDIR/ui-logout-recovery-logout"
python3 apps/windows-client/tests/ui_logout_recovery_tests.py \
  --case notice --output "$TMPDIR/ui-logout-recovery-notice"
# Repeat each with --sanitize for ASAN+UBSAN and leak detection.
```

The runner compiles actual production `logout`, `cleanup_step`, `begin_close`,
`finish_before_return`, `retry_stops`, notice methods and `window_procedure`,
plus actual catalog enumeration. The timer case, draining and idle portions of
`poll` are extracted, not the unrelated completion-processing remainder.
Win32 display/dispatch, identity refresh, service operations, catalog loading,
clock sleeping, worker and credential I/O are explicitly injected local seams.
The synthetic marker/blob flags are assertions of caller behavior only; the
existing pending-logout tests separately exercise production transaction policy.

Observed behavior includes every allocation in two long-alias enumeration
(one-shot and sticky faults), repeated logout/retry, reentrant close, actual
final-return gating across two persistent-failure intervals, deletion failures
before/after synthetic marker commit, service-down independence, remote-logout
failure accounting, late grant tickets, ordinary close and empty catalog.
The timer tests include exact multiple-lease retention, construction/body
reporting failures, an outstanding drain ticket, postreport identity-refresh
failure, retry and ordinary positive operation. No secret is logged.

## Executed evidence and boundaries

Evidence root: `/root/.hermes/cache/scratch/ui-logout-recovery/`.

- The preexisting `reproduce_gaps.py` reproduced both old actual-caller failures
  before edits, normally and with ASAN+UBSAN.
- `red-logout` failed the restore-blocked assertion; `green-logout` passed after
  only the logout-intent/init repair. `red-notice` failed nonescape;
  `green-notice` passed after containing literal-notice construction/body.
- The later real idle-poll continuation test failed at `red-boundary` despite
  the contained notice; adding the small actual Win32-entry catch made
  `green-boundary` pass. This is not a claim that the whole callback stack is
  allocation-free. Persistent OOM may prevent progress indefinitely.
- `run_regressions.py` and `regression-results.json` hold exact commands and
  exit codes for existing lifecycle/drain/caller/return-ownership/pending-logout
  tests, their sanitizer runs, supplementary source checks and GNU client build.
  Counts there are command checks (including builds), not native test totals.
- The GNU build reads existing node-session/credential and service-client
  archives. Their recorded hashes identify inputs; their source provenance is
  **not re-attested**. The GUI PE was linked, never executed.

Production source is frozen for independent parent review. No native Windows,
Microsoft STL, real credential deletion, service recovery, HTTPS remote
revocation, WFP/forwarding or complete-stage acceptance is claimed. Failed
precommit storage still has no durable offline guarantee; forced process
termination is not made safe by an in-process logout gate.
