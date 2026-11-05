# Standalone service process Job tests

These tests do not install/start an SCM service, change accounts or policy, use
Node APIs, or launch a browser. They intentionally remain outside CMake pending
independent review. Run from the repository root.

## Cross-build (Linux MinGW-w64, Windows x64 execution required)

Use a fresh owned scratch output directory and these exact executable basenames
(the read-only cleanup audit recognizes them):

```sh
OUT="$TMPDIR/orangespace-selfjob-owned"
mkdir "$OUT"
CXX=x86_64-w64-mingw32-g++-posix
COMMON="-std=c++20 -Wall -Wextra -Werror -O2 -static -static-libgcc -static-libstdc++"
$CXX $COMMON -municode -DSERVICE_PROCESS_JOB_BASELINE \
  -I apps/windows-service/include \
  apps/windows-service/tests/service_process_job_native.cpp -o "$OUT/selfjob-red.exe"
$CXX $COMMON -municode -I apps/windows-service/include \
  apps/windows-service/tests/service_process_job_native.cpp -o "$OUT/selfjob-native.exe"
$CXX $COMMON -I apps/windows-service/include \
  apps/windows-service/tests/service_process_job_failures.cpp -o "$OUT/selfjob-failures.exe"
python3 apps/windows-service/tests/service_process_job_startup.py
sha256sum "$OUT"/*.exe
```

Copy only these owned artifacts to a fresh authorized Windows temporary directory,
using the environment reference's explicit SSH identity and pinned known-hosts
file. Read back each Windows SHA-256 before execution. No execution-policy change,
PowerShell runner, task, elevation, or service registration is needed. Run directly:

```text
selfjob-red.exe          expected exit 1: gap child_exit_before_fallback=false
selfjob-native.exe audit expected exit 0: no remaining exact-path fixture processes
selfjob-native.exe       expected exit 0
selfjob-failures.exe     expected exit 0
selfjob-native.exe audit expected exit 0
```

The baseline macro omits ONLY installation/inspection of the production SelfJob;
it is not compiled into production. Actual pre-implementation native RED was
observed before creating the production header. Rebuilding the final fixture with
the macro retains a reproducible missing-premise negative control.

## Kernel assertions

- A private bounded activation read (five seconds, exits on EOF) prevents the owner
  from creating any child before its supervisor assigns the fallback cleanup Job.
  The EOF case is actually exercised before fallback assignment.
- The supervisor retains actual owner/child/grandchild process handles. It hard
  exits only its exact owner with `TerminateProcess`, waits for owner kernel exit,
  then requires each held descendant handle to signal **before** fallback Job
  termination/close. Dummy children ignore stdin/EOF and wait forever.
- Gap: one live child, no inner Job at all. This is the outer SelfJob-specific
  death proof; fallback still owns its open Job handle throughout observation.
- Nested: inherited outer membership followed by single-member inner Job admission.
  Inner Job death can also contribute in this case; it is a compatibility proof,
  not independent attribution of death to the outer Job.
- Multiprocess: two owner children plus one grandchild are simultaneously alive,
  demonstrating that the outer Job does not impose the helper's single-member cap.
- Normal return: supervisor requires witnesses after the owner's function returns
  to `wmain` and during CRT static destruction, then descendant kernel exit. This
  catches premature RAII self-Job close before normal process teardown.
- Native queries require exactly KILL_ON_JOB_CLOSE, zero active-process limit,
  non-inheritable handle, empty object name, actual current-process membership, and
  no handle-count increase/replacement after sixteen repeated installations.
- Failure test injects Create/Set/Assign API failures **only for newly-owned test
  Jobs**, including zero last-error. These six failures are injected, not naturally
  occurring kernel permission failures. It checks short circuit, nonzero status,
  no published installed flag, saved error despite cleanup, no native handle leak,
  then real native successful retry/idempotence with no explicit successful close.
- The Python startup test is a source wiring contract, **not** SCM execution proof.

All assertion failures still unwind through the held fallback Job, which owns only
fixture descendants. No PID-only kill, broad process termination, or cleanup kill
is counted as success. The `audit` mode performs read-only full-path attribution;
its PID enumeration is not used to target termination. In an outer runner's
`finally`, run `audit`, remove only the owned upload directory, then independently
read back that the exact directory is absent. Keep local logs/hashes for review.

## Optional exact Go runtime compatibility

Place the authorized sing-box 1.14.4 executable beside `selfjob-native.exe`, verify
its SHA-256 before any launch, then run `selfjob-native.exe go` (expected exit 0).

```text
Archive SHA-256:    99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df
Executable SHA-256: 8f30682ee198855440d2a7fe070d5d3653793b2d01bb8c85eea88f93bbe7c8b9
```

This starts the actual Go runtime with `run --config stdin`, no inbound listener,
no credentials/node, and a reject route. Its config EOF is delivered before launch;
it must remain alive for one second, then die after exact owner hard exit before
fallback cleanup, both without and with inner Job assignment. This is runtime
startup/nested-lifetime compatibility only, not the Rust supervisor integration,
authenticated SOCKS/TUIC forwarding, service privilege, browser, or WFP acceptance.

## Remaining gates

GNU static-runtime builds and ordinary SSH user/session-0 kernel tests are not
MSVC/SDK final CI or installed LocalSystem SCM crash acceptance. Independent review
must precede full service acceptance. The production outer Job covers trusted
foreground spawn-to-inner-assignment lifetime only; it does not constrain malicious
delegated spawning or privileged alternate-parent brokers. No new browser/process
architecture or helper policy is introduced.
