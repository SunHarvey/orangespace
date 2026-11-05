# Stop/cleanup allocation regression

Run from the repository root (output outside the repository):

```sh
g++ -std=c++20 -O0 -g -Wall -Wextra -Werror -fno-elide-constructors -pthread \
  -Iapps/windows-service/include -Iapps/windows-client/include \
  apps/windows-service/tests/service_stop_tests.cpp -o /absolute/scratch/stop
/absolute/scratch/stop
python3 apps/windows-service/tests/service_stop_poison_tests.py "$PWD" \
  /absolute/scratch/poison "$PWD/target/debug/liborangespace_runtime.a"
```

Repeat with `-fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie -no-pie`;
pass these through `SERVICE_TEST_CXXFLAGS` for the Python extraction build.

The actual `Engine::stop` runs with a liveness backend and the exact ledger
serializer, but an injected persistence sink. A successful two-binding stop
counts its allocations; each index is then failed once transiently and once
persistently for adopted, unadopted/provisional, and pending-start bindings.
Every index must actually throw. No guessed fault-budget ceiling is used.

Before mutation, allocation failure must retain the exact owner and unchanged
cursor, permit authenticated retry, and preserve honest status (pending and
unadopted helpers never expose proof). After local close, vector construction
and serialization failures must poison the namespace and backend, deny work
and proof, and leave cleanup-only retirement usable. The pending-start callback
must finish all assertions before the enclosing expected cancellation is counted.
Unauthenticated peers, unknown auth/sandbox IDs and stale CAS are separately
rejected without closing work. Ordinary stop/preparation failure preserves the
unrelated sibling; backend poison intentionally invalidates every shared realm.

The poison regression extracts the **exact production** `Realm`, map,
`reserve` and `fail_closed` bodies from `chain_windows.cpp`. A durable-writer
fault enables sticky C++ allocation failure before production poison runs.
Two Engines with distinct namespaces share this backend. Held Realm objects
must both be retired, both real Linux Rust runtime handles freed, the backend
map empty, and future production reservations denied. Helper liveness itself
is modeled; no helper is spawned. This is not Windows native/SCM/IPC/HTTPS/WFP
or network-isolation acceptance, and linking an existing Rust archive does not
re-attest its source provenance.

Preserve the existing chain/ownership/postACK/release suites: they additionally
cover retained remote cleanup after failed persistence, exact provisional
rollback, receipt cap 64, peer binding, retire without remote logout, S1/L2,
and preACK DTO transfer with copy elision disabled.
