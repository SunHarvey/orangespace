# Prototype-only mixed/private channel adapter

This bounded SDK slice does not change ServiceMain, CEF, OSP2/OSP3, browser_allowed,
WFP, UI, helper pin or either namespace implementation. No remote execution.

Trusted Service code explicitly obtains
`std::unique_ptr<win::PrototypePlatformBackend> make_prototype_platform_chain_backend()`.
It is still a `chain::Backend` for Engine construction and follows the unchanged
independent PlatformNode/Centre/Node authorization path. Only this factory selects
`WindowsBackend(true,true)` and C ABI local proxy protocol 1. Existing factories
retain old SOCKS constructors (including the existing protected CA branch).

After **Engine.start and ACK adoption have completed**, the trusted caller can call
`LocalChannel take_local_channel(std::string_view auth_id, const chain::Binding&)`.
The full Binding must include the original successful start's server_expiry and
deadline_ms. The backend requires submitted/exact/current authority, immutable
original Budget, nonretired/nonpoisoned realm and actual root polling. Renewal
never extends this grant: if it changes active authority metadata, this API rejects
rather than accepting a stale initial Binding or treating renewal as a new grant.

Return is move-only/nothrow-movable LocalChannel, containing full Binding,
original LeaseBudget, uint16 port (host is always 127.0.0.1), move-only
platform_session::SerializedSecret username/password and proof_observed_at_ms.
Secrets have only explicit `.view()` access; no implicit string conversion/logging.
Keep it in future parent-held protected RootIPC ownership, not general status,
argv, environment or persistence. The method itself does NOT attest OS peer,
instance or ACK receipt; those remain trusted Service caller responsibilities.

The dedicated C ABI output is a noncopyable 4096-byte RAII-wiped array, never
`call()`'s plain string path. Decoder uses the existing guarded/wiping JSON DOM,
exact wire integer scanner and bounded printable ASCII secret owners. It rejects
unknown/duplicate/missing fields, wrong tuple/clock/anchor/deadline/host/port,
expired original grants, future proof and proof age >=3000 ms. Current exact
identity/deadline/root checks surround allocating work and consumed output.
A possibly submitted take attempt is latched before FFI and cannot be retried even
if decoding/allocation/delivery fails. Caller must close/revoke the exact
provisional Binding OUTSIDE this method's IO lock; there is no internal close
callback or retry/reanchor path.

## Executed locally

Initial missing decoder header RED and missing prototype factory RED were observed;
then the following passed (fixture secrets only):

```
g++ -std=c++20 -Wall -Wextra -Werror -Wno-missing-field-initializers -Iapps/windows-service/include -Iapps/windows-client/include apps/windows-service/tests/prototype_local_channel_tests.cpp -o <scratch>/channel
<scratch>/channel
python3 apps/windows-service/tests/prototype_backend_source_tests.py
python3 apps/windows-service/tests/prototype_backend_tests.py <scratch>/backend
python3 apps/windows-service/tests/tuic_private_ca_tests.py <scratch>/ca
cmake --build build -j1
ctest --test-dir build --output-on-failure
```

Commands were serialized with the existing build lock. Positive + 20 decoder
negative cases passed, also ASan/UBSan. Actual extracted backend bodies passed
once-only, wrong/missing authority, expired original grant, retirement/poison/close,
renewal and root-exit pre/post-FFI controls: injected OS/FFI policy, NOT Windows.
Root CTest 28/28 and existing PlatformNode backend/mockHTTP regression passed.
The existing CA fixture's stale `os_runtime_free` source replacement was repaired
while retaining its real free-count behavior and all original assertions.

Real production chain_windows.cpp, windows_security.cpp, node_session_win.cpp and
platform_session_win.cpp compiled with private clang-cl 19 + MSVC STL/Windows SDK
and linked /MT against the supplied new Rust MSVC archive. Scratch build recipe:
`/root/.hermes/cache/scratch/build-prototype-backend-msvc.py`; commands/map/artifacts
in `/root/.hermes/cache/scratch/prototype-backend-msvc/`. PE imports contain Windows
DLLs only, no dynamic CRT. Archive SHA256:
`9a036ffce28bce5e8b591444558b7584335361147e9e67cdd521a0167d17c8f9`.
Link-only fixture EXE SHA256:
`692c1690d99a047619f5fef98d8b6fc167098e3a973a7e24bbf0cdb0e70c5010`.
The fixture references the actual prototype factory but must not be described as a
Service executable or executed production acceptance. No Windows execution,
mixed-helper authentication, ACK/RootIPC integration, CEF or WFP claim is made.
