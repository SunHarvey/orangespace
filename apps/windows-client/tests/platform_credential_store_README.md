# Independent central credential store — bounded handoff

API: `orangespace::platform_session::CredentialStore::{save(config,session), load(config), erase(config)}` in `orangespace/platform_credential_store.hpp`. Implementations are appended to the existing `credential_store_win.cpp`.

## Product behavior

- Fixed naturally-created `%LOCALAPPDATA%\\OrangeSpace-Platform-Credentials-v1` root; independent `OrangeSpace/PlatformCredentialStore/v1/central-session` entropy binds current SID and exact protected config origin.
- Internal `central-<CNG SHA-256 exact origin>.dpapi` filename. Reused `NodeEntry` is **storage-only**, never an API node identifier, user ID or replacement for authenticated identity.
- Shares the original private held-ancestor/relative-file/ACL/current-user-DPAPI/atomic-write/lock/pending-erase implementation. `Directory` gets a private kind defaulting to node; node directory, UUID filenames, entropy and public method bodies remain unchanged.
- `save` independently verifies the config origin and the SDK's eight-field central envelope source, namespace, integers, token, IDs and local expiry before encryption/write.
- `load` refuses a pending marker before decryption/HTTP; decrypts and validates binding, then calls production `Session::restore(config,envelope)` (Windows SDK uses strict HTTPS and real central revalidation). It does not turn decrypted bytes directly into login authority.
- Invalid/expired/revoked load uses the existing pending-erase transaction, releasing the open blob first, retaining committed markers on uncertain cleanup, and rethrowing the original failure. A failed `erase` is never successful logout. No plain-text persistence or legacy blob migration.

## Executed RED / GREEN

Working directory `/root/projects/orangespace`; `TMPDIR=/var/tmp/hermes-runtime/tmp`.

Initial interface RED (before new header):

```sh
g++ -std=c++20 -Wall -Wextra -Werror -I apps/windows-client/include \
  apps/windows-client/tests/platform_credential_store_policy_tests.cpp \
  apps/windows-client/src/platform_session_win.cpp -o "$TMPDIR/platform-store-evidence/policy"
```

Actual result: missing `platform_credential_store.hpp`, exit 1. Same compile after implementation plus executing the binary: `platform credential policy passed`. A malformed initial test token (44 vs SDK's required 43 characters) was corrected; no token validation was relaxed.

Implementation source RED: `python3 apps/windows-client/tests/platform_credential_store_source_tests.py` failed 3 tests because central implementations were missing. After implementation: 3/3 pass. Supplemental actual-body extraction test also returns `RED: central CredentialStore implementations are missing` against the preserved original source at `$TMPDIR/platform-store-evidence/credential_store_before.cpp`.

GREEN:

```sh
python3 apps/windows-client/tests/platform_credential_store_source_tests.py
python3 apps/windows-client/tests/platform_credential_store_policy_io_tests.py
```

The latter compiles the actual production save/load/erase bodies with explicitly RAM-only Windows I/O seams and the real portable SDK Session implementation. It covers central restore invocation and HTTP-status denial, config/envelope cross-origin denial, pending save/load admission, deletion/marker-clear failure recovery, tamper and expiry cleanup, and preservation of the original restore error. This is policy evidence, NOT Windows DPAPI or real-network success.

Also personally compiled/executed with GNU C++20 `-Wall -Wextra -Werror`: central policy, existing credential ACL/entropy policy, existing pending-logout fault/concurrency policy, SDK platform-session tests. Existing pending-logout Python source guards: 3/3 pass. Compared the original and edited source: legacy public store methods and the complete crypto/atomic-write/pending primitive bodies are byte-identical.

## GNU Windows compile/link

All cross-builds serialized with `flock /var/tmp/hermes-runtime/tmp/orangespace-build.lock`; same TMPDIR. Private scratch CMake overlay adds SDK source only for validation without modifying actor-owned repository CMake files.

Successful full compile/link targets: `orangespace_node_session` (node + central SDK + both stores), `orangespace-credential-store-native-tests`, `platform-credential-policy`, `OrangeSpaceLogin`, `OrangeSpaceService`. The Rust archive is the existing baseline archive; this is not new Rust source provenance evidence.

New native primitive fixture successfully compiled/linked separately:

```sh
flock "$TMPDIR/orangespace-build.lock" x86_64-w64-mingw32-g++ \
  -std=c++20 -O2 -Wall -Wextra -Werror -static -static-libgcc -static-libstdc++ \
  -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -DNOMINMAX -D_WIN32_WINNT=0x0A00 \
  -I apps/windows-client/include \
  apps/windows-client/tests/platform_credential_store_native_win.cpp \
  apps/windows-client/src/node_session_win.cpp apps/windows-client/src/platform_session_win.cpp \
  -o "$TMPDIR/platform-store-evidence/platform-store-native.exe" \
  -lwinhttp -ladvapi32 -lcrypt32 -lshell32 -lole32 -lbcrypt -luuid
```

PE imports contain only Windows system DLLs (no libstdc++, libgcc or libwinpthread DLL). Native fixture is **not executed**: it requires a limited interactive token, uses a random `.invalid` origin solely as a storage key, tests the real new-root DPAPI and pending primitives and verifies exact fixture-leaf cleanup. It does not exercise HTTPS or central Session load.

Scratch evidence directory: `/var/tmp/hermes-runtime/tmp/platform-store-evidence/`; contains initial RED log, full-build/module-build logs, original source snapshot, archive, native fixture and source/artifact manifest.

## Integration / remaining gates

- Parent owns CMake: ensure `platform_session_win.cpp` is in `orangespace_node_session`; also add it to the existing private-inclusion `orangespace-credential-store-native-tests` target (that target includes `credential_store_win.cpp` directly). No separate platform-store implementation TU/link library is needed. New tests currently run by the explicit commands above, not CTest registration.
- Full default GNU build was attempted and blocked in concurrently edited actor-owned `main_win.cpp` by old `TrustedCatalog`/`alias`/`finish_login` call sites after the central type switch. These were not modified here. Do not describe the complete UI/application build as green from the successfully linked subset.
- Initial hash call used an SDK pseudo-handle unavailable in installed MinGW headers; replaced with `BCryptOpenAlgorithmProvider(BCRYPT_SHA256_ALGORITHM)` + RAII close + `BCryptHash`. First standalone native link missed `-luuid`; final command above succeeds.
- Existing SDKactor-reported old transport-contract guard mismatch around `if (!promoted) purge(...)` was not changed or weakened.
- Parent independent review, repository CMake integration/full UI build, and real interactive-user central HTTPS/DPAPI end-to-end acceptance remain pending. No session-0, model, cross-compile or primitive-only result is native login success.

## Parent follow-up (separate evidence)

The parent subsequently added the central SDK source to both CMake dependency closures and successfully rebuilt/linked the complete manager, login tool and Service in a fresh GNU build directory. The earlier UI compile failure above is historical, not a remaining blocker for that frozen build. Evidence: `/var/tmp/hermes-runtime/tmp/orangespace-dev-delivery-ixrznt39/platform-parent-glue/build-receipt.json`.

Independent source review `deleg_f45ccba7` passed the store changes and frozen primitive fixture; the parent matched their hashes. Its limited primitive execution approval does not cover later app-private-CA SDK edits. Those shared SDK dependencies need their own review and rebuild before attributing a new native result to them. Real interactive-user DPAPI and central HTTPS roundtrips remain unverified. No remote execution, Profile/trust edits or commit performed.
