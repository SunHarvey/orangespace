# Central Windows management UI slice

`src/main_win.cpp` now uses the real platform SDK and independent Service platform API. No legacy Node login fallback exists in this UI. Existing legacy `workspace_auth.hpp` and legacy identity/Profile/SQLite ownership are not changed or migrated.

## Glue required by parent build

- Link production `platform_session_win.cpp` and the CredentialStore implementation providing `platform_session::CredentialStore::{save,load,erase}` into the manager's existing dependency closure.
- Existing Service client must export `authorize_platform(const Session&, const NodeRef&)`, `register_sandbox(const Grant&, string_view localSandboxUUID)` and `start_registered_tunnel(const Grant&, string_view localSandboxUUID)`; retain `stop_tunnel`, `logout`, `retire`, foundation status.
- Add `tests/platform_workspace_tests.cpp` as a portable CTest target (model INTERFACE dependency suffices). CMake is parent-owned and intentionally not edited here.
- UI path control explicitly loads the administrator-protected absolute `platform.json` through `PlatformConfig::load`; there is no guessed/unprotected config fallback. Automatic packaged path population is not part of this slice.

## Product behavior

- Central login or blank-password DPAPI restoration; online SDK validation and complete authorized-node enumeration. Aliases including dots remain unchanged.
- Local Broker owner is `identity().central_user_id`; remote legacy identity is used only inside the typed per-node Service grant. Existing old-owned data remains old-owned; UI explicitly says explicit migration is needed, no migration tool is claimed.
- SQLite create/list/bind/close/delete reuse the existing broker. Linux personal-area deletion is never issued. Close/rebind/delete wait for a pending exact stop of the selected row.
- Start captures the row's bound node UUID, central session owner, local UUID and cached per-node typed grant. Same-node siblings reuse the grant; another node gets its own grant. Cursor comes from Service registration/ledger, not local generations.
- Three explicit row columns remain unknown/processing until a typed Service result validates process_started, tunnel_authenticated and forwarding_verified. Verified text says **at startup**: it is establishment proof, not continuous liveness or WFP evidence.
- Independent Stop can cancel the selected in-flight start or enqueue its exact adopted binding for stop/retry without retiring a sibling grant. Late returned bindings retain pending-stop ownership. Mailbox, joined worker, grant drain, final-return ownership, DPAPI pending-logout gate and exact stop retries remain in place.
- Browser remains always denied. Files panel explicitly incomplete. No helper credentials are shown.

## Executed evidence (portable/cross-build only)

Scratch root: `$TMPDIR/platform-ui` (this session resolved to `/var/tmp/hermes-runtime/tmp/platform-ui`). All build commands use the shared `flock /var/tmp/hermes-runtime/tmp/orangespace-build.lock`.

- `platform_workspace_tests.cpp`: observed RED missing central model, GREEN; then RED missing per-row model, GREEN; then RED missing mutation gate, GREEN. Covers different legacy IDs with one central owner, unchanged old owner/Profile, login ticket fence, A stop/late reply not changing B, and unknown proof during start. GNU `-Wall -Wextra -Werror` and ASan/UBSan both executed.
- `platform_ui_logout_tests.py --output $TMPDIR/platform-ui/central-logout-green`: compiles actual production cleanup methods with injected OS/Service/DPAPI seams. RED reproduced lost final-return late central session, GREEN after fix. A second RED showed retired proof surviving logout, GREEN in `logout-proof-green`. Covers local disk/service retry, normal close preserving stored login, explicit remote failure and final late-login revoke attempt.
- `platform_ui_tunnel_tests.py --output $TMPDIR/platform-ui/central-tunnel`: executes exact production start worker with typed injected Service seams; verifies central/legacy separation, grant reuse, Service cursor, failed/cancelled exact-owner retention and sibling preservation. Policy evidence, not real forwarding.
- `platform_ui_broker_tests.py --output $TMPDIR/platform-ui/broker-green`: RED reproduced list/create falsely recording selected-row stop; GREEN after capturing an explicit mutation/stop predicate. Executes the actual production broker worker body.
- Existing `ui_lifecycle_tests.cpp`, `ui_cleanup_drain_tests.cpp`, `workspace_auth_tests.cpp`, `model_tests.cpp`, and `ui_lifecycle_source_tests.py` executed successfully.
- Production `main_win.cpp` compiled to x64 Windows object with MinGW using C++20, Unicode, Windows 10 API definitions and `-Wall -Wextra -Werror`; no native execution or link/runtime acceptance is claimed.

Example repeat:

```sh
flock /var/tmp/hermes-runtime/tmp/orangespace-build.lock sh -c '
set -e
g++ -std=c++20 -Wall -Wextra -Werror -Iapps/windows-client/include apps/windows-client/tests/platform_workspace_tests.cpp -o "$TMPDIR/platform-ui/workspace-tests"
"$TMPDIR/platform-ui/workspace-tests"
python3 apps/windows-client/tests/platform_ui_logout_tests.py --output "$TMPDIR/platform-ui/logout-final"
python3 apps/windows-client/tests/platform_ui_tunnel_tests.py --output "$TMPDIR/platform-ui/tunnel-final"
python3 apps/windows-client/tests/platform_ui_broker_tests.py --output "$TMPDIR/platform-ui/broker-final"
x86_64-w64-mingw32-g++ -std=c++20 -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -DNOMINMAX -D_WIN32_WINNT=0x0A00 -Wall -Wextra -Werror -Iapps/windows-client/include -Iapps/windows-service/include -c apps/windows-client/src/main_win.cpp -o "$TMPDIR/platform-ui/main_win.o"
'
```

## Explicit remaining boundaries

- Parent must complete dependency/CMake glue, final full binary link and actual Windows protected-config/HTTPS/DPAPI/Service/helper/UI interaction acceptance. No service installation, trust changes, SCM operations or remote execution were performed by this slice.
- Old `ui_cleanup_callers_tests.py` and `ui_logout_recovery_tests.py` embed legacy source markers/NodeCatalog/store DTOs. Actual execution found extraction/compilation failures against the new central UI. They are not counted green; new central extraction runners cover the changed bodies. Parent should port or explicitly scope those legacy harnesses before adding them to CI.
- Per-row displayed proof is historical startup establishment, not continuously polled helper liveness. No WFP/DNS/browser/file bridge/full installer claim.
