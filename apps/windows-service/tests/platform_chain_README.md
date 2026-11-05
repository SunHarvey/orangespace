# Platform Service adapter handoff

This is a source/backend/client slice, not native HTTPS/IPC/helper acceptance.

## Glue owned by parent

* `service_main.cpp`: use `win::make_platform_chain_backend()` explicitly. It loads and pins installation-directory `platform.json` immediately (`{"schema":1,"api_origin":"https://..."}`); missing/bad/unprotected config throws. Never catch and fall back to `make_chain_backend()`.
* Keep `make_chain_namespace()` and its existing protected `nodes.json`/`service-state.json` anchors. Exact local UUID registration uses `Engine::register_sandbox(peer,auth,uuid)` and the Engine owner's schema2 central/SID ownership. Legacy schema1 records are not silently claimed.
* `pipe_server.cpp`: recognize OSP3 magic alongside existing OSP1/OSP2, bound to the SAME OS-observed `Peer`. Invoke `win::dispatch_platform_chain(engine,peer,bytes)` for OSP3, retain existing `Response` ownership, `deliver(write,read_ack)` and one-byte ACK=6. Do not flatten Response to a plain string. The OSP3 payload limit remains 16384; operations 1..6 retain existing operation IDs, 7 is registration. Platform start requires exact sandbox UUID plus expected generation.
* CMake: ensure both client and Service link the real `platform_session_win.cpp` into the existing Node SDK library (no duplicate definitions). Add the three tests below; backend `.inc` is included by `chain_windows.cpp`, not a separate compilation unit.
* UI stable APIs in `service_client`: `authorize_platform(const platform_session::Session&,const platform_session::NodeRef&)`, `register_sandbox(const Grant&,std::string_view localSandboxUUID)`, `start_registered_tunnel(const Grant&,std::string_view localSandboxUUID)`. Alternatively register then `start_tunnel(grant,cursor)`. Grant `user()` stays **remote legacy UID**; `central_user()` is Centre UID. UI local broker ownership should use SDK Centre identity separately. Existing stop/retire/logout/status functions select OSP3 for a platform Grant, OSP2 for historical Grants.

## Product path

Service restores the central envelope independently, enumerates/revalidates the entire central node list, compares node/grant/mapping/epochs/revision/scopes, matches HTTPS host/port/node/TLS name to its protected static catalog, issues its own exchange ticket, and uses the existing strict WinHTTP transport. Exchange and cleanup validate the unique Node header, including error responses. Node replies bind central session/user, legacy user, mapping/grant, epochs, expiry and exact selected origin. NodeSession then independently restores the token through `/healthz`, `/v1/me`, `/v1/session`; no issued-envelope rewriting to add a port. Its returned legacy UID and expiry must match. Static schema1 catalog does not contain signing-key fingerprints: fingerprints are compared against authenticated Centre snapshots, not falsely claimed as static key pins.

Refresh rechecks central identity and selected NodeRef, then independently restores Node session. create/renew/revoke delegate existing Node APIs and runtime/backend remains unchanged. Single-node logout revokes only the private node exchange credential; never logs out the shared central session.

## Exact cleanup ownership and limits

A preallocated 64-slot pool retains exact exchange ID/token before possible POST. Initialization failure, independent restore mismatch, response ownership loss/ACK loss and final Session destruction attempt exact exchange-cleanup. Failed cleanup remains retained and retries on the next platform authorization; exhausted capacity denies new authorization. A 401 unknown exchange/network/malformed reply is not success; only validated revoked response or Node-header-validated 410 completes the receipt. No eviction or credential logging. Pool scope is this backend process lifetime; it is not restart-durable cleanup and has no timer/guardian. Retire preserves the Engine's existing no-remote-logout behavior; explicit logout is scoped to Node.

## Actually executed

All build commands were wrapped in `TMPDIR=/var/tmp/hermes-runtime/tmp flock /var/tmp/hermes-runtime/tmp/orangespace-build.lock`; CMake used `-j1`.

Portable tests (model/mockHTTP, NOT native):

```sh
g++ -std=c++20 -Wall -Wextra -Werror -Wno-missing-field-initializers -Iapps/windows-service/include -Iapps/windows-client/include apps/windows-service/tests/platform_chain_policy_tests.cpp -o /var/tmp/hermes-runtime/tmp/platform-chain-policy
/var/tmp/hermes-runtime/tmp/platform-chain-policy
g++ -std=c++20 -Wall -Wextra -Werror -Wno-missing-field-initializers -Iapps/windows-service/include -Iapps/windows-client/include apps/windows-service/tests/platform_chain_backend_tests.cpp apps/windows-client/src/platform_session_win.cpp -o /var/tmp/hermes-runtime/tmp/platform-chain-backend
/var/tmp/hermes-runtime/tmp/platform-chain-backend
cmake --build build -j1
ctest --test-dir build --output-on-failure
```

Policy test observed initial missing-header RED then GREEN. API compile test observed missing factory/client APIs RED then all four Windows production TUs compiled GREEN. Backend mockHTTP exercised actual `platform_chain_windows.inc` plus actual portable Centre SDK with explicit mock Node HTTP; covers legacy/Centre separation, mapping mismatch, independently returned UID/expiry mismatch, epoch refresh denial, lost-owner cleanup retention/retry and zero Centre logout. Post-logout refresh regression observed actual SIGSEGV RED, then rejection GREEN. Root CTest passed 20/20, including real-ABI-no-helper policy (not native network acceptance).

GNU MinGW actually compiled `chain_windows.cpp`, `service_client_win.cpp`, `node_session_win.cpp`, SDK and current service/security/pipe sources under `-Wall -Wextra -Werror -Wno-missing-field-initializers`. Linked full `PlatformService.exe` against existing `target/x86_64-pc-windows-gnu/release/liborangespace_runtime.a`, with `-static -static-libgcc -static-libstdc++ -municode`, Windows libraries `winhttp advapi32 crypt32 wtsapi32 bcrypt ws2_32 userenv ntdll secur32 shell32 ole32 pthread`. Also linked `PlatformClientApi.exe`. These are real PE link results, not new provenance attestation of the existing Rust archive; parent glue may still have changed since those objects were compiled. PE import inspection showed Windows DLLs only, no MinGW runtime DLL.

Pending: parent pipe/main/CMake/UI wiring and rebuild, independent production review, actual Windows centre+node trusted HTTPS/credential exchange and ACK-loss validation, persistent cleanup across Service crash (not implemented), interactive manager/sandbox/helper runtime native acceptance. No Trust/RDS/SCM/remote operations or commits were performed by this slice.
