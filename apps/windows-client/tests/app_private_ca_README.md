# App-private CA bridge (bounded SDK slice)

## Configuration and ownership

Schema 1 keeps its exact existing fields, parsing and WinHTTP behavior. Five-field
`NodeEntry{name,node_id,host,port,api_prefix}` aggregate initialization remains valid;
the new trailing `shared_ptr<const string> ca_pem` defaults to null.

Platform schema 2 explicitly selects private roots and requires exactly:

```json
{"schema":2,"api_origin":"https://centre.test:19093","ca_file":"C:\\OrangeSpace\\ca.pem"}
```

Static NodeCatalog schema 2 retains `schema,nodes`; entries retain
`name,node_id,api_origin` and may add `ca_file`. An entry without it still uses
normal WinHTTP, permitting mixed catalogs. Schema 1 rejects a `ca_file` field.

`PlatformConfig::load` / `TrustedCatalog::load` read CA files through the existing
`detail::read_admin_protected_config` held-handle ACL/reparse/fixed-drive reader.
CA paths must be explicit local Windows absolute paths, decoded from JSON UTF-8.
No relative, UNC, ADS or traversal path is admitted. Loaded nonempty CA bytes
are snapshotted once into `shared_ptr<const string>` and retained by copied
Bootstrap/NodeEntry/session objects. The checked-in shared reader actually caps
files at 65536 bytes (not 16 KiB); this bridge preserves that existing bound.
CA PEM/DER correctness is checked by Rust before network use, not guessed by C++.

## API and validation split

`detail::private_https_request(node,method,path,body,bearer,node_header_required,
receive,request=os_https_request_v1)` constructs the six borrowed fields from the
real `orangespace_https.h`; it does not duplicate ABI declarations. Origin excludes
the Node API prefix, which is instead prepended to path. It borrows body/token
without copies. Its 1 MiB response allocation and 64-byte header buffer are wiped
on success, rejection and consumer exceptions. C++ reimposes Node 16 KiB versus
Centre 1 MiB, checks Node header equality on errors too, and returns status without
turning HTTP 4xx into TLS failure. Existing consumers preserve typed status errors,
identity checks and strict JSON lease schema 2 validation.

Private-root Transport construction does not initialize WinHTTP. Its request branch
returns directly; a Rust failure throws only `app-private HTTPS failed`, never
retries or falls back. Schema 1/non-CA nodes continue through the original WinHTTP
path. No system-root import, verification bypass, proxy, trust or business
certificate mutation is introduced; no body/token enters logs, argv or env.

**Rust layer required before native acceptance:** unique Node header syntax/count,
TLS validation exclusively against supplied CA, no redirect/proxy, 5-second bound,
and the original WinHTTP rule that every non-204 response has exactly one
Content-Type equal to `application/json` or `application/json; charset=utf-8`.
The v1 ABI has no Content-Type output; this must be enforced in Rust before success,
not silently omitted. Parent owns the Rust amendment and canonical Centre
`/control/v1/me/nodes?limit=100[&cursor=UUID]` query support. Rust also sends fixed
`X-OrangeSpace-Lease-Schema: 2` on app-CA requests. This is a **request header**;
there is no separate response lease header. The **response** schema remains checked
by the existing C++ JSON typed parser. No ABI v2 or weaker lease guard is needed.

## Executed portable tests and GNU link

Parser and bridge test compilation were each observed RED before adding their API,
then GREEN. Injection tests exercise the actual portable bridge but do not perform
TLS and are never reported as real HTTPS success.

From repository root:

```sh
g++ -std=c++20 -Wall -Wextra -Werror -Iapps/windows-client/include apps/windows-client/tests/app_private_ca_tests.cpp apps/windows-client/src/platform_session_win.cpp -o /root/.hermes/cache/scratch/app-private-ca-tests
/root/.hermes/cache/scratch/app-private-ca-tests
g++ -std=c++20 -Wall -Wextra -Werror -Iapps/windows-client/include apps/windows-client/tests/app_private_ca_bridge_tests.cpp -o /root/.hermes/cache/scratch/app-private-ca-bridge-tests
/root/.hermes/cache/scratch/app-private-ca-bridge-tests
x86_64-w64-mingw32-g++ -std=c++20 -Wall -Wextra -Werror -Iapps/windows-client/include -c apps/windows-client/src/node_session_win.cpp -o /root/.hermes/cache/scratch/app-private-node.o
x86_64-w64-mingw32-g++ -std=c++20 -Wall -Wextra -Werror -Iapps/windows-client/include -c apps/windows-client/src/platform_session_win.cpp -o /root/.hermes/cache/scratch/app-private-platform.o
x86_64-w64-mingw32-g++ -std=c++20 -static -static-libgcc -static-libstdc++ -Iapps/windows-client/include apps/windows-client/tests/app_private_ca_tests.cpp /root/.hermes/cache/scratch/app-private-node.o /root/.hermes/cache/scratch/app-private-platform.o crates/orangespace-https/target/x86_64-pc-windows-gnu/release/liborangespace_https.a -lwinhttp -ladvapi32 -lws2_32 -lbcrypt -lntdll -luserenv -lcrypt32 -lsecur32 -liphlpapi -o /root/.hermes/cache/scratch/app-private-ca-link.exe
```

The first GNU PE linked successfully against standalone HTTPS archive
SHA-256 `970da51b04a94055c07dc6c74da29cdd8206a64837d23e579574171ab6805f59`.
That link predates parent's Rust Content-Type/query/lease-header amendment; it
attests C ABI link compatibility only, not the amended transport policy.
Final expanded-test PE SHA-256:
`be596bb5034d9d26a46bde57f390b50fee40729a0c6d426aa9313e22177b22eb`.
Both new portable executables also passed with AddressSanitizer + UBSan.
Product builds must consume parent's unified runtime archive instead of linking
two Rust standard libraries. Cargo/CMake/runtime integration is outside this slice.

Regression executables: node_session_tests (95 checks), node_session_error_tests,
node_session_lifecycle_tests, node_session_prefix_tests and platform_session_tests
all passed. Platform schema 2 without ca_file remains rejected (the original
platform negative test); explicit schema 2 with a valid protected CA reader is new.
Native Windows protected-path reads and real Centre/Node login remain parent gates.
No WFP/browser gate changed.
