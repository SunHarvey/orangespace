# SinglePrototype Control / ordinary-user operator seam

This is local source/build glue only. It does not install a service, change WFP,
add loopback exceptions, start CEF, or establish Windows browsing acceptance.
Legacy ServiceMain, UI, Foundation identity and namespace remain unchanged.

## Parent API and ordering

`online_control_win.hpp`, namespace `orangespace::service::win`:

```cpp
PrototypeControl control(actualSelectedWTS, serviceStop, trustedSGNodeUUID);
control.start(); // parent has already installed/read back Offline and published observation rights
// parent may now publish SCM RUNNING (operator authenticates SCM/PID before credentials)
auto channel = control.wait_channel(timeout_ms); // nullptr on timeout/stop; may throw on revocation
if (channel) {
  control.verify_live(*channel);
  // Parent only: create Root/package, install path + package SID WFP,
  // add only the owned loopback exception, issue RootIPC admission.
}
control.stopAndJoin(); // before parent destroys serviceStop or referenced runtime/pins
```

The parent retains `shared_ptr<const LocalChannel>` for the entire Root lifetime.
The owner is published only after OSP3 Engine.start, actual received ACK6 adoption,
fresh Engine.diagnose with full trusted authority metadata, and once-only private
take. Original runtime grant/deadline/proof checks are unchanged. Poll is 200ms;
remote tick starts only after publication and its first execution waits 3000ms.
`verify_live` checks the exact immutable owner and fresh Engine status/full tuple;
its initial 30s grant is not used as continued renewal authority. Stop/helper loss,
expired current authority or maintenance failure sets the parent's service stop.
The parent must kill its own Root Job on that event. Channel ownership alone is
not a browser permit. Public OSP responses keep `browser_allowed=false`.

Fixed endpoint: `\\.\pipe\OrangeSpace.SinglePrototype.Control.v1.session.<actualSession>`.
The existing pipe helper provides protected SY + exact-user individual-rights ACL,
first-instance protection/local-only and OS SID/session/LUID verification. A bounded
non-consuming OSP3 header gate excludes the helper's legacy OSP1 decoder. One start
is allowed for this owner lifetime, including ACK-loss/failure attempts; subsequent
authorize/register/start reject, while exact-auth stop/status/logout/retire retain
SDK behavior. Malformed requests do not themselves stop a valid Root.

## Build and operator

Both new TUs require `ORANGESPACE_PROTOTYPE_NODE_UUID` from the trusted private
build. There is no source fallback or caller-selected node. Tests use a placeholder
UUID, not a deployable SG selection. `online_control.cmake` is an explicit optional
fragment for existing Windows SDK targets, not included by legacy CMake entrypoints.
Do not also compile chain_windows.cpp directly into a parent linking this archive.
All linked SDK/static Rust objects must use matching `/MT`.

The operator calls SDK PlatformConfig.load on its module-sibling protected
`platform.json`, checks a real non-elevated interactive token/session and no thread
impersonation, restores the normal current-user management DPAPI session, selects
only the build-pinned node from the server's complete node list, authorizes through
OSP3, registers an OS-random local UUID, and starts the exact cursor. No browser,
proxy or login UI is provided. Success only prints `请求已接受`.

No arguments: normal cached SDK login. Cache failure prints the fixed instruction
to first sign in through the management program. Optional `--login-stdin` accepts
only a PIPE and two LF-terminated bounded UTF-8 lines (username <=256 bytes,
password <=1024), uses the actual SDK Session.login, and never saves/erases the
management cache. This is only a development RAM bridge, not an SSH product flow.
On failure it retires only its own Service grant; it never logs out a cached central
session. Only its own fresh failed login is eligible for central logout.

Compile **only service_client_win.cpp** with
`apps/windows-client/prototype/operator-private` BEFORE normal include paths. The
private header renames the identity namespace in that TU and fixes the Prototype
SCM/pipe. Do not apply this directory to credential_store_win.cpp or legacy UI.
CredentialStore keeps the original installation identity (including any matching
management development suffix), preventing an ODR collision or accidental new
credential namespace. No old install_identity.hpp changes are required.

The SDK retains its original transfer timeouts: ordinary local transfers are
1500ms; credential-bearing requests' existing response wait is 90000ms to cover
independent HTTPS work. This seam does not rewrite that SDK transport budget.

## Executed local evidence

```sh
python3 apps/windows-service/tests/prototype_control_tests.py
python3 apps/windows-client/tests/prototype_operator_tests.py
python3 /var/tmp/hermes-runtime/tmp/orangespace-single-prototype-20261102/build-control-operator-v1.py
```

Both new tests first failed for the missing implementations, then passed (2 + 2).
They execute actual extracted metadata/status and bounded-line policy with g++;
source integration assertions are explicitly not native IPC/adoption evidence.
The private build script compiled the actual new Control and operator plus existing
backend/security/pipe/SDK/store TUs using clang-cl `/MT /W4 /WX`, and linked both
COFF x64 executables against the actual Rust MSVC local-channel archive SHA256
`9a036ffce28bce5e8b591444558b7584335361147e9e67cdd521a0167d17c8f9`.
Output directory: `/var/tmp/hermes-runtime/tmp/orangespace-single-prototype-20261102/control-operator-msvc-v1`.
`commands.json` records exact invocations. PE import inspection showed no MSVCP or
VCRUNTIME dependency. These are compile/link witnesses with a placeholder node;
Windows SCM/ACL/DPAPI/real SG lease/mixed channel/Root/CEF acceptance is unexecuted.
