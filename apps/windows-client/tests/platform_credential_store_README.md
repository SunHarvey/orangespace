# Centre credential store (remember-login)

API: `orangespace::platform_session::CredentialStore::{save(config,session), load(config), erase(config)}` in `orangespace/platform_credential_store.hpp`; implemented in `credential_store_win.cpp` beside the node store.

## Behaviour

- Fixed `%LOCALAPPDATA%\OrangeSpace-Platform-Credentials-v1` root; current-user DPAPI with entropy `OrangeSpace/PlatformCredentialStore/v1/central-session` bound to the user SID and the exact protected config origin; file `central-<SHA-256 of origin>.dpapi`. Shares the node store's held-ancestor, relative-file, ACL, write-through atomic replacement, lock and pending-erase transaction.
- What is stored is a session **renewal** (`Session::export_renewal`: user, session, epoch, hard deadline, refresh credential and its expiry), never an access credential. `save` checks it (`credential_detail::validate_renewal`) before encrypting.
- The refresh credential is one-time: the window's Centre saves the new renewal after every refresh, and `load` saves the rotated one before returning.
- `load` returns nothing when nothing is saved. Otherwise it signs in again through `Session::resume` (one refresh at the Centre, which must name the same user, session, epoch and deadline).
  - Invalid, expired or tampered item, or the Centre refuses it (HTTP 401/403): erased with the pending-erase transaction, original error rethrown.
  - Network failure, other HTTP status or an unexpected reply: kept, `SavedSignInKept` thrown, so a short outage does not sign the user out.
- A pending-logout marker refuses `load` and `save` until `erase` completes; the window's next password sign-in erases first.

## Tests

- `platform_credential_store_policy_tests.cpp` (ctest `platform-credential-policy`): origin, entropy and storage-id rules; the renewal admission check (origin, namespace, deadline, expiry, exact fields, token).
- `platform_remember_native_win.cpp` (`orangespace-platform-remember-native-tests`, run in a desktop session, not over SSH: the store refuses session 0): real DPAPI store with a random fixture origin and a fake rotating Centre — nothing saved, save → resume → rotated renewal saved (a second start works only with it), refresh while running then save, offline and 503 keep the item, 401 erases it, erase after sign-out.
- `platform_credential_store_native_win.cpp`: DPAPI/NTFS primitives and the pending marker.

None of these is Centre HTTPS acceptance; that is done with the window on the test VM (docs/roadmap.md).
