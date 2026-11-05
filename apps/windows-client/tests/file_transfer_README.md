# File API client slice (not browser/file bridge acceptance)

Owned sources: `include/orangespace/file_transfer.hpp`, `src/file_transfer_win.cpp`.

- `FileContext.central_envelope` is a required immutable central SDK snapshot, produced by the UI owner while its shared Session is idle. `FileContext.session` is retained for interface compatibility and is never read. The worker restores a private Session, compares the authenticated central user, refreshes the exact authorized NodeRef, matches the protected executable-adjacent `nodes.json`, issues an exchange, validates its complete federation envelope, and independently restores NodeSession. File paths never contain a supplied user UUID.
- App-private CA file operations use `os_https_transfer_v1` from `file_https_abi.h`; public OS-trusted HTTPS uses strict WinHTTP. No OS trust modification, TLS-ignore flags, redirect/proxy fallback, or capped binary JSON ABI. Streams/callbacks use at most 64 KiB; metadata is capped at 1 MiB and upload commit JSON at 16 KiB.
- Tasks copy immutable central-user/sandbox/node/relative-path scope. Each FileClient serializes its private Session. Its node session is revoked using the exact exchange cleanup capability; it never logs out the shared central token. A fixed 64-receipt process-local pool retains uncertain cleanup, retries one pending receipt per new admission and denies on exhaustion. This is not durable cleanup across process exit.
- Downloads create an unpredictable CREATE_NEW same-directory part, retain object-anchored directory handles and the exclusive exact part handle, flush, check cancellation, then publish with native `FileRenameInformation` and the held final-parent `RootDirectory` and `ReplaceIfExists=FALSE`. This intentionally uses handle-based atomic rename rather than closing the handle before path-based MoveFileEx: the latter opens a substitution/delete race. Failure cleanup requests deletion only on the exact owned handle, never on a destination pathname. Native filesystem acceptance is still required.
- Unknown response length reports Progress total=0. Progress bytes are not a completed status. Only successful method return means complete. The existing server PUT commits on receipt of the complete body: a cancellation racing an already committed request cannot guarantee remote absence/rollback. Interrupted incomplete PUTs are cleaned by the existing server finally/Upload.close route.
- `modified_at_ns` remains absent: the server does provide nanoseconds, but the shared JSON DOM cannot represent these integers exactly. No rounded/fabricated timestamp is displayed.

## Executed evidence

Portable TDD linker RED for absent scope/path/cancellation functions, publication ownership, and listing parser; then GREEN. The test executes actual common production bodies, not a second model. Covers frozen task node after context mutation, traversal/temp-prefix rejection, encoding, wrong listing node and traversal entry, real large metadata value, cancellation before publication, conflict retention, one-time success/republication denial.

```sh
g++ -std=c++20 -Wall -Wextra -Werror -Iapps/windows-client/include \
  apps/windows-client/tests/file_transfer_tests.cpp \
  apps/windows-client/src/file_transfer_win.cpp -o <owned>/file-transfer-tests
<owned>/file-transfer-tests
x86_64-w64-mingw32-g++ -std=c++20 -Wall -Wextra -Werror \
  -Iapps/windows-client/include -Iapps/windows-service/include \
  -c apps/windows-client/src/file_transfer_win.cpp -o <owned>/file-transfer-win.o
```

Both run under the common build flock and pass. The Windows TU is actually compiled, not linked/executed; no native HTTPS/filesystem/GUI claim. Integration needs existing Node/Platform SDK objects, the new Rust streaming symbol, WinHTTP and BCrypt. Parent owns CMake/linking and the Rust adapter's real TLS tests. Current Rust route acceptance should be reviewed for catalog `/nodes/<uuid>` prefixes and percent-encoded legitimate filename characters. This slice does not open the browser or change WFP gates.

## Directory-redirection repair (native regression passed; GUI/package pending)

`src/file_transfer_local_io_win.hpp` is the private production implementation,
not a test copy. Open the fixed-drive root once, walk single validated components
with NtCreateFile RootDirectory, OBJ_DONT_REPARSE and FILE_OPEN_REPARSE_POINT,
query/reject directory reparses, then open the upload/create the exclusive part
relative to the final held parent. Publication uses the exact part handle and
NtSetInformationFile FileRenameInformation with a relative leaf and that parent.
Directories share writes; deny-delete pins stabilize rename identity, not metadata.
**There is no claim that pins prevent junction IOCTL or attribute changes.**

Primary references: Microsoft Learn NtCreateFile (winternl.h), OBJECT_ATTRIBUTES
(ntdef.h), FILE_RENAME_INFORMATION (ntifs.h), ZwSetInformationFile (ntifs.h).
The missing MinGW OBJ_DONT_REPARSE value matches Microsoft's
Windows-Driver-Frameworks public wudfwdm.h (0x00001000L). Function pointers are
fixed-signature exports from the already loaded system ntdll, without a new DLL.

`orangespace-file-directory-native-tests` is an opt-in Windows-subsystem target,
not an automatic CTest startup. It includes the production header and links the
actual common cancellation/ownership bodies with ORANGESPACE_FILE_LOCAL_IO_ONLY
(excludes networking only). NDEBUG cannot disable its throwing predicates.
It creates only the fresh protected LocalAppData leaf
`OrangeSpace-native-file-relative-7b2e8c4819d0-r2`; existing leaf returns 91 untouched.
Fixed receipt.txt/exitcode.txt are CREATE_NEW. No recursive cleanup; fixture leaves
are retained, owned parts are disposition-deleted, junctions removed by exact handle.
Codes: 0 all checks passed; 90 incomplete/assertion; 91 scope unavailable;
92 receipt failure; 93 unsafe redirect. Any nonzero result blocks acceptance.
Cases: positive set/delete junction, preexisting reparse rejection, mutation before
upload open and relative part creation, mutation between part creation/publication,
preexisting target preservation, publication success, cancellation/destructor cleanup.

The parent already observed the old production metadata-only pins permit the
junction IOCTL (exit 93); adding directory-list access did not repair it and caused
publication sharing failure. This is NOT a share-mask fix. The corrected native
fixture was run with the actual production header under a Limited interactive
Windows token: exit 0, no unsafe redirect and no incomplete case. The early
upload/create junction changes really succeeded; they did not redirect access to
the outside target. After part creation, the nonempty-ancestor junction attempt
was blocked by NTFS (145) and directory rename by sharing (32); released-handle
rename control succeeded. This is not evidence of a successful late junction
mutation. Publication/no-clobber/cancel/destructor cases passed, with outside
sink absence and original/sentinel bytes independently read back. Full HTTPS GUI,
new-package provenance and corresponding new-commit CI acceptance remain separate.
