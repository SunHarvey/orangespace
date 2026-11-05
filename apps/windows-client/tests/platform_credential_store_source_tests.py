"""Source integration guards, not native DPAPI acceptance."""
import pathlib
import unittest
import os
import subprocess
import tempfile

SOURCE = pathlib.Path(__file__).resolve().parents[1] / 'src/credential_store_win.cpp'

class PlatformStoreSource(unittest.TestCase):
    def platform(self):
        source = SOURCE.read_text()
        self.assertIn('namespace orangespace::platform_session {', source)
        return source.split('namespace orangespace::platform_session {', 1)[1]

    def test_store_reuses_protected_io_and_real_restore(self):
        source = self.platform()
        for item in ['CredentialStore::save(', 'CredentialStore::load(', 'CredentialStore::erase(',
                     'Directory directory(StoreKind::platform)', 'NodeLock lock(', 'require_not_pending(',
                     'credential_detail::validate_envelope(', 'encrypt(', 'decrypt(', 'atomic_write(',
                     'erase_pending(', 'Session::restore(config, envelope)']:
            self.assertIn(item, source)
        self.assertNotIn('validate_envelope(*', source)
        self.assertNotIn('CryptProtectData', source)
        self.assertNotIn('CreateFileW', source)

    def test_storage_key_is_hash_of_protected_origin_not_identity(self):
        source = self.platform()
        self.assertIn('BCryptHash(', source)
        self.assertIn('BCRYPT_SHA256_ALGORITHM', source)
        self.assertIn('config.api_origin()', source)
        self.assertIn('storage-only', source)
        self.assertNotIn('central_user_id', source)

    def test_pending_cleanup_preserves_restore_error(self):
        source = self.platform()
        self.assertIn('try {erase_pending(directory, key);} catch (...) {}', source)
        self.assertIn('file.reset();', source)
        self.assertIn('throw;', source)

    def test_failed_promoted_credential_is_removed_but_logout_marker_survives(self):
        # Execute the exact production failure handler, not a duplicate predicate.
        # Injected cleanup policy only: no DPAPI/NTFS durability claim.
        source = SOURCE.read_text()
        writer = source.split('void atomic_write_leaf(', 1)[1].split('\nvoid atomic_write(', 1)[0]
        handler = writer.split('} catch (...) {', 1)[1].rsplit('\n  }', 1)[0]
        cpp = r'''
#include <cassert>
struct File { int get() { return 1; } };
static int purged=0;
void purge(int) { ++purged; }
void failed(bool promoted, bool preserve_promoted) {
  File file;
  (void)promoted; (void)preserve_promoted;
  try { throw 7; } catch (...) { /*HANDLER*/ }
}
int main() {
  for (bool promoted : {false, true}) {
    for (bool marker : {false, true}) {
      purged=0; bool original=false;
      try { failed(promoted, marker); } catch (int n) { original=n==7; }
      assert(original);
      assert(purged == ((promoted && marker) ? 0 : 1));
    }
  }
}
'''.replace('#include <cassert>', '#include <cassert>\n#include <initializer_list>').replace('/*HANDLER*/', handler)
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as td:
            path=pathlib.Path(td)/'failure.cpp'; exe=pathlib.Path(td)/'failure'
            path.write_text(cpp)
            subprocess.run(['g++','-std=c++20','-Wall','-Wextra','-Werror',str(path),'-o',str(exe)],check=True)
            result=subprocess.run([str(exe)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('bool preserve_promoted = false', writer)
        self.assertIn('atomic_write_leaf(directory, pending_leaf(directory, node), blob, true)', source)


    def test_install_storage_isolation_executes_production_paths(self):
        # Compile exact production selection/preparation slices with OS seams.
        broker = (SOURCE.parent / 'broker_win.cpp').read_text()
        store = SOURCE.read_text()
        def function(source, signature):
            start = source.index(signature)
            brace = source.index('{', start)
            depth = 1
            end = brace + 1
            while depth:
                depth += (source[end] == '{') - (source[end] == '}')
                end += 1
            return source[start:end]
        # Baseline extraction intentionally executes the OLD shared-root path.
        if 'std::wstring credential_directory_leaf(' in store:
            selection = function(store, 'std::wstring credential_directory_leaf(')
            path_code = store.split('// Separate protected product root: do not alter broker/profile directories.', 1)[1].split('    checked(detail::explicit_local_path(path))', 1)[0]
        else:
            selection = ''
            path_code = store[store.index('    path = kind =='):store.index('    checked(detail::explicit_local_path(path))')]
        prep = broker[broker.index('  std::wstring command = quote_argument(executable);'):broker.index('  SECURITY_ATTRIBUTES security')]
        identity = SOURCE.parents[2] / 'windows-service/include/orangespace/install_identity.hpp'
        model = SOURCE.parents[1] / 'include/orangespace/model.hpp'
        cpp = r'''
#include <cassert>
#include <string>
#include <vector>
#include <stdexcept>
#include <cstdlib>
#include "IDENTITY"
#include "MODEL"
using namespace orangespace;
namespace platform_session::credential_detail {
constexpr std::wstring_view directory_name = L"OrangeSpace-Platform-Credentials-v1";
}
enum class StoreKind { node, platform };
SELECTION
using PWSTR = wchar_t*;
constexpr int FOLDERID_LocalAppData=1, KF_FLAG_DEFAULT=0;
static bool folder_ok=true, folder_null=false;
static int queries=0, frees=0;
int SHGetKnownFolderPath(int, int, void*, PWSTR* p) {
  ++queries; *p=folder_null ? nullptr : const_cast<wchar_t*>(L"C:\\Users\\Alice Space\\AppData\\Local");
  return folder_ok ? 0 : -1;
}
bool FAILED(int hr) { return hr < 0; }
void CoTaskMemFree(PWSTR) { ++frees; }
struct Result { std::wstring failure; };
std::wstring prepare(const std::vector<std::wstring>& arguments, Result& result) {
  (void)result;
  const std::wstring executable=L"C:\\Program Files\\OrangeSpace\\orangespace-broker.exe";
PREP
  return command;
}
int main() {
  const std::wstring local=L"C:\\Users\\Alice Space\\AppData\\Local";
  const auto suffix=std::wstring(install_identity::suffix.begin(), install_identity::suffix.end());
  for (auto kind : {StoreKind::node, StoreKind::platform}) {
    std::wstring path;
PATH_CODE
    auto expected=local+L"\\"+(kind==StoreKind::node ? L"OrangeSpace-Credentials-v1" : L"OrangeSpace-Platform-Credentials-v1");
    if (!suffix.empty()) expected+=L".Dev."+suffix;
    assert(path==expected);
  }
  const std::vector<std::wstring> args={L"list",L"--user",L"a b",L"trailing\\",L"quote\""};
  const auto executable=L"C:\\Program Files\\OrangeSpace\\orangespace-broker.exe";
  std::wstring expected=quote_argument(executable);
  if (!suffix.empty()) expected+=L" "+quote_argument(L"--data-dir")+L" "+quote_argument(local+L"\\OrangeSpace.Dev."+suffix);
  for (const auto& arg:args) expected+=L" "+quote_argument(arg);
  Result result;
  assert(prepare(args,result)==expected);
  assert(queries==(suffix.empty()?0:1));
  assert(frees==queries);
  if (!suffix.empty()) {
    for (bool null_path : {false,true}) {
      folder_ok=null_path; folder_null=null_path;
      result.failure.clear();
      assert(prepare(args,result).empty());
      assert(!result.failure.empty());
    }
  }
}
'''.replace('IDENTITY',str(identity)).replace('MODEL',str(model)).replace('SELECTION',selection).replace('PREP',prep.replace('return result;', 'return {};')).replace('PATH_CODE',path_code)
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as td:
            path=pathlib.Path(td)/'isolation.cpp'; exe=pathlib.Path(td)/'isolation'
            path.write_text(cpp)
            for suffix in ['', 'dev-2026', 'other']:
                subprocess.run(['g++','-std=c++20','-Wall','-Wextra','-Werror',
                                '-I'+str(SOURCE.parents[1] / 'include'), '-Wno-unused-function', '-DORANGESPACE_DEVELOPMENT_INSTALL_ID="'+suffix+'"',
                                str(path),'-o',str(exe)],check=True)
                result=subprocess.run([str(exe)],capture_output=True,text=True)
                self.assertEqual(result.returncode,0,'suffix='+suffix+' '+result.stderr)

if __name__ == '__main__': unittest.main()
