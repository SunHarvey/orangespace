"""Portable execution of actual production path gates; not native Win32 evidence."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
spec = importlib.util.spec_from_file_location("profile_baseline", HERE / "bootstrap_profile_failure_tests.py")
assert spec is not None and spec.loader is not None
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

SERVICE_SHIM = r'''
#include <filesystem>
#include <string>
#include <vector>
#include <iostream>
#include <stdexcept>
using DWORD=unsigned long;using BOOL=int;using PWSTR=wchar_t*;
constexpr int S_OK=0;
constexpr DWORD INVALID_FILE_ATTRIBUTES=~DWORD{0}, FILE_ATTRIBUTE_REPARSE_POINT=0x400, FILE_ATTRIBUTE_DIRECTORY=16;
std::string scenario;std::vector<std::string> calls;bool impersonating=false;
void need(bool b){if(!b)throw std::runtime_error("denied");}
namespace fs {using path=std::filesystem::path;void create_directories(const path&){calls.push_back("temp");need(impersonating);if(scenario=="temp_throw")throw std::runtime_error("temp");}}
struct Token{void* get(){return nullptr;}};struct Session{Token token;}s;void* package=nullptr;
bool ImpersonateLoggedOnUser(void*){calls.push_back("impersonate");impersonating=true;return true;}
std::wstring sidtext(void*){need(impersonating);return L"actual-package-sid";}
int GetAppContainerFolderPath(const wchar_t* sid,PWSTR* p){need(impersonating&&std::wstring(sid)==L"actual-package-sid");calls.push_back("folder");static wchar_t folder[]=L"/package/private";*p=folder;return scenario=="folder"?-1:0;}
DWORD GetFileAttributesW(const char* p){need(impersonating);calls.push_back(p);auto sep=scenario.find(':');if(sep!=std::string::npos&&scenario.substr(sep+1)==p){auto kind=scenario.substr(0,sep);if(kind=="invalid")return INVALID_FILE_ATTRIBUTES;if(kind=="reparse")return 16|0x400;if(kind=="file")return 0;if(kind=="throw")throw std::runtime_error("query");}return 16;}
void CoTaskMemFree(PWSTR){calls.push_back("free");}
BOOL RevertToSelf(){calls.push_back("revert");impersonating=false;return scenario!="revert";}
void run(){
'''
SERVICE_TAIL = r'''
calls.push_back("CreateProcessAsUserW");calls.push_back("ResumeThread");
}
int main(int,char**argv){scenario=argv[1];try{run();std::cout<<0<<"\n";}catch(...){std::cout<<1<<"\n";}for(auto&c:calls)std::cout<<c<<"\n";}
'''


class OwnerContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="profile-owner-", dir=os.environ.get("TMPDIR"))
        cls.service = (ROOT / "windows-service/prototype/service_win.cpp").read_text()
        cls.bootstrap = base.SOURCE.read_text()
        a = cls.service.index(" need(ImpersonateLoggedOnUser", cls.service.index("std::vector<wchar_t> environment"))
        b = cls.service.index("\n std::map", a)
        root = cls.bootstrap[cls.bootstrap.index("  HANDLE token{};if(!OpenProcessToken"):cls.bootstrap.index("  CefRunMessageLoop();")]
        shim = base.SHIMS.replace('int run() {', '''void ProfilePathFailure(const char*,DWORD,DWORD){record("diagnostic");}
int run() {''')
        shim = shim.replace('std::string prefix=created?', '''if(std::string(path)=="/package") return INVALID_FILE_ATTRIBUTES;
  if(scenario==std::string(created?"post_root_":"pre_root_")+"missing" && std::string(path)=="/package/private") return INVALID_FILE_ATTRIBUTES;
  if(created && scenario=="post_root_reparse" && std::string(path)=="/package/private") return FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT;
  if(created && scenario=="post_root_file" && std::string(path)=="/package/private") return 0;
  std::string prefix=created?''')
        cls.binaries = {}
        for name, text in [("service", SERVICE_SHIM + cls.service[a:b] + SERVICE_TAIL), ("root", shim + root + base.TAIL)]:
            cpp = Path(cls.temp.name) / (name + ".cpp")
            cpp.write_text(text)
            binary = cpp.with_suffix("")
            subprocess.run(["g++", "-std=c++20", "-Wall", "-Wextra", "-Werror", str(cpp), "-o", str(binary)], check=True, capture_output=True, text=True)
            cls.binaries[name] = binary

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_gate(self, name, scenario):
        p = subprocess.run([str(self.binaries[name]), scenario], check=True, capture_output=True, text=True)
        lines = p.stdout.splitlines()
        return int(lines[0]), lines[1:]

    def test_service_full_chain_failure_prevents_launch_and_reverts(self):
        for path in ["/package/private", "/package"]:
            for kind in ["invalid", "reparse", "file", "throw"]:
                with self.subTest(path=path, kind=kind):
                    code, calls = self.run_gate("service", kind + ":" + path)
                    self.assertEqual(code, 1)
                    self.assertEqual(calls[-2:], ["free", "revert"])
                    self.assertNotIn("CreateProcessAsUserW", calls)
                    self.assertNotIn("ResumeThread", calls)

    def test_service_success_checks_chain_under_user_context(self):
        code, calls = self.run_gate("service", "success")
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["impersonate", "folder", "/package/private", "/package", "temp", "free", "revert", "CreateProcessAsUserW", "ResumeThread"])
        self.assertLess(self.service.index("auto env=environment(s,package)"), self.service.index("BOOL made=CreateProcessAsUserW"))

    def test_service_exceptions_and_revert_failure_stay_closed(self):
        for scenario in ["folder", "temp_throw", "revert"]:
            code, calls = self.run_gate("service", scenario)
            self.assertEqual(code, 1)
            self.assertEqual(calls[-1], "revert")
            self.assertNotIn("CreateProcessAsUserW", calls)

    def test_cap0_never_queries_above_private_root(self):
        for scenario in ["success", "exists"]:
            code, calls = self.run_gate("root", scenario)
            self.assertEqual(code, 0)
            self.assertEqual([x for x in calls if x.startswith(("pre:", "post:"))], ["pre:/package/private", "post:/package/private/BrowserCache", "post:/package/private"])
            self.assertNotIn("diagnostic", calls)

    def test_private_root_and_cache_fail_closed(self):
        for scenario, expected in [("pre_missing",244),("pre_reparse",244),("pre_file",244),("post_missing",246),("post_reparse",246),("post_file",246),("post_root_missing",246),("post_root_reparse",246),("post_root_file",246),("mkdir",245)]:
            with self.subTest(scenario=scenario):
                code, calls = self.run_gate("root", scenario)
                self.assertEqual(code, expected)
                self.assertNotIn("initialize", calls)


if __name__ == "__main__":
    unittest.main()
