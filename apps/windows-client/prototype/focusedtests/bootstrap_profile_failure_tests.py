"""Compile the actual Bootstrap profile/initialize block with local API shims.

Portable branch evidence only: this does not execute Win32 or CEF. The fixed
baseline digest binds the entire pre-diagnostic TU, including success behavior.
"""
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "bootstrap_prototype_win.cc"
BASELINE_SHA256 = "d9c906e5a478fbcd87dded2b972edc8812cb90906032e367c912a2d3f1b192ee"

SHIMS = r'''
#include <filesystem>
#include <string>
#include <vector>
#include <iostream>
#include <cstdlib>
using HANDLE = void*;
using BYTE = unsigned char;
using DWORD = unsigned long;
using BOOL = int;
using LPWSTR = wchar_t*;
using HRESULT = long;
struct TOKEN_APPCONTAINER_INFORMATION { void* TokenAppContainer; };
constexpr int TOKEN_QUERY=8, TokenAppContainerSid=31;
constexpr DWORD INVALID_FILE_ATTRIBUTES=~DWORD{0};
constexpr DWORD FILE_ATTRIBUTE_REPARSE_POINT=0x400, FILE_ATTRIBUTE_DIRECTORY=0x10;
constexpr int ERROR_ALREADY_EXISTS=183, S_OK=0, LOGSEVERITY_DISABLE=99;
std::string scenario;
std::vector<std::string> calls;
void record(const char* name) { calls.emplace_back(name); }
void* GetCurrentProcess() { record("process"); return reinterpret_cast<void*>(1); }
BOOL OpenProcessToken(HANDLE, int, HANDLE* out) {
  record("open"); *out=reinterpret_cast<void*>(2); return scenario!="open";
}
BOOL GetTokenInformation(HANDLE, int, BYTE* p, size_t, DWORD* size) {
  record("query"); *size=sizeof(TOKEN_APPCONTAINER_INFORMATION);
  reinterpret_cast<TOKEN_APPCONTAINER_INFORMATION*>(p)->TokenAppContainer=
      scenario=="null_sid" ? nullptr : reinterpret_cast<void*>(3);
  return scenario!="query";
}
void CloseHandle(HANDLE) { record("close"); }
BOOL ConvertSidToStringSidW(void*, LPWSTR* out) {
  record("sid"); static wchar_t sid[]=L"S-1-15-2-test"; *out=sid;
  return scenario!="sid";
}
HRESULT GetAppContainerFolderPath(LPWSTR, LPWSTR* out) {
  record("folder"); static wchar_t folder[]=L"/package/private"; *out=folder;
  return scenario=="folder" ? -1 : S_OK;
}
void LocalFree(LPWSTR) { record("free_sid"); }
void CoTaskMemFree(LPWSTR) { record("free_folder"); }
bool created=false;
DWORD GetFileAttributesW(const char* path) {
  record((std::string(created?"post:":"pre:")+path).c_str());
  std::string prefix=created?"post_":"pre_";
  if (scenario==prefix+"missing") return INVALID_FILE_ATTRIBUTES;
  if (scenario==prefix+"reparse") return FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT;
  if (scenario==prefix+"file") return 0;
  return FILE_ATTRIBUTE_DIRECTORY;
}
BOOL CreateDirectoryW(const char*, void*) {
  record("mkdir"); created=true;
  return scenario!="mkdir" && scenario!="exists";
}
DWORD GetLastError() { record("last_error"); return scenario=="exists"?ERROR_ALREADY_EXISTS:5; }
struct Settings {
  std::wstring root_cache_path, cache_path, log_file;
  int log_severity=0;
} settings;
std::wstring& CefString(std::wstring* out) { record("setting"); return *out; }
std::wstring OfflineLogPath(const wchar_t* name) { record("log_path"); return name; }
int args=0, app=0;
void* sandbox_info=reinterpret_cast<void*>(4);
BOOL CefInitialize(int, const Settings& s, int, void* sandbox) {
  record("initialize");
  if (s.root_cache_path!=L"/package/private/BrowserCache" ||
      s.cache_path!=s.root_cache_path || s.log_file!=L"orangespace-cef.log" ||
      s.log_severity!=LOGSEVERITY_DISABLE || sandbox!=sandbox_info) std::abort();
  return scenario!="initialize";
}
int run() {
'''
TAIL = r'''
  return 0;
}
int main(int argc, char** argv) {
  if(argc!=2) return 2;
  scenario=argv[1]; const int result=run();
  std::cout << result << "\n";
  for(const auto& name:calls) std::cout << name << "\n";
}
'''


class ProfileFailureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = SOURCE.read_bytes()
        source = cls.original.decode()
        start = source.index("  HANDLE token{};if(!OpenProcessToken")
        end = source.index("  CefRunMessageLoop();", start)
        cls.temp = tempfile.TemporaryDirectory(prefix="bootstrap-profile-", dir=os.environ.get("TMPDIR"))
        cpp = Path(cls.temp.name) / "branches.cpp"
        cpp.write_text(SHIMS + source[start:end] + TAIL)
        cls.binary = cpp.with_suffix("")
        subprocess.run(["g++", "-std=c++20", "-Wall", "-Wextra", "-Werror", str(cpp), "-o", str(cls.binary)], check=True, capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def outcome(self, scenario, code, expected_calls):
        result = subprocess.run([str(self.binary), scenario], check=True, capture_output=True, text=True)
        lines = result.stdout.splitlines()
        self.assertEqual(int(lines[0]), code, scenario)
        self.assertEqual(lines[1:], expected_calls, scenario)

    def test_open_process_token_240(self):
        self.outcome("open", 240, ["process", "open"])

    def test_get_token_information_241(self):
        self.outcome("query", 241, ["process", "open", "query", "close"])

    def test_sid_conversion_242(self):
        self.outcome("sid", 242, ["process", "open", "query", "close", "sid"])
        self.outcome("null_sid", 242, ["process", "open", "query", "close"])

    def test_package_folder_243(self):
        self.outcome("folder", 243, ["process", "open", "query", "close", "sid", "folder", "free_sid"])

    def prefix(self):
        return ["process", "open", "query", "close", "sid", "folder", "free_sid", "free_folder"]

    def before_mkdir(self):
        return self.prefix() + ["pre:/package/private", "pre:/package"]

    def before_initialize(self):
        return self.before_mkdir() + ["mkdir", "post:/package/private/BrowserCache", "post:/package/private", "post:/package", "setting", "setting", "log_path", "setting"]

    def test_parent_ancestry_attributes_244(self):
        for variant in ["missing", "reparse", "file"]:
            self.outcome("pre_"+variant, 244, self.prefix()+["pre:/package/private"])

    def test_create_directory_245(self):
        self.outcome("mkdir", 245, self.before_mkdir()+["mkdir", "last_error"])

    def test_cache_ancestry_attributes_246(self):
        for variant in ["missing", "reparse", "file"]:
            self.outcome("post_"+variant, 246, self.before_mkdir()+["mkdir", "post:/package/private/BrowserCache"])

    def test_cef_initialize_247(self):
        self.outcome("initialize", 247, self.before_initialize()+["initialize"])

    def test_success_and_existing_directory_unchanged(self):
        self.outcome("success", 0, self.before_initialize()+["initialize"])
        calls = self.before_initialize()
        calls.insert(calls.index("mkdir")+1, "last_error")
        self.outcome("exists", 0, calls+["initialize"])

    def test_inverse_diagnostics_is_entire_original_tu_byte_exact(self):
        normalized = re.sub(rb"return 24[0-7];", b"return 24;", self.original)
        self.assertEqual(hashlib.sha256(normalized).hexdigest(), BASELINE_SHA256)

    def test_eight_unique_codes_in_profile_block(self):
        source = self.original.decode()
        block = source[source.index("  HANDLE token{};if(!OpenProcessToken"):source.index("  CefRunMessageLoop();")]
        self.assertEqual(re.findall(r"return (\d+);", block), [str(x) for x in range(240, 248)])


if __name__ == "__main__":
    unittest.main()
