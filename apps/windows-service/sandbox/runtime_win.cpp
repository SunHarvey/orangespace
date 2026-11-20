#include "runtime_win.hpp"

#include "appcontainer_win.hpp"

#include <filesystem>
#include <system_error>

namespace orangespace::sandbox {
namespace fs = std::filesystem;

namespace {
bool SameFile(const fs::path& a, const fs::path& b) {
  std::error_code e1, e2, e3, e4;
  return fs::exists(b, e1) && fs::file_size(a, e2) == fs::file_size(b, e3) && !e2 && !e3 &&
         fs::last_write_time(a, e4) == fs::last_write_time(b, e4) && !e4;
}

void Mirror(const fs::path& source, const fs::path& target) {
  if (!CreateDirectoryW(target.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
    throw Win32Error("CreateDirectory(sandbox runtime)", GetLastError());
  const DWORD attrs = GetFileAttributesW(target.c_str());
  if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_DIRECTORY) || (attrs & FILE_ATTRIBUTE_REPARSE_POINT))
    throw std::runtime_error("sandbox runtime directory is not a plain directory");
  for (const auto& entry : fs::directory_iterator(source)) {
    const auto dest = target / entry.path().filename();
    if (entry.is_directory()) {
      Mirror(entry.path(), dest);
      continue;
    }
    if (!entry.is_regular_file()) continue;
    if (SameFile(entry.path(), dest)) continue;
    DeleteFileW(dest.c_str());
    if (!CreateHardLinkW(dest.c_str(), entry.path().c_str(), nullptr)) {
      // Different volume (or links not permitted): fall back to a copy.
      if (!CopyFileW(entry.path().c_str(), dest.c_str(), FALSE))
        throw Win32Error("CopyFile(sandbox runtime)", GetLastError());
    }
  }
}
}  // namespace

std::wstring PrepareSandboxRuntime(const std::wstring& shared_runtime_dir, const std::wstring& sandbox_dir) {
  const fs::path source(shared_runtime_dir);
  if (!fs::is_regular_file(source / L"osbrowser.exe")) throw std::runtime_error("shared runtime lacks osbrowser.exe");
  fs::create_directories(fs::path(sandbox_dir).parent_path());
  Mirror(source, sandbox_dir);
  // Hard links share the shared runtime's file ACLs, but the new directories do
  // not: Chromium's sandboxed children (AppContainer/LPAC tokens) must be able
  // to traverse and map them, exactly as for the shared runtime.
  GrantRuntimeToChromiumSandboxes(sandbox_dir);
  const auto exe = fs::path(sandbox_dir) / L"osbrowser.exe";
  return exe.wstring();
}

void RemoveSandboxRuntime(const std::wstring& sandbox_dir) {
  std::error_code ec;
  fs::remove_all(sandbox_dir, ec);  // hard links: removing them leaves the shared runtime intact
  if (ec) throw std::runtime_error("cannot remove sandbox runtime: " + ec.message());
}

}  // namespace orangespace::sandbox
