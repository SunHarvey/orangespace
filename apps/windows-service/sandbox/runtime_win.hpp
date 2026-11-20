#pragma once
// Per-sandbox BrowserHost image path.
//
// WFP identifies a sandbox's browser processes by their image path (AppId), so
// each sandbox needs its own copy of osbrowser.exe and of everything that must
// sit next to it (the bootstrap loads osbrowser.dll and libcef.dll from its own
// directory). Files are hard links to the shared, hash-verified runtime, so a
// sandbox costs directory entries, not disk space; when the per-sandbox root is
// on another volume they are copied.
#include <windows.h>

#include <string>

namespace orangespace::sandbox {

// Creates/refreshes `sandbox_dir` as a mirror of `shared_runtime_dir` and returns
// the absolute path of the sandbox's osbrowser.exe. Existing entries that are
// not identical (size + last write) to the shared runtime are replaced.
std::wstring PrepareSandboxRuntime(const std::wstring& shared_runtime_dir, const std::wstring& sandbox_dir);

// Removes a sandbox runtime directory created by PrepareSandboxRuntime.
void RemoveSandboxRuntime(const std::wstring& sandbox_dir);

}  // namespace orangespace::sandbox
