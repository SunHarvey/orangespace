#pragma once
// Per-sandbox AppContainer identity. Each sandbox gets its own package SID so
// that WFP rules, loopback exemption and file ACLs can name exactly one sandbox.
#include <windows.h>

#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace orangespace::sandbox {

struct SidDeleter {
  void operator()(void* sid) const noexcept;
};
using UniqueSid = std::unique_ptr<void, SidDeleter>;

class Win32Error : public std::runtime_error {
 public:
  Win32Error(const char* operation, DWORD code)
      : std::runtime_error(std::string(operation) + " failed: " + std::to_string(code)), code_(code) {}
  DWORD code() const noexcept { return code_; }

 private:
  DWORD code_;
};

// "OrangeSpace.Sandbox.<32 hex>" (<= 64 chars as required by the API).
std::wstring PackageName(const std::string& sandbox_uuid);

struct Package {
  std::wstring name;
  UniqueSid sid;   // AppContainer SID (S-1-15-2-...)
  std::wstring sid_string;
};

// Creates the profile for the calling (or impersonated) user, or derives the SID
// of an existing one. Must run as the interactive user whose session will host
// the browser, not as SYSTEM.
Package EnsurePackage(const std::string& sandbox_uuid);

// The sandbox's package SID, derived from its id alone (no profile needed).
// Lets a privileged component name the right package without trusting a SID
// supplied by a less privileged one.
UniqueSid PackageSid(const std::string& sandbox_uuid);

// Removes the AppContainer profile (and its AppData folder) of a deleted sandbox.
void DeletePackage(const std::string& sandbox_uuid);

// Adds an allow ACE for `sid` to `path` (merging with the existing DACL).
// `inherit` makes it apply to children (directories).
void GrantPath(const std::wstring& path, void* sid, DWORD access, bool inherit);

// Chromium runs its GPU (and other) processes in LPAC/AppContainer sandboxes.
// They can only load the runtime if the install directory grants read/execute
// to ALL APPLICATION PACKAGES (S-1-15-2-1) and ALL RESTRICTED APPLICATION
// PACKAGES (S-1-15-2-2), exactly as Chrome's own installer does.
void GrantRuntimeToChromiumSandboxes(const std::wstring& runtime_dir);

// Never add per-package ACEs to the interactive WinSta0/Default DACLs: they
// already grant ALL APPLICATION PACKAGES and ALL RESTRICTED APPLICATION
// PACKAGES, and measured on Windows 11 26H2 a single package-SID ACE makes
// user32.dll fail to initialise (ERROR_DLL_INIT_FAILED) in every
// low-integrity process of that logon session - including Chromium's GPU
// process - until the user logs off. `orangespace-netcheck --user32-restricted`
// checks this.

std::wstring SidToString(void* sid);

}  // namespace orangespace::sandbox
