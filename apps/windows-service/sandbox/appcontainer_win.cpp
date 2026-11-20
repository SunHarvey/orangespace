#include "appcontainer_win.hpp"

#include <aclapi.h>
#include <sddl.h>
#include <userenv.h>

#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")

namespace orangespace::sandbox {

void SidDeleter::operator()(void* sid) const noexcept {
  if (sid) FreeSid(sid);
}

std::wstring PackageName(const std::string& sandbox_uuid) {
  std::wstring name = L"OrangeSpace.Sandbox.";
  for (const char c : sandbox_uuid) {
    if (c == '-') continue;
    const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    if (!hex) throw std::invalid_argument("sandbox id must be a canonical lowercase UUID");
    name.push_back(static_cast<wchar_t>(c));
  }
  if (name.size() != 20 + 32) throw std::invalid_argument("sandbox id must be a canonical lowercase UUID");
  return name;
}

std::wstring SidToString(void* sid) {
  LPWSTR text = nullptr;
  if (!ConvertSidToStringSidW(sid, &text)) throw Win32Error("ConvertSidToStringSid", GetLastError());
  std::wstring out(text);
  LocalFree(text);
  return out;
}

UniqueSid PackageSid(const std::string& sandbox_uuid) {
  PSID sid = nullptr;
  const HRESULT hr = DeriveAppContainerSidFromAppContainerName(PackageName(sandbox_uuid).c_str(), &sid);
  if (FAILED(hr) || !sid) throw Win32Error("DeriveAppContainerSidFromAppContainerName", static_cast<DWORD>(hr));
  return UniqueSid(sid);
}

Package EnsurePackage(const std::string& sandbox_uuid) {
  Package p;
  p.name = PackageName(sandbox_uuid);
  PSID sid = nullptr;
  HRESULT hr = CreateAppContainerProfile(p.name.c_str(), L"OrangeSpace sandbox", L"OrangeSpace sandbox browser",
                                         nullptr, 0, &sid);
  if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
    hr = DeriveAppContainerSidFromAppContainerName(p.name.c_str(), &sid);
  }
  if (FAILED(hr) || !sid) throw Win32Error("CreateAppContainerProfile", static_cast<DWORD>(hr));
  p.sid.reset(sid);
  p.sid_string = SidToString(sid);
  return p;
}

void DeletePackage(const std::string& sandbox_uuid) {
  const auto name = PackageName(sandbox_uuid);
  const HRESULT hr = DeleteAppContainerProfile(name.c_str());
  if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_NOT_FOUND) && hr != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND))
    throw Win32Error("DeleteAppContainerProfile", static_cast<DWORD>(hr));
}

namespace {
void MergeAce(HANDLE object, SE_OBJECT_TYPE type, const wchar_t* name, void* sid, DWORD access, DWORD inheritance) {
  PACL old_dacl = nullptr;
  PSECURITY_DESCRIPTOR sd = nullptr;
  DWORD rc = name ? GetNamedSecurityInfoW(name, type, DACL_SECURITY_INFORMATION, nullptr, nullptr, &old_dacl,
                                          nullptr, &sd)
                  : GetSecurityInfo(object, type, DACL_SECURITY_INFORMATION, nullptr, nullptr, &old_dacl, nullptr,
                                    &sd);
  if (rc != ERROR_SUCCESS) throw Win32Error("GetSecurityInfo", rc);
  EXPLICIT_ACCESSW ea{};
  ea.grfAccessPermissions = access;
  ea.grfAccessMode = GRANT_ACCESS;
  ea.grfInheritance = inheritance;
  ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
  ea.Trustee.ptstrName = static_cast<LPWSTR>(sid);
  PACL new_dacl = nullptr;
  rc = SetEntriesInAclW(1, &ea, old_dacl, &new_dacl);
  if (rc != ERROR_SUCCESS) {
    LocalFree(sd);
    throw Win32Error("SetEntriesInAcl", rc);
  }
  rc = name ? SetNamedSecurityInfoW(const_cast<LPWSTR>(name), type, DACL_SECURITY_INFORMATION, nullptr, nullptr,
                                    new_dacl, nullptr)
            : SetSecurityInfo(object, type, DACL_SECURITY_INFORMATION, nullptr, nullptr, new_dacl, nullptr);
  LocalFree(new_dacl);
  LocalFree(sd);
  if (rc != ERROR_SUCCESS) throw Win32Error("SetSecurityInfo", rc);
}
}  // namespace

void GrantPath(const std::wstring& path, void* sid, DWORD access, bool inherit) {
  MergeAce(nullptr, SE_FILE_OBJECT, path.c_str(), sid, access,
           inherit ? SUB_CONTAINERS_AND_OBJECTS_INHERIT : NO_INHERITANCE);
}

void GrantRuntimeToChromiumSandboxes(const std::wstring& runtime_dir) {
  // Chromium's GPU process runs in an LPAC that additionally holds the
  // "lpacChromeInstallFiles" capability; Chrome's installer grants that
  // capability read/execute on the install directory.
  PSID* groups = nullptr;
  DWORD group_count = 0;
  PSID* caps = nullptr;
  DWORD cap_count = 0;
  // Not in the import libraries of every SDK; resolve from kernelbase.
  using Derive = BOOL(WINAPI*)(LPCWSTR, PSID**, DWORD*, PSID**, DWORD*);
  const HMODULE kernelbase = GetModuleHandleW(L"kernelbase.dll");
  const auto derive = reinterpret_cast<Derive>(
      reinterpret_cast<void*>(kernelbase ? GetProcAddress(kernelbase, "DeriveCapabilitySidsFromName") : nullptr));
  if (!derive) throw Win32Error("GetProcAddress(DeriveCapabilitySidsFromName)", ERROR_PROC_NOT_FOUND);
  if (!derive(L"lpacChromeInstallFiles", &groups, &group_count, &caps, &cap_count))
    throw Win32Error("DeriveCapabilitySidsFromName", GetLastError());
  try {
    for (DWORD i = 0; i < cap_count; ++i) GrantPath(runtime_dir, caps[i], GENERIC_READ | GENERIC_EXECUTE, true);
  } catch (...) {
    for (DWORD i = 0; i < group_count; ++i) LocalFree(groups[i]);
    for (DWORD i = 0; i < cap_count; ++i) LocalFree(caps[i]);
    LocalFree(groups);
    LocalFree(caps);
    throw;
  }
  for (DWORD i = 0; i < group_count; ++i) LocalFree(groups[i]);
  for (DWORD i = 0; i < cap_count; ++i) LocalFree(caps[i]);
  LocalFree(groups);
  LocalFree(caps);
  for (const wchar_t* text : {L"S-1-15-2-1", L"S-1-15-2-2"}) {
    PSID sid = nullptr;
    if (!ConvertStringSidToSidW(text, &sid)) throw Win32Error("ConvertStringSidToSid", GetLastError());
    try {
      GrantPath(runtime_dir, sid, GENERIC_READ | GENERIC_EXECUTE, true);
    } catch (...) {
      LocalFree(sid);
      throw;
    }
    LocalFree(sid);
  }
}

}  // namespace orangespace::sandbox
