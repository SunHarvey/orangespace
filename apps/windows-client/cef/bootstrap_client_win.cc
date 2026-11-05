#include "bootstrap_policy.hpp"
#include "cef_pin.hpp"

#include "include/base/cef_logging.h"
#include "include/cef_api_hash.h"
#include "include/cef_sandbox_win.h"
#include "include/wrapper/cef_library_loader.h"
#include "include/wrapper/cef_util_win.h"

#include <cstring>
#include <string>
#include <string_view>
#include <type_traits>

namespace orangespace::cef_host {
static_assert(CEF_API_VERSION == pin::api_version);
static_assert(std::string_view(CEF_VERSION) == pin::version);
static_assert(std::string_view(CEF_COMMIT_HASH) == pin::commit);
static_assert(std::string_view(CEF_API_HASH_PLATFORM) == pin::api_hash);
static_assert(std::string_view(CEF_SANDBOX_COMPAT_HASH) == pin::sandbox_hash);

namespace {
BootstrapVersion Snapshot(const cef_version_info_t& info) {
  return {{{info.cef_version_major, info.cef_version_minor,
            info.cef_version_patch, info.cef_commit_number,
            info.chrome_version_major, info.chrome_version_minor,
            info.chrome_version_build, info.chrome_version_patch}},
          std::string_view(info.sandbox_compat_hash, 16)};
}
}  // namespace
}  // namespace orangespace::cef_host

// Exactly the CEF header's C-linkage, cdecl ABI, NOT WINAPI/wWinMain.
// The sandbox is owned by the matching official bootstrap; never substitute
// a locally allocated object, null pointer, or a sandbox-disabling setting.
CEF_BOOTSTRAP_EXPORT int RunWinMain(HINSTANCE, LPWSTR, int,
                                   void* sandbox_info,
                                   cef_version_info_t* version_info) {
  using namespace orangespace::cef_host;
  if (!sandbox_info) return static_cast<int>(StartupResult::invalid_sandbox);
  if (!version_info || version_info->size != sizeof(cef_version_info_t) ||
      version_info->sandbox_compat_hash[16] != '\0')
    return static_cast<int>(StartupResult::invalid_bootstrap);

  cef_version_info_t expected_info = {};
  CEF_POPULATE_VERSION_INFO(&expected_info);
  const auto expected = Snapshot(expected_info);
  const auto actual = Snapshot(*version_info);
  auto result = CheckBootstrap(sandbox_info, &actual, expected);
  if (result != StartupResult::compatible) return static_cast<int>(result);

  // No installer/CDN resolution, machine-wide runtime, or fallback discovery.
  // The compile-only output does not stage a libcef runtime; an attempted launch
  // therefore fails closed even before these compatibility checks can finish.
  if (version_info->installer_error_code || version_info->libcef_path)
    return static_cast<int>(StartupResult::invalid_bootstrap);
  CefScopedLibraryLoader loader;
  {
    cef::logging::ScopedEarlySupport early_logging({});
    const auto executable = cef_util::GetExePath();
    const auto separator = executable.find_last_of(L"/\\");
    if (separator == std::wstring::npos)
      return static_cast<int>(StartupResult::invalid_runtime);
    const std::wstring library = executable.substr(0, separator + 1) + L"libcef.dll";
    // Failures intentionally terminate in the upstream loader. No unsigned
    // library allowance, no PATH search, no weaker fallback after failure.
    if (!loader.LoadInMainAssert(library.c_str(), nullptr, false, &expected_info))
      return static_cast<int>(StartupResult::invalid_runtime);
  }

  result = CheckRuntime(cef_api_hash(CEF_API_VERSION, 0),
                        cef_api_hash(CEF_API_VERSION, 2),
                        cef_api_hash(CEF_API_VERSION, 3), cef_version_full(),
                        {pin::api_hash, pin::commit, pin::sandbox_hash, pin::version});
  if (result != StartupResult::compatible) return static_cast<int>(result);

  // Compatibility does not authorize network access. Phase 1 has no verified
  // process-bound service grant, so deny unconditionally. Intentionally NO
  // CefExecuteProcess, CefInitialize, message loop, browser, or profile writes.
  return static_cast<int>(CompileOnlyLaunchDecision());
}

using BootstrapEntry = int (*)(HINSTANCE, LPWSTR, int, void*, cef_version_info_t*);
static_assert(std::is_same_v<decltype(&RunWinMain), BootstrapEntry>);
