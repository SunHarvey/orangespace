#pragma once

#include <array>
#include <string_view>

namespace orangespace::cef_host {
// Compatibility is not authorization. Only launch_denied leaves this phase's
// entry point after compatibility validation; no service-ready boolean exists.
enum class StartupResult : int {
  compatible = 0,
  invalid_sandbox = 20,
  invalid_bootstrap = 21,
  invalid_runtime = 22,
  launch_denied = 23,
};

struct BootstrapVersion {
  std::array<int, 8> numbers;
  std::string_view sandbox_hash;
};

inline StartupResult CheckBootstrap(const void* sandbox_info,
                                    const BootstrapVersion* actual,
                                    const BootstrapVersion& expected) {
  if (!sandbox_info) return StartupResult::invalid_sandbox;
  if (!actual || actual->numbers != expected.numbers ||
      actual->sandbox_hash != expected.sandbox_hash)
    return StartupResult::invalid_bootstrap;
  return StartupResult::compatible;
}

struct RuntimeHashes {
  std::string_view api;
  std::string_view commit;
  std::string_view sandbox;
  std::string_view full_version;
};

inline StartupResult CheckRuntime(const char* api, const char* commit,
                                 const char* sandbox, const char* full_version,
                                 const RuntimeHashes& expected) {
  if (!api || !commit || !sandbox || !full_version || api != expected.api ||
      commit != expected.commit || sandbox != expected.sandbox ||
      full_version != expected.full_version)
    return StartupResult::invalid_runtime;
  return StartupResult::compatible;
}

inline StartupResult CompileOnlyLaunchDecision() {
  return StartupResult::launch_denied;
}
}  // namespace orangespace::cef_host
