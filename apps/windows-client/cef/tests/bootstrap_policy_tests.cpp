#include "bootstrap_policy.hpp"

#include <iostream>

using namespace orangespace::cef_host;
int main() {
  const BootstrapVersion expected{{156, 0, 14, 1, 156, 0, 8078, 48}, "sandbox"};
  int opaque_sandbox = 1;  // Only a policy fixture, not a Chromium sandbox.
  if (CheckBootstrap(nullptr, &expected, expected) != StartupResult::invalid_sandbox) return 1;
  if (CheckBootstrap(&opaque_sandbox, nullptr, expected) != StartupResult::invalid_bootstrap) return 2;
  auto wrong = expected;
  ++wrong.numbers[7];
  if (CheckBootstrap(&opaque_sandbox, &wrong, expected) != StartupResult::invalid_bootstrap) return 3;
  wrong = expected;
  wrong.sandbox_hash = "wrong";
  if (CheckBootstrap(&opaque_sandbox, &wrong, expected) != StartupResult::invalid_bootstrap) return 4;
  if (CheckBootstrap(&opaque_sandbox, &expected, expected) != StartupResult::compatible) return 5;
  const RuntimeHashes hashes{"api", "commit", "sandbox", "version"};
  if (CheckRuntime(nullptr, "commit", "sandbox", "version", hashes) != StartupResult::invalid_runtime) return 6;
  if (CheckRuntime("api", "commit", "wrong", "version", hashes) != StartupResult::invalid_runtime) return 7;
  if (CheckRuntime("api", "wrong", "sandbox", "version", hashes) != StartupResult::invalid_runtime) return 8;
  if (CheckRuntime("wrong", "commit", "sandbox", "version", hashes) != StartupResult::invalid_runtime) return 9;
  if (CheckRuntime("api", "commit", "sandbox", "wrong", hashes) != StartupResult::invalid_runtime) return 10;
  if (CheckRuntime("api", "commit", "sandbox", "version", hashes) != StartupResult::compatible) return 11;
  if (CompileOnlyLaunchDecision() != StartupResult::launch_denied) return 12;
  std::cout << "CEF bootstrap policy: sandbox/version/hash rejection and unconditional launch denial passed\n";
}
