// orangespace-wsl: developer/acceptance tool for the OrangeSpace WSL runtime
// (the same code the client uses). Run it in the user's interactive session.
//
//   orangespace-wsl status
//   orangespace-wsl import <rootfs.tar.gz> <install dir>
//   orangespace-wsl check [seconds]     start the agent, print its facts, verify the
//                                        distribution's isolation settings, keep it
//                                        running for <seconds>, then shut it down
//   orangespace-wsl terminate
//   orangespace-wsl unregister --delete-all-data
#include "orangespace/json.hpp"
#include "orangespace/wsl_runtime.hpp"

#include <cstdio>
#include <string>

namespace wsl = orangespace::wsl;
namespace json = orangespace::json;

namespace {
int usage() {
  std::fputs("usage: orangespace-wsl status | import <rootfs.tar.gz> <dir> | check [seconds] | terminate |"
             " unregister --delete-all-data\n",
             stderr);
  return 2;
}

int check(int seconds) {
  const DWORD started = GetTickCount();
  wsl::Agent agent;
  std::printf("agent started in %lu ms (wsl.exe pid %lu)\n", GetTickCount() - started, agent.pid());
  const std::string facts = agent.request(R"({"op":"facts"})");
  std::printf("facts: %s\n", facts.c_str());
  const auto value = json::Parser(facts).parse();
  int failures = 0;
  auto expect = [&](bool ok, const char* what) {
    std::printf("  %-48s %s\n", what, ok ? "PASS" : "FAIL");
    failures += ok ? 0 : 1;
  };
  const auto* drives = value.find("windows_drives");
  expect(drives && std::get<json::Value::Array>(drives->data).empty(), "no Windows drives mounted (automount off)");
  expect(value.find("interop") && !value.find("interop")->is_true(), "Windows interop disabled");
  expect(value.find("systemd") && value.find("systemd")->is_true(), "systemd running");
  expect(value.find("wslg") && value.find("wslg")->is_true(), "WSLg display available");
  for (int i = 0; i < seconds; ++i) {
    Sleep(1000);
    if (!agent.running()) {
      std::puts("agent stopped unexpectedly");
      return 1;
    }
  }
  const std::string ping = agent.request(R"({"op":"ping"})");
  std::printf("ping after %d s: %s\n", seconds, ping.c_str());
  agent.shutdown();
  std::printf("%s\n", failures ? "CHECK FAILED" : "CHECK PASSED");
  return failures ? 1 : 0;
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
  try {
    if (argc < 2) return usage();
    const std::wstring command = argv[1];
    if (command == L"status") {
      std::printf("wsl.exe: %s\nOrangeSpace distribution: %s\n", wsl::wsl_executable().empty() ? "missing" : "present",
                  wsl::distribution_registered() ? "registered" : "not registered");
      return 0;
    }
    if (command == L"import" && argc == 4) {
      wsl::import_distribution(argv[2], argv[3]);
      std::puts("imported");
      return 0;
    }
    if (command == L"check") return check(argc >= 3 ? _wtoi(argv[2]) : 0);
    if (command == L"terminate") {
      wsl::terminate_distribution();
      std::puts("terminated");
      return 0;
    }
    if (command == L"unregister" && argc == 3 && std::wstring(argv[2]) == L"--delete-all-data") {
      wsl::unregister_distribution();
      std::puts("unregistered");
      return 0;
    }
    return usage();
  } catch (const std::exception& e) {
    std::fprintf(stderr, "error: %s\n", e.what());
    return 1;
  }
}
