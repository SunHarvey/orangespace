#pragma once
// Windows side of the OrangeSpace WSL distribution (Windows only).
//
// The client owns the distribution's lifetime: it imports it once, starts it
// from the user's interactive session (WSLg attaches only to the session that
// first boots WSL), keeps one wsl.exe agent child alive for as long as
// sandboxes may run (WSL stops an idle distribution), and shuts it down.
#include "orangespace/wsl_channel.hpp"

#include <windows.h>

#include <cstdint>
#include <string>
#include <string_view>

namespace orangespace::wsl {

inline constexpr wchar_t kDistribution[] = L"OrangeSpace";

class RuntimeError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// %SystemRoot%\System32\wsl.exe if present, else empty.
std::wstring wsl_executable();
// Registered for the current user (HKCU\...\Lxss\{guid}\DistributionName).
bool distribution_registered();
// wsl --import OrangeSpace <install_dir> <rootfs> --version 2. Throws on failure.
void import_distribution(const std::wstring& rootfs_tar_gz, const std::wstring& install_dir);
// wsl --terminate OrangeSpace (stops every process in it, sandboxes included).
void terminate_distribution();
// wsl --unregister OrangeSpace: deletes the distribution and ALL its data.
void unregister_distribution();

// The long-lived agent child: `wsl.exe -d OrangeSpace -u root -- python3
// /opt/orangespace/wsl/agent.py`, with private stdin/stdout pipes.
class Agent {
 public:
  explicit Agent(DWORD start_timeout_ms = 120000);
  ~Agent();
  Agent(const Agent&) = delete;
  Agent& operator=(const Agent&) = delete;

  // Sends one JSON request and returns the agent's JSON reply text.
  std::string request(std::string_view json, DWORD timeout_ms = 30000);
  // Asks the agent to stop, then closes the channel and waits for wsl.exe.
  void shutdown() noexcept;
  bool running() const noexcept;
  DWORD pid() const noexcept { return pid_; }

 private:
  void read_until(DWORD deadline_tick, bool want_reply, std::uint32_t number, std::string& out);

  HANDLE process_{};
  HANDLE to_agent_{};
  HANDLE from_agent_{};
  DWORD pid_{};
  std::uint32_t next_{1};
  ReplyReader reader_;
};

}  // namespace orangespace::wsl
