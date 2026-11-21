#pragma once
// Windows side of the OrangeSpace WSL distribution (Windows only).
//
// The client owns the distribution's lifetime: it imports it once, starts it
// from the user's interactive session (WSLg attaches only to the session that
// first boots WSL), keeps one wsl.exe agent child alive for as long as
// sandboxes may run (WSL stops an idle distribution), and shuts it down.
#include "orangespace/wsl_channel.hpp"

#include <windows.h>

#include <condition_variable>
#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <string_view>
#include <thread>

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
//
// Thread-safe: requests from different threads run concurrently (the agent
// answers each on its own worker), so one sandbox's slow desktop start never
// holds up another sandbox's lease renewal. A reader thread hands every reply
// to the request waiting for its number; a reply nobody waits for any more
// (timed out) is dropped.
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
  void read_marker(DWORD deadline_tick);
  void read_replies() noexcept;

  HANDLE process_{};
  HANDLE to_agent_{};
  HANDLE from_agent_{};
  DWORD pid_{};
  ReplyReader reader_;
  std::thread reader_thread_;
  std::mutex write_mutex_;
  std::mutex mutex_;
  std::condition_variable replied_;
  std::uint32_t next_{1};
  std::set<std::uint32_t> waiting_;
  std::map<std::uint32_t, std::string> replies_;
  bool closed_{false};
};

}  // namespace orangespace::wsl
