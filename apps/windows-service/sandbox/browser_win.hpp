#pragma once
// One running sandbox browser, as the Service owns it.
//
// Opening follows the order the architecture requires, and fails closed at
// every step:
//   1. the container window really belongs to the requesting client process
//      (checked by the OS window owner, never by a claim in the request);
//   2. the sandbox's private runtime directory is prepared (its own
//      osbrowser.exe = its own WFP AppId);
//   3. WFP proxy-only rules for that image path are installed and read back;
//   4. BrowserHost starts with the session user's normal token in a
//      kill-on-close Job, the config line (with the proxy credentials) is
//      written by us, and only then
//   5. the command/event pipe ends are duplicated into the client process.
// The client never sees the proxy credentials: it receives the write end of
// stdin (commands) and the read end of stdout (events) after the config line.
//
// Destruction terminates the browser tree and removes its WFP rules.
#include "firewall_win.hpp"
#include "launch_win.hpp"

#include <windows.h>

#include <cstdint>
#include <functional>
#include <string>

namespace orangespace::sandbox {

// The sandbox's authenticated loopback proxy (its helper's HTTP inbound).
struct LocalProxy {
  std::uint16_t port{};
  std::string username, password;
  ~LocalProxy() {
    SecureZeroMemory(username.data(), username.size());
    SecureZeroMemory(password.data(), password.size());
  }
};

// Starts `executable` (the sandbox's own osbrowser.exe) and returns its process,
// Job and pipes. Production: CreateProcessAsUser with the session user's token.
using BrowserLauncher = std::function<BrowserProcess(const std::wstring& executable)>;
BrowserLauncher LaunchAsUser(HANDLE user_token);

struct BrowserOpen {
  std::string sandbox_id;          // canonical lower-case UUID
  HANDLE client_process{};         // PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION
  std::uint64_t container_window{};  // HWND created by the client for this sandbox
  std::wstring shared_runtime;     // verified install runtime directory
  std::wstring sandbox_root;       // Service-owned parent of the per-sandbox runtimes
  std::wstring profile_dir;        // existing per-user, per-sandbox profile directory
  std::string start_url = "about:blank";
  BrowserLauncher launch;
};

// Handle values valid inside the client process.
struct ClientPipes {
  std::uint64_t commands{};  // write end of BrowserHost stdin
  std::uint64_t events{};    // read end of BrowserHost stdout
};

class SandboxBrowser {
 public:
  SandboxBrowser(SandboxFirewall& firewall, const BrowserOpen& request, const LocalProxy& proxy);
  ~SandboxBrowser();
  SandboxBrowser(const SandboxBrowser&) = delete;
  SandboxBrowser& operator=(const SandboxBrowser&) = delete;

  const ClientPipes& pipes() const { return pipes_; }
  DWORD pid() const { return process_.pid; }
  const std::wstring& image() const { return image_; }
  bool running() const;
  // Re-reads the rules; false means they were altered and the sandbox must be cut.
  bool verify();
  // Helper gone or lease lost: block everything for this sandbox immediately.
  void cut() noexcept;

 private:
  SandboxFirewall& firewall_;
  std::string sandbox_id_;
  std::wstring image_;
  BrowserProcess process_;
  ClientPipes pipes_;
};

// Throws unless `window` is a live window owned by process `client_pid` in the
// same session as the client.
void RequireClientWindow(std::uint64_t window, DWORD client_pid);

}  // namespace orangespace::sandbox
