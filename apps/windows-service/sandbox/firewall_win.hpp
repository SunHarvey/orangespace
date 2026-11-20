#pragma once
// Per-sandbox WFP containment for a BrowserHost AppContainer.
//
// For one package SID the only permitted traffic is an outbound TCP connection
// to 127.0.0.1:<proxy_port> (that sandbox's own helper). Everything else -
// other loopback ports (including other sandboxes' helpers), non-TCP, IPv6,
// any remote address, and every inbound accept - is blocked.
//
// Rules live in a dynamic WFP session owned by the process that created the
// SandboxFirewall: if that process dies the rules disappear, but so does every
// BrowserHost (they are in kill-on-close Jobs owned by the same process), and an
// AppContainer without network capabilities has no internet access by default.
#include <windows.h>

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace orangespace::sandbox {

// Who the rules apply to. Chromium's browser process cannot itself run inside an
// AppContainer (its sandbox broker fails there), so production sandboxes are
// identified by their own BrowserHost executable path (WFP AppId): every
// sandbox runs osbrowser.exe from a private per-sandbox directory, and all
// Chromium child processes inherit that image path. Package SIDs remain
// supported for AppContainer workloads and tests.
struct FirewallIdentity {
  enum class Kind { package_sid, app_id } kind{};
  std::vector<BYTE> bytes;  // SID bytes, or the WFP AppId blob for the image path
  static FirewallIdentity Package(void* sid);
  static FirewallIdentity Executable(const std::wstring& image_path);
  bool operator==(const FirewallIdentity&) const = default;
};

class SandboxFirewall {
 public:
  SandboxFirewall();  // opens a dynamic WFP session and registers sublayer
  ~SandboxFirewall();
  SandboxFirewall(const SandboxFirewall&) = delete;
  SandboxFirewall& operator=(const SandboxFirewall&) = delete;

  // Installs (or replaces) the rules of one sandbox and reads them back.
  // Throws if the installed state is not exactly what was requested.
  void Apply(const std::string& sandbox_id, const FirewallIdentity& who, std::uint16_t proxy_port);
  // Offline mode: block everything for the identity (no proxy port).
  void Block(const std::string& sandbox_id, const FirewallIdentity& who);
  void Apply(const std::string& sandbox_id, void* package_sid, std::uint16_t proxy_port) {
    Apply(sandbox_id, FirewallIdentity::Package(package_sid), proxy_port);
  }
  void Block(const std::string& sandbox_id, void* package_sid) { Block(sandbox_id, FirewallIdentity::Package(package_sid)); }
  // Removes this sandbox's rules. Call only after its BrowserHost tree exited.
  void Remove(const std::string& sandbox_id);
  // Re-reads the rules of one sandbox from the engine and compares them with
  // what was installed. Used before launch and periodically while running.
  bool Verify(const std::string& sandbox_id);

 private:
  struct Installed {
    FirewallIdentity who;
    std::uint16_t port{};
    std::vector<std::uint64_t> filter_ids;
  };
  void Install(const std::string& sandbox_id, const FirewallIdentity& who, std::uint16_t port);
  void RemoveLocked(const std::string& sandbox_id);
  bool VerifyLocked(const Installed& installed);

  HANDLE engine_{};
  std::mutex mutex_;
  std::map<std::string, Installed> sandboxes_;
};

// Loopback exemption is a machine-wide list; we add/remove only our own SIDs.
void AddLoopbackExemption(void* package_sid);
void RemoveLoopbackExemption(void* package_sid);

}  // namespace orangespace::sandbox
