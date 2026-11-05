#pragma once
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#include <functional>
#endif

namespace orangespace::wfp_prototype {
enum class Mode { Offline, ProxyOnly };
enum class Layer { ConnectV4, ConnectV6, ReceiveV4, ReceiveV6 };
enum class RuleKind { All, NonTcp, WrongAddress, WrongPort };
struct Rule {
  Layer layer; RuleKind kind; std::uint16_t port = 0;
  bool operator==(const Rule&) const = default;
};
inline std::vector<Rule> policyRules(Mode mode, std::uint16_t port) {
  if ((mode != Mode::Offline && mode != Mode::ProxyOnly) || (mode == Mode::Offline && port))
    throw std::invalid_argument("policy-mode-port");
  std::vector<Rule> r;
  if (mode == Mode::ProxyOnly) {
    if (!port) throw std::invalid_argument("proxy-port");
    r = {{Layer::ConnectV4, RuleKind::NonTcp},
         {Layer::ConnectV4, RuleKind::WrongAddress},
         {Layer::ConnectV4, RuleKind::WrongPort, port}};
  } else r = {{Layer::ConnectV4, RuleKind::All}};
  r.push_back({Layer::ConnectV6, RuleKind::All});
  r.push_back({Layer::ReceiveV4, RuleKind::All});
  r.push_back({Layer::ReceiveV6, RuleKind::All});
  return r;
}
inline bool ruleMatches(Rule r, unsigned protocol, std::uint32_t address, unsigned port) {
  switch (r.kind) {
    case RuleKind::All: return true;
    case RuleKind::NonTcp: return protocol != 6;
    case RuleKind::WrongAddress: return protocol == 6 && address != 0x7f000001;
    case RuleKind::WrongPort: return protocol == 6 && port != r.port;
  }
  return true;
}
#ifdef _WIN32
enum class IdentityScope { ExecutablePath, ExactAppContainerSid };
struct VerifiedFilter {
  std::uint64_t filterId;
  Rule rule;
  IdentityScope identityScope = IdentityScope::ExecutablePath;
  // All native conditions, AppId bytes, action, flags, layer and keys have
  // been compared with the expected rule before this receipt is returned.
};
class PackageNetworkPolicy;
class NetworkPolicy final {
public:
  NetworkPolicy();
  ~NetworkPolicy(); // Close handles only; NEVER remove persistent policy.
  NetworkPolicy(const NetworkPolicy&) = delete;
  NetworkPolicy& operator=(const NetworkPolicy&) = delete;
  void installOffline(const std::wstring& exactProtectedExecutable);
  void switchToProxyOnly(std::uint16_t port);
  void restoreOffline();
  std::vector<VerifiedFilter> verifyExactPolicy(Mode expected, std::uint16_t port = 0);
  // Callback must not re-enter either policy. Runs under both locks and one BFE transaction.
  void withPairedSnapshot(PackageNetworkPolicy& package, Mode expected, std::uint16_t port,
    const std::function<void(HANDLE,const std::vector<VerifiedFilter>&)>& callback);
  // Caller must have retained and observed exit of the EXACT complete CEF tree.
  // Separate explicit operation, not a destructor/error path.
  void cleanupAfterExactTreeExit();
private:
  friend class PackageNetworkPolicy;
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
// Additional SID-wide deny gate, never a replacement for the legacy path gate.
// Trusted native caller must pass the actual OS-created root profile SID.
// Does not configure loopback exemptions or grant network capabilities.
class PackageNetworkPolicy final {
public:
  PackageNetworkPolicy();
  ~PackageNetworkPolicy(); // Handle close only; persistent deny is retained.
  PackageNetworkPolicy(const PackageNetworkPolicy&) = delete;
  PackageNetworkPolicy& operator=(const PackageNetworkPolicy&) = delete;
  void installOffline(PSID exactAppContainerSid);
  void switchToProxyOnly(std::uint16_t port);
  void restoreOffline();
  std::vector<VerifiedFilter> verifyExactPolicy(Mode expected, std::uint16_t port = 0);
  // Only after retained exact-tree handles prove every child exited, and after
  // the caller revoked/read back its owned loopback exemption.
  void cleanupAfterExactTreeExit();
private:
  friend class NetworkPolicy;
  std::unique_ptr<NetworkPolicy::Impl> impl_;
};
#endif
}
