#pragma once
#include "orangespace/node_session.hpp"
#include <memory>
#include <functional>

namespace orangespace::platform_session {
// No implicit string conversion, copying or diagnostic representation. Caller
// owns any explicitly copied bytes; this owner wipes its storage on destruction.
class SerializedSecret {
 public:
  explicit SerializedSecret(std::string_view value = {}) : bytes_(value.begin(), value.end()) {}
  SerializedSecret(const SerializedSecret&) = delete;
  SerializedSecret& operator=(const SerializedSecret&) = delete;
  SerializedSecret(SerializedSecret&& other) noexcept { bytes_.swap(other.bytes_); }
  SerializedSecret& operator=(SerializedSecret&& other) noexcept {
    if (this != &other) { clear(); bytes_.swap(other.bytes_); } return *this;
  }
  ~SerializedSecret() { clear(); }
  std::string_view view() const noexcept { return {bytes_.data(), bytes_.size()}; }
  void clear() noexcept { node_session::detail::wipe(bytes_.data(), bytes_.size()); bytes_.clear(); }
 private:
  std::vector<char> bytes_;
};
class HttpStatusError final : public std::runtime_error {
 public:
  explicit HttpStatusError(unsigned status) : std::runtime_error("platform HTTPS response rejected"), status_(status) {}
  unsigned status_code() const noexcept { return status_; }
 private: unsigned status_;
};
struct Bootstrap {
  std::string api_origin, host; std::uint16_t port{443};
  std::shared_ptr<const std::string> ca_pem{};
};
struct CentralIdentity {
  std::string central_user_id, central_session_id, username, role;
  std::int64_t user_epoch{}, expires_at{};
};
struct NodeRef {
  std::string node_id, alias, display_name, api_origin, tls_server_name, key_fingerprint;
  std::string grant_id, mapping_id, remote_legacy_user_id;
  std::vector<std::string> scopes;
  std::int64_t node_epoch{}, config_revision{}, grant_epoch{}, mapping_epoch{};
};
struct ExchangeTicket {
  std::string exchange_id, node_id;
  std::int64_t expires_at{};
  SerializedSecret exchange_token;
  // Node-side exchange endpoint consumes this credential once. Not a node
  // access token/transport proof; Service must perform its own exchange.
  SerializedSecret take_token() { return std::move(exchange_token); }
};
namespace detail {
Bootstrap validate_bootstrap(std::string_view input, const node_session::detail::ProtectedConfigReader& reader = {});
struct TestAccess;
}
class PlatformConfig {
 public:
  static PlatformConfig load(const std::wstring& administrator_protected_path);
  const std::string& api_origin() const noexcept { return bootstrap_.api_origin; }
 private:
  explicit PlatformConfig(Bootstrap bootstrap) : bootstrap_(std::move(bootstrap)) {}
  Bootstrap bootstrap_;
  friend class Session;
  friend struct detail::TestAccess;
};
// Explicit injectable request seam. Production uses the existing strict
// WinHTTP implementation; injection does not bypass PlatformConfig protection.
struct Response { unsigned status{}; SerializedSecret body; };
class Transport {
 public:
  virtual ~Transport() = default;
  virtual Response request(const Bootstrap&, std::string_view method, std::string_view path,
      std::string_view body, std::string_view bearer) = 0;
};
class Session {
 public:
  static Session login(const PlatformConfig&, std::string_view username, std::string_view password);
  static Session restore(const PlatformConfig&, std::string_view serialized_secret);
  // Caller-owned Transport and any clock captures must outlive this Session.
  // Single-threaded: serialize logout/revalidate/issue with UI work.
  static Session login(const PlatformConfig&, std::string_view, std::string_view, Transport&, std::function<std::int64_t()> clock);
  static Session restore(const PlatformConfig&, std::string_view, Transport&, std::function<std::int64_t()> clock);
  Session(const Session&) = delete;
  Session& operator=(const Session&) = delete;
  Session(Session&&) noexcept = default;
  Session& operator=(Session&&) = delete;
  const CentralIdentity& identity() const noexcept { return identity_; }
  void revalidate();
  // Serialization only: no central DPAPI persistence is implemented here.
  // Parent must use a separate central namespace/entropy/file, never old blobs.
  SerializedSecret export_envelope() const;
  std::vector<NodeRef> nodes(); // All pages or an error, never a partial success.
  ExchangeTicket issue(std::string_view canonical_node_id);
  void logout(); // Remote 202 = revocation accepted, not forwarding stopped.
 private:
  Session(Bootstrap, CentralIdentity, SerializedSecret, Transport&, std::function<std::int64_t()>);
  Response request(std::string_view method, std::string_view path, std::string_view body, unsigned expected);
  void live() const;
  Bootstrap bootstrap_;
  CentralIdentity identity_;
  SerializedSecret token_;
  Transport* transport_;
  std::function<std::int64_t()> clock_;
};
} // namespace orangespace::platform_session
