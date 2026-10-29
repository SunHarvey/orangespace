#pragma once

#include "orangespace/json.hpp"
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace orangespace::node_session {
namespace detail {
struct NodeEntry { std::string name, node_id, host; std::uint16_t port{443}; };
inline void require(bool condition) {
  if (!condition) throw std::runtime_error("invalid node session data");
}
inline const json::Value::Object& object(const json::Value& value, std::size_t size) {
  const auto* obj = std::get_if<json::Value::Object>(&value.data);
  require(obj && obj->size() == size);
  return *obj;
}
inline const json::Value& field(const json::Value& value, std::string_view key) {
  const auto* f = value.find(key);
  require(f != nullptr);
  return *f;
}
inline const std::string& text(const json::Value& value) {
  const auto* s = std::get_if<std::string>(&value.data);
  require(s != nullptr);
  return *s;
}
inline bool uuid(std::string_view value) {
  if (value.size() != 36) return false;
  bool nonzero = false;
  for (std::size_t i = 0; i < value.size(); ++i) {
    if (i == 8 || i == 13 || i == 18 || i == 23) { if (value[i] != '-') return false; }
    else {
      if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f'))) return false;
      nonzero = nonzero || value[i] != '0';
    }
  }
  return nonzero;
}
inline std::vector<NodeEntry> parse_catalog(std::string_view input) {
  require(input.size() <= 65536);
  const auto root = json::parse(input);
  object(root, 2);
  const auto* version = std::get_if<double>(&field(root, "schema").data);
  require(version && *version == 1);
  const auto* nodes = std::get_if<json::Value::Array>(&field(root, "nodes").data);
  require(nodes && !nodes->empty() && nodes->size() <= 64);
  std::vector<NodeEntry> result;
  for (const auto& value : *nodes) {
    object(value, 3);
    NodeEntry node;
    node.name = text(field(value, "name"));
    node.node_id = text(field(value, "node_id"));
    require(uuid(node.node_id));
    const auto origin = text(field(value, "api_origin"));
    require(origin.starts_with("https://"));
    node.host = origin.substr(8);
    const auto colon = node.host.find(':');
    if (colon != std::string::npos) {
      const auto port = node.host.substr(colon + 1);
      require(!port.empty());
      unsigned number = 0;
      for (char c : port) { require(c >= '0' && c <= '9'); number = number * 10 + static_cast<unsigned>(c - '0'); require(number <= 65535); }
      require(number != 0);
      node.port = static_cast<std::uint16_t>(number);
      node.host.resize(colon);
    }
    require(!node.name.empty() && node.name.size() <= 64);
    for (char c : node.name) require((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_');
    require(!node.host.empty() && node.host.size() <= 253);
    std::size_t label = 0;
    char previous = '.';
    for (char c : node.host) {
      if (c == '.') { require(label > 0 && previous != '-'); label = 0; }
      else {
        require((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '-' && label > 0));
        require(++label <= 63);
      }
      previous = c;
    }
    require(label > 0 && previous != '-');
    if (colon != std::string::npos) require(origin.substr(8 + colon + 1) == std::to_string(node.port));
    for (const auto& other : result) require(node.name != other.name && node.node_id != other.node_id && (node.host != other.host || node.port != other.port));
    result.push_back(std::move(node));
  }
  return result;
}
inline bool safe_utf8(std::string_view s, bool printable = false) {
  for (std::size_t i = 0; i < s.size();) {
    const auto first = static_cast<unsigned char>(s[i++]);
    std::uint32_t cp = first;
    unsigned extra = 0;
    if (first >= 0xc2 && first <= 0xdf) { cp = first & 31; extra = 1; }
    else if (first >= 0xe0 && first <= 0xef) { cp = first & 15; extra = 2; }
    else if (first >= 0xf0 && first <= 0xf4) { cp = first & 7; extra = 3; }
    else if (first >= 0x80) return false;
    if (s.size() - i < extra) return false;
    for (unsigned j = 0; j < extra; ++j) {
      const auto c = static_cast<unsigned char>(s[i++]);
      if ((c & 0xc0) != 0x80) return false;
      cp = (cp << 6) | (c & 63);
    }
    if ((extra == 1 && cp < 0x80) || (extra == 2 && cp < 0x800) || (extra == 3 && cp < 0x10000) || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return false;
    if (printable && (cp < 32 || (cp >= 127 && cp <= 159))) return false;
  }
  return true;
}
inline void wipe(void* data, std::size_t size) noexcept {
  auto* p = static_cast<volatile unsigned char*>(data);
  while (size--) *p++ = 0;
}
inline void wipe_json(json::Value& value) noexcept {
  if (auto* s = std::get_if<std::string>(&value.data)) wipe(s->data(), s->size());
  if (auto* a = std::get_if<json::Value::Array>(&value.data)) for (auto& v : *a) wipe_json(v);
  if (auto* o = std::get_if<json::Value::Object>(&value.data)) for (auto& [key, v] : *o) { (void)key; wipe_json(v); }
}
struct JsonGuard {
  json::Value value;
  explicit JsonGuard(std::string_view input) : value(json::parse(input)) {}
  ~JsonGuard() { wipe_json(value); }
};
struct LoginReply {
  std::string token;
  std::int64_t expires_at{};
  LoginReply(const std::string& value, std::int64_t expires) : token(value), expires_at(expires) {}
  LoginReply(const LoginReply&) = delete;
  LoginReply& operator=(const LoginReply&) = delete;
  ~LoginReply() { wipe(token.data(), token.size()); }
};
struct Identity { std::string user_id, username, node_id; };
inline LoginReply validate_login(const NodeEntry& node, unsigned status, std::string_view header, std::string_view body, std::int64_t now) {
  require(status == 200 && header == node.node_id && body.size() <= 16384);
  require(safe_utf8(body));
  JsonGuard document(body);
  const auto& root = document.value;
  object(root, 4);
  require(text(field(root, "node_id")) == node.node_id);
  require(text(field(root, "token_type")) == "bearer");
  const auto& token = text(field(root, "access_token"));
  require(token.size() == 43);
  for (char c : token) require((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-');
  const auto* expires = std::get_if<double>(&field(root, "expires_at").data);
  require(expires && *expires > static_cast<double>(now) && *expires <= 9007199254740991.0 && std::floor(*expires) == *expires);
  return {token, static_cast<std::int64_t>(*expires)};
}
inline Identity validate_me(const NodeEntry& node, unsigned status, std::string_view header, std::string_view body) {
  require(status == 200 && header == node.node_id && body.size() <= 16384);
  require(safe_utf8(body));
  JsonGuard document(body);
  const auto& root = document.value;
  object(root, 3);
  Identity result{text(field(root, "user_id")), text(field(root, "username")), text(field(root, "node_id"))};
  require(uuid(result.user_id) && result.node_id == node.node_id);
  require(!result.username.empty() && result.username.size() <= 256 && safe_utf8(result.username, true));
  return result;
}
enum class AceKind { allow, deny, unsupported };
struct Ace { AceKind kind; bool privileged; std::uint32_t mask; };
// Windows FILE_* and standard/generic write rights. Unknown ACE types fail closed;
// deny ACEs cannot excuse an ordinary-user allow because group membership varies.
inline bool secure_acl(bool privileged_owner, bool protected_dacl, bool dacl_present,
                       const std::vector<Ace>& entries, bool ancestor = false) {
  if (!privileged_owner || !dacl_present || (!ancestor && !protected_dacl)) return false;
  const std::uint32_t forbidden = 0x10000u | 0x40000u | 0x80000u | 0x40000000u |
      0x10000000u | 0x02000000u | 16u | 256u | 64u | (ancestor ? 0u : 6u);
  for (const auto& ace : entries) {
    if (ace.kind == AceKind::unsupported) return false;
    if (ace.kind == AceKind::allow && !ace.privileged && (ace.mask & forbidden)) return false;
  }
  return true;
}
inline bool explicit_local_path(std::wstring_view path) {
  if (path.size() < 4 || path.size() > 240 || !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) || path[1] != L':' || path[2] != L'\\') return false;
  std::size_t start = 3;
  for (std::size_t i = 3; i <= path.size(); ++i) {
    if (i < path.size() && path[i] != L'\\') {
      if (path[i] < 32 || path[i] == L'/' || path[i] == L':' || path[i] == L'?' || path[i] == L'*' || path[i] == L'"' || path[i] == L'<' || path[i] == L'>' || path[i] == L'|') return false;
      continue;
    }
    const auto part = path.substr(start, i - start);
    if (part.empty() || part.back() == L'.' || part.back() == L' ') return false;
    std::wstring stem(part.substr(0, part.find(L'.')));
    for (auto& c : stem) if (c >= L'a' && c <= L'z') c = static_cast<wchar_t>(c - L'a' + L'A');
    if (stem == L"CON" || stem == L"PRN" || stem == L"AUX" || stem == L"NUL" ||
        (stem.size() == 4 && (stem.starts_with(L"COM") || stem.starts_with(L"LPT")) && stem[3] >= L'0' && stem[3] <= L'9')) return false;
    start = i + 1;
  }
  return true;
}
} // namespace detail

// Only the Windows ACL-checked loader can construct a transport-capable catalog.
// detail::parse_catalog is validation only: its output cannot authorize requests.
class TrustedCatalog {
 public:
  static TrustedCatalog load(const std::wstring& explicit_path);
  std::vector<std::string> names() const;
 private:
  explicit TrustedCatalog(std::vector<detail::NodeEntry> nodes) : nodes_(std::move(nodes)) {}
  std::vector<detail::NodeEntry> nodes_;
  friend class NodeSession;
};

// Scoped, noncopyable session. No public token accessor, serialization, global
// current-node, credential persistence, or browser launch path.
class NodeSession {
 public:
  static NodeSession login(const TrustedCatalog& catalog, std::string_view name,
                           std::string_view username, std::string_view password);
  NodeSession(const NodeSession&) = delete;
  NodeSession& operator=(const NodeSession&) = delete;
  ~NodeSession() { detail::wipe(token_.data(), token_.size()); }
  const detail::Identity& identity() const noexcept { return identity_; }
  std::int64_t expires_at() const noexcept { return expires_at_; }
 private:
  NodeSession(detail::NodeEntry node, detail::Identity identity, const detail::LoginReply& reply)
      : node_(std::move(node)), identity_(std::move(identity)),
        token_(reply.token.begin(), reply.token.end()), expires_at_(reply.expires_at) {}
  detail::NodeEntry node_;
  detail::Identity identity_;
  std::vector<char> token_;
  std::int64_t expires_at_{};
};
} // namespace orangespace::node_session
