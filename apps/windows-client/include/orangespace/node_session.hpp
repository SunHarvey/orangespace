#pragma once

#include "orangespace/json.hpp"
#include "../../../../crates/orangespace-https/include/orangespace_https.h"
#include <array>
#include <functional>
#include <memory>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

namespace orangespace::node_session {
// Stable metadata for denial tests/UI decisions; never retain response bodies,
// headers, usernames, passwords, URLs or tokens in an exception.
class HttpStatusError final : public std::runtime_error {
 public:
  explicit HttpStatusError(unsigned status)
      : std::runtime_error("node HTTPS response rejected"), status_(status) {}
  unsigned status_code() const noexcept { return status_; }
 private:
  unsigned status_;
};
// Only the authenticated response to the exact cleanup POST can prove absence.
class ExchangeCleanupAbsent final : public std::runtime_error {
 public:
  ExchangeCleanupAbsent() : std::runtime_error("node exchange cleanup absent") {}
};
namespace detail {
using ProtectedConfigReader = std::function<std::string(const std::wstring&)>;
inline std::shared_ptr<const std::string> load_private_ca(std::string_view, const ProtectedConfigReader&);
inline void exact_wire_integers(std::string_view);
struct NodeEntry {
  std::string name, node_id, host;
  std::uint16_t port{443};
  std::string api_prefix{}; // Empty or exactly /nodes/<this canonical node_id>.
  std::shared_ptr<const std::string> ca_pem{}; // Explicit schema 2 only; immutable snapshot.
};
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
inline std::vector<NodeEntry> parse_catalog(std::string_view input, const ProtectedConfigReader& reader = {}) {
  require(input.size() <= 65536);
  const auto root = json::parse(input);
  object(root, 2);
  const auto* version = std::get_if<double>(&field(root, "schema").data);
  require(version && (*version == 1 || *version == 2));
  if (*version == 2) exact_wire_integers(input);
  const auto* nodes = std::get_if<json::Value::Array>(&field(root, "nodes").data);
  require(nodes && !nodes->empty() && nodes->size() <= 64);
  std::vector<NodeEntry> result;
  for (const auto& value : *nodes) {
    const auto* ca = value.find("ca_file");
    object(value, *version == 2 && ca ? 4 : 3);
    NodeEntry node;
    if (*version == 2 && ca) node.ca_pem = load_private_ca(text(*ca), reader);
    node.name = text(field(value, "name"));
    node.node_id = text(field(value, "node_id"));
    require(uuid(node.node_id));
    const auto origin = text(field(value, "api_origin"));
    require(origin.starts_with("https://"));
    node.host = origin.substr(8);
    const auto slash = node.host.find('/');
    if (slash != std::string::npos) {
      node.api_prefix = node.host.substr(slash);
      require(node.api_prefix == "/nodes/" + node.node_id);
      node.host.resize(slash);
    }
    const auto authority = node.host;
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
    if (colon != std::string::npos) require(authority.substr(colon + 1) == std::to_string(node.port));
    for (const auto& other : result) require(node.name != other.name && node.node_id != other.node_id &&
        (node.host != other.host || node.port != other.port || node.api_prefix != other.api_prefix));
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
  json::wipe(value);
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
inline void require_http_response(const NodeEntry& node, unsigned status,
    std::string_view header, std::size_t body_size, unsigned expected = 200) {
  // An error from a different node is a protocol/trust failure, not evidence of
  // a password or session denial from the pinned node.
  require(header == node.node_id && body_size <= 16384 && status >= 100 && status <= 599);
  if (status != expected) throw HttpStatusError(status);
}
inline LoginReply validate_login(const NodeEntry& node, unsigned status, std::string_view header, std::string_view body, std::int64_t now) {
  require_http_response(node, status, header, body.size());
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
  require_http_response(node, status, header, body.size());
  require(safe_utf8(body));
  JsonGuard document(body);
  const auto& root = document.value;
  object(root, 3);
  Identity result{text(field(root, "user_id")), text(field(root, "username")), text(field(root, "node_id"))};
  require(uuid(result.user_id) && result.node_id == node.node_id);
  require(!result.username.empty() && result.username.size() <= 256 && safe_utf8(result.username, true));
  return result;
}
inline std::int64_t integer(const json::Value& value, std::int64_t minimum = 1) {
  const auto* n = std::get_if<double>(&value.data);
  require(n && *n >= static_cast<double>(minimum) && *n <= 9007199254740991.0 && std::floor(*n) == *n);
  return static_cast<std::int64_t>(*n);
}
inline std::int64_t validate_session(const NodeEntry& node, const Identity& identity,
    unsigned status, std::string_view header, std::string_view body, std::int64_t now) {
  require_http_response(node, status, header, body.size());
  require(safe_utf8(body));
  JsonGuard doc(body);
  object(doc.value, 4);
  require(text(field(doc.value, "user_id")) == identity.user_id &&
          text(field(doc.value, "username")) == identity.username &&
          text(field(doc.value, "node_id")) == node.node_id);
  const auto expires = integer(field(doc.value, "expires_at"));
  require(expires > now);
  return expires;
}
inline std::string api_origin(const NodeEntry& node) {
  return "https://" + node.host + ":" + std::to_string(node.port) + node.api_prefix;
}
inline std::string api_path(const NodeEntry& node, std::string_view fixed_route) {
  require(fixed_route.starts_with('/') && !fixed_route.starts_with("//"));
  require(node.api_prefix.empty() || node.api_prefix == "/nodes/" + node.node_id);
  return node.api_prefix + std::string(fixed_route);
}
inline void validate_token(std::string_view token) {
  require(token.size() == 43);
  for (char c : token) require((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
      (c >= '0' && c <= '9') || c == '_' || c == '-');
}
inline LoginReply validate_envelope(const NodeEntry& node, std::string_view input, std::int64_t now) {
  require(input.size() <= 16384 && safe_utf8(input));
  JsonGuard doc(input);
  object(doc.value, 5);
  require(integer(field(doc.value, "schema")) == 1);
  require(text(field(doc.value, "node_id")) == node.node_id);
  require(text(field(doc.value, "api_origin")) == api_origin(node));
  const auto& token = text(field(doc.value, "access_token"));
  validate_token(token);
  const auto expires = integer(field(doc.value, "expires_at"));
  require(expires > now);
  return {token, expires};
}
// The shared DOM stores doubles. Check numeric wire tokens before that conversion
// so 2.0, exponent forms, and rounded fractional integers cannot masquerade as
// integer protocol fields. Strings (including escaped secret text) are skipped.
inline void exact_wire_integers(std::string_view input) {
  for(std::size_t i=0;i<input.size();) {
    char c=input[i++];
    if(c=='"') {
      while(i<input.size()) {
        c=input[i++];
        if(c=='\\') {require(i<input.size());++i;}
        else if(c=='"') break;
      }
    } else if(c=='-' || c=='.') require(false);
    else if(c>='0' && c<='9') {
      std::uint64_t n=static_cast<unsigned>(c-'0');
      while(i<input.size() && input[i]>='0' && input[i]<='9') {
        const auto digit=static_cast<unsigned>(input[i++]-'0');
        require(n<=(9007199254740991ULL-digit)/10);
        n=n*10+digit;
      }
      require(i==input.size() || input[i]==',' || input[i]=='}' || input[i]==']' ||
        input[i]==' ' || input[i]=='\t' || input[i]=='\r' || input[i]=='\n');
    }
  }
}
inline void validate_tunnel_request(std::string_view input) {
  require(input.size() <= 1024 && safe_utf8(input));
  exact_wire_integers(input);
  JsonGuard doc(input);
  object(doc.value, 3);
  require(uuid(text(field(doc.value, "sandbox_id"))) && uuid(text(field(doc.value, "tunnel_id"))));
  (void)integer(field(doc.value, "generation"));
}
// Shared OS epoch, deliberately not steady_clock's implementation-defined epoch.
inline constexpr std::int64_t max_exact_integer = 9007199254740991LL;
#ifdef _WIN32
inline constexpr std::string_view lease_clock = "windows-gettickcount64-ms-v1";
#else
inline constexpr std::string_view lease_clock = "linux-clock-monotonic-ms-v1";
#endif
inline std::int64_t monotonic_ms() {
#ifdef _WIN32
  const auto ms = GetTickCount64();
  require(ms <= static_cast<ULONGLONG>(max_exact_integer));
  return static_cast<std::int64_t>(ms);
#else
  timespec ts{};
  require(clock_gettime(CLOCK_MONOTONIC, &ts) == 0 && ts.tv_sec >= 0 && ts.tv_nsec >= 0 && ts.tv_nsec < 1000000000);
  require(ts.tv_sec <= (max_exact_integer - ts.tv_nsec / 1000000) / 1000);
  return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}
struct LeaseBudget {
  std::string clock;
  std::int64_t request_started_ms{}, remaining_ttl_ms{}, deadline_ms{};
  void validate(std::int64_t now) const {
    require(clock == lease_clock && now >= 0 && now <= max_exact_integer &&
      request_started_ms >= 0 && request_started_ms <= now &&
      remaining_ttl_ms > 0 && remaining_ttl_ms <= 30000 &&
      request_started_ms <= max_exact_integer - remaining_ttl_ms &&
      deadline_ms == request_started_ms + remaining_ttl_ms && deadline_ms > now);
  }
};
struct RenewResult { std::int64_t expires_at; LeaseBudget budget; };
inline LeaseBudget authenticated_budget(const json::Value& root, std::int64_t started, std::int64_t received) {
  require(integer(field(root, "lease_schema")) == 2);
  const auto ttl = integer(field(root, "remaining_ttl_ms"));
  require(ttl <= 30000 && started >= 0 && started <= max_exact_integer - ttl);
  LeaseBudget result{std::string(lease_clock), started, ttl, started + ttl};
  result.validate(received);
  return result;
}
inline void lease_expiry(const json::Value& root, std::int64_t now, std::int64_t session_expiry) {
  const auto expires = integer(field(root, "expires_at"));
  // Lease epochs belong to the server; client wall time only vetoes sessions.
  require(session_expiry > now && session_expiry <= max_exact_integer && expires <= session_expiry);
}
inline RenewResult validate_renew(const NodeEntry& node, std::string_view tunnel, unsigned status,
    std::string_view header, std::string_view input, std::int64_t now, std::int64_t session_expiry,
    std::int64_t started, std::int64_t received) {
  require(uuid(tunnel) && status == 200 && header == node.node_id && input.size() <= 16384 && safe_utf8(input));
  exact_wire_integers(input);
  JsonGuard doc(input);
  object(doc.value, 5);
  require(text(field(doc.value, "tunnel_id")) == tunnel && text(field(doc.value, "node_id")) == node.node_id);
  lease_expiry(doc.value, now, session_expiry);
  return {integer(field(doc.value, "expires_at")), authenticated_budget(doc.value, started, received)};
}
inline bool literal_ip(std::string_view s) {
  if (s.find(':') == std::string_view::npos) {
    unsigned parts = 0;
    while (!s.empty()) {
      const auto end = s.find('.');
      const auto part = s.substr(0, end);
      if (part.empty() || part.size() > 3 || (part.size() > 1 && part[0] == '0')) return false;
      unsigned v = 0;
      for (char c : part) { if (c < '0' || c > '9') return false; v = v * 10 + static_cast<unsigned>(c - '0'); }
      if (v > 255) return false;
      ++parts;
      if (end == std::string_view::npos) return parts == 4;
      s.remove_prefix(end + 1);
    }
    return false;
  }
  // Conservative IPv6 grammar: eight hex groups or one compressed gap;
  // dotted tails and scoped addresses are deliberately not accepted.
  const auto gap = s.find("::");
  if (gap != std::string_view::npos && s.find("::", gap + 2) != std::string_view::npos) return false;
  unsigned groups = 0;
  auto side = [&](std::string_view v) {
    if (v.empty()) return true;
    while (true) {
      const auto end = v.find(':'); const auto p = v.substr(0, end);
      if (p.empty() || p.size() > 4) return false;
      for (char c : p) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
      ++groups;
      if (end == std::string_view::npos) return true;
      v.remove_prefix(end + 1);
    }
  };
  if (gap == std::string_view::npos) return side(s) && groups == 8;
  return side(s.substr(0, gap)) && side(s.substr(gap + 2)) && groups < 8;
}
inline LeaseBudget validate_tunnel(const NodeEntry& node, const Identity& identity, std::string_view request,
    unsigned status, std::string_view header, std::string_view input, std::int64_t now,
    std::int64_t session_expiry, std::string_view api_token, std::int64_t started, std::int64_t received) {
  validate_tunnel_request(request);
  require(status == 200 && header == node.node_id && input.size() <= 16384 && safe_utf8(input));
  exact_wire_integers(input);
  JsonGuard doc(input), asked(request);
  const auto& root = doc.value;
  object(root, 17);
  require(text(field(root, "node_id")) == node.node_id && text(field(root, "user_id")) == identity.user_id);
  for (const auto key : {"sandbox_id", "tunnel_id"}) require(text(field(root, key)) == text(field(asked.value, key)));
  require(integer(field(root, "generation")) == integer(field(asked.value, "generation")));
  lease_expiry(root, now, session_expiry);
  require(literal_ip(text(field(root, "endpoint_ip"))));
  require(integer(field(root, "endpoint_port")) <= 65535 && integer(field(root, "probe_port")) <= 65535);
  const auto& name = text(field(root, "tls_server_name"));
  require(!name.empty() && name.size() <= 253);
  std::size_t label = 0; char previous = '.';
  for (char c : name) {
    if (c == '.') { require(label > 0 && previous != '-'); label = 0; }
    else {
      require((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '-' && label > 0));
      require(++label <= 63);
    }
    previous = c;
  }
  require(label > 0 && previous != '-');
  const auto& tuic_id = text(field(root, "tuic_uuid"));
  require(uuid(tuic_id) && tuic_id != identity.user_id && tuic_id != node.node_id && tuic_id != text(field(root, "tunnel_id")));
  require(text(field(root, "probe_host")) == "127.0.0.1");
  const auto& password = text(field(root, "tuic_password"));
  const auto& probe = text(field(root, "probe_request"));
  const auto& proof = text(field(root, "probe_response"));
  validate_token(password); validate_token(probe); validate_token(proof);
  require(password != api_token && probe != api_token && proof != api_token &&
          password != probe && password != proof && probe != proof);
  return authenticated_budget(root, started, received);
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
inline std::shared_ptr<const std::string> load_private_ca(std::string_view path, const ProtectedConfigReader& reader) {
  require(!path.empty() && path.size() <= 960 && safe_utf8(path, true));
  std::wstring wide;
  // Decode JSON UTF-8 explicitly, independent of the process locale.
  for (std::size_t i=0; i<path.size();) {
    auto cp=static_cast<std::uint32_t>(static_cast<unsigned char>(path[i++]));
    unsigned extra=0;
    if(cp>=0xf0) {cp&=7;extra=3;} else if(cp>=0xe0) {cp&=15;extra=2;} else if(cp>=0xc0) {cp&=31;extra=1;}
    while(extra--) cp=(cp<<6)|(static_cast<unsigned char>(path[i++])&63);
    if constexpr(sizeof(wchar_t)==2) {
      if(cp>0xffff) {cp-=0x10000;wide.push_back(static_cast<wchar_t>(0xd800+(cp>>10)));wide.push_back(static_cast<wchar_t>(0xdc00+(cp&1023)));continue;}
    }
    wide.push_back(static_cast<wchar_t>(cp));
  }
  require(explicit_local_path(wide) && static_cast<bool>(reader));
  auto bytes=reader(wide);
  require(!bytes.empty() && bytes.size()<=65536);
  return std::make_shared<const std::string>(std::move(bytes));
}
// Borrowed C ABI only. No body/token copies, diagnostic serialization or retry.
// Rust validates TLS, redirects, unique headers and JSON Content-Type; the
// existing C++ typed parsers still validate identity, errors and lease schema 2.
inline void private_https_request(const NodeEntry& node, std::string_view method,
    std::string_view path, std::string_view body, std::string_view token, bool node_header_required,
    const std::function<void(unsigned, std::string_view, std::string_view)>& receive,
    decltype(&os_https_request_v1) request = os_https_request_v1) {
  if (!node.ca_pem || node.ca_pem->empty() || !request) throw std::runtime_error("app-private HTTPS failed");
  const auto origin="https://"+node.host+":"+std::to_string(node.port);
  const auto full_path=api_path(node,path);
  const auto borrowed=[](std::string_view s) -> OsHttpsBytes {return {reinterpret_cast<const std::uint8_t*>(s.data()),s.size()};};
  const OsHttpsRequest input{borrowed(origin),borrowed(*node.ca_pem),borrowed(method),borrowed(full_path),borrowed(body),borrowed(token)};
  struct Output {
    std::vector<std::uint8_t> bytes;
    std::array<std::uint8_t,64> header{};
    Output() : bytes(OS_HTTPS_MAX_RESPONSE) {}
    ~Output() {wipe(bytes.data(),bytes.size());wipe(header.data(),header.size());}
  } output;
  std::uint32_t status=0,header_size=0;
  const auto size=request(&input,output.bytes.data(),output.bytes.size(),&status,output.header.data(),output.header.size(),&header_size);
  if(size<0 || static_cast<std::size_t>(size)>output.bytes.size() || header_size>output.header.size() ||
      status<100 || status>599 || (node_header_required && size>16384))
    throw std::runtime_error("app-private HTTPS failed");
  const std::string_view header(reinterpret_cast<const char*>(output.header.data()),header_size);
  if(node_header_required && header!=node.node_id) throw std::runtime_error("app-private HTTPS failed");
  receive(status,header,{reinterpret_cast<const char*>(output.bytes.data()),static_cast<std::size_t>(size)});
}
// Narrow shared Windows adapters. Same protected-handle ACL reader and strict
// WinHTTP path, not a second transport. Central protocol has no node header.
std::string read_admin_protected_config(const std::wstring& explicit_path);
void central_https_request(const NodeEntry&, std::string_view method, std::string_view path,
    std::string_view body, std::string_view token,
    const std::function<void(unsigned, std::string_view)>& receive);
} // namespace detail

using LeaseBudget = detail::LeaseBudget;
using RenewResult = detail::RenewResult;
// Final guarded owner. No copying/moving secret-bearing strings (including SSO).
// Guaranteed-prvalue return constructs this owner directly at every call seam.
struct LeaseResult {
  std::string payload;
  LeaseBudget budget;
  std::int64_t expires_at;
  LeaseResult(std::string_view input, LeaseBudget timing, std::int64_t expiry)
      : payload(input), budget(std::move(timing)), expires_at(expiry) {}
  // Delegation completes the wiping owner BEFORE the final clock check can throw.
  LeaseResult(std::string_view input, LeaseBudget timing, std::int64_t expiry, std::int64_t (*clock)())
      : LeaseResult(input, std::move(timing), expiry) { budget.validate(clock()); }
  LeaseResult(const LeaseResult&) = delete;
  LeaseResult& operator=(const LeaseResult&) = delete;
  ~LeaseResult() { detail::wipe(payload.data(), payload.size()); }
};
// Only the Windows ACL-checked loader can construct a transport-capable catalog.
// detail::parse_catalog is validation only: its output cannot authorize requests.
class TrustedCatalog {
 public:
  static TrustedCatalog load(const std::wstring& explicit_path);
  std::vector<std::string> names() const;
  const detail::NodeEntry& federation_node(std::string_view canonical_node_id) const;
  void federation_exchange(std::string_view canonical_node_id, std::string_view body, bool cleanup,
      const std::function<void(std::string_view)>& receive) const;
 private:
  explicit TrustedCatalog(std::vector<detail::NodeEntry> nodes) : nodes_(std::move(nodes)) {}
  std::vector<detail::NodeEntry> nodes_;
  friend class NodeSession;
  friend class CredentialStore;
};

// Scoped, noncopyable session. The envelope is exclusively for user DPAPI or
// already authenticated service IPC; callers must wipe its transient buffer.
class NodeSession {
 public:
  static NodeSession restore(const TrustedCatalog& catalog, std::string_view name, std::string_view token);
  static NodeSession restore_envelope(const TrustedCatalog& catalog, std::string_view name, std::string_view envelope);
  std::string credential_envelope() const;
  LeaseResult create_tunnel(std::string_view request_json) const;
  RenewResult renew_tunnel(std::string_view canonical_tunnel_id) const;
  void revoke_tunnel(std::string_view canonical_tunnel_id) const;
  void logout() const;
  static NodeSession login(const TrustedCatalog& catalog, std::string_view name,
                           std::string_view username, std::string_view password);
  NodeSession(const NodeSession&) = delete;
  NodeSession& operator=(const NodeSession&) = delete;
  ~NodeSession() { detail::wipe(token_.data(), token_.size()); }
  const detail::Identity& identity() const noexcept { return identity_; }
  std::int64_t expires_at() const noexcept { return expires_at_; }
 private:
  std::int64_t revalidate() const;
  NodeSession(detail::NodeEntry node, detail::Identity identity, const detail::LoginReply& reply)
      : node_(std::move(node)), identity_(std::move(identity)),
        token_(reply.token.begin(), reply.token.end()), expires_at_(reply.expires_at) {}
  detail::NodeEntry node_;
  detail::Identity identity_;
  std::vector<char> token_;
  std::int64_t expires_at_{};
};
} // namespace orangespace::node_session
