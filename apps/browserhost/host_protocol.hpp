#pragma once
// BrowserHost <-> owner control protocol. Portable (no Windows/CEF types) so it
// can be unit tested on any platform.
//
// Transport: two anonymous pipes created by the Service. Line 1 on stdin is the
// launch Config (contains proxy credentials, never put on argv/env/disk). Every
// later stdin line is one Command. BrowserHost writes one Event per stdout line.
// All lines are UTF-8 JSON objects terminated by '\n', at most kMaxLine bytes.
#include "orangespace/json.hpp"

#include <cmath>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace orangespace::browserhost {

inline constexpr std::size_t kMaxLine = 64 * 1024;
inline constexpr std::size_t kMaxUrl = 8 * 1024;

struct Config {
  std::string sandbox_id;         // canonical lowercase UUID
  std::uint64_t parent_window{};  // HWND of the owner's container window
  std::uint16_t proxy_port{};     // 127.0.0.1:<port>, this sandbox's helper only
  std::string proxy_username;
  std::string proxy_password;
  std::string profile_dir;        // absolute; root_cache_path for this sandbox
  std::string start_url;          // http(s) or about:blank
};

enum class Op { navigate, back, forward, reload, stop, new_tab, select_tab, close_tab, resize, shutdown };

struct Command {
  Op op{};
  int tab{};        // browser identifier; 0 = active tab where allowed
  std::string url;  // navigate / new_tab
};

struct TabState {
  int tab{};
  std::string url;
  std::string title;
  bool loading{};
  bool can_back{};
  bool can_forward{};
  bool active{};
};

inline bool canonical_uuid(std::string_view s) {
  if (s.size() != 36) return false;
  for (std::size_t i = 0; i < s.size(); ++i) {
    const char c = s[i];
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (c != '-') return false;
    } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
      return false;
    }
  }
  return s != "00000000-0000-0000-0000-000000000000";
}

// Only web navigations a user can type. No file:, data:, javascript:, chrome:,
// devtools: or custom schemes; those could read local files or bypass the proxy.
inline bool allowed_url(std::string_view url) {
  if (url == "about:blank") return true;
  if (url.empty() || url.size() > kMaxUrl) return false;
  for (const char c : url) {
    const auto u = static_cast<unsigned char>(c);
    if (u <= 0x20 || u == 0x7f) return false;
  }
  const auto scheme_end = url.find("://");
  if (scheme_end == std::string_view::npos) return false;
  std::string scheme(url.substr(0, scheme_end));
  for (auto& c : scheme) c = static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
  if (scheme != "http" && scheme != "https") return false;
  return url.size() > scheme_end + 3;  // non-empty authority
}

namespace detail {
inline std::optional<std::int64_t> integer(const json::Value* v, std::int64_t lo, std::int64_t hi) {
  if (!v) return std::nullopt;
  const auto* d = std::get_if<double>(&v->data);
  if (!d || !std::isfinite(*d) || std::floor(*d) != *d) return std::nullopt;
  if (*d < static_cast<double>(lo) || *d > static_cast<double>(hi)) return std::nullopt;
  return static_cast<std::int64_t>(*d);
}
inline const std::string* string(const json::Value* v) {
  return v ? std::get_if<std::string>(&v->data) : nullptr;
}
inline bool only_keys(const json::Value& v, std::initializer_list<std::string_view> keys) {
  const auto* object = std::get_if<json::Value::Object>(&v.data);
  if (!object) return false;
  for (const auto& [key, _] : *object) {
    bool known = false;
    for (const auto k : keys) known = known || key == k;
    if (!known) return false;
  }
  return true;
}
inline bool absolute_windows_path(std::string_view p) {
  if (p.size() < 3 || p.size() > 1024) return false;
  const bool drive = ((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) && p[1] == ':' && p[2] == '\\';
  if (!drive) return false;
  for (std::size_t i = 0; i < p.size(); ++i) {
    const char c = p[i];
    if (static_cast<unsigned char>(c) < 0x20 || c == '/' || c == '*' || c == '?' || c == '"' || c == '<' ||
        c == '>' || c == '|' || (c == ':' && i != 1))
      return false;
  }
  // No "." or ".." components: the Service passes an already canonical path.
  std::size_t start = 3;
  while (start <= p.size()) {
    const auto end = std::min(p.find('\\', start), p.size());
    const auto part = p.substr(start, end - start);
    if (part == "." || part == ".." || (part.empty() && end != p.size())) return false;
    start = end + 1;
  }
  return true;
}
}  // namespace detail

// Parse the first stdin line. On failure returns nullopt and a short reason that
// never contains input bytes (the line carries credentials).
inline std::optional<Config> parse_config(std::string_view line, std::string& error) {
  try {
    if (line.size() > kMaxLine) { error = "config too large"; return std::nullopt; }
    auto value = json::Parser(line).parse();
    json::detail::WipeGuard<json::Value> guard{value};
    if (!detail::only_keys(value, {"v", "sandbox_id", "parent_window", "proxy_port", "proxy_username",
                                   "proxy_password", "profile_dir", "start_url"})) {
      error = "config has unknown fields"; return std::nullopt;
    }
    if (detail::integer(value.find("v"), 1, 1) != 1) { error = "config version"; return std::nullopt; }
    Config c;
    const auto* sandbox = detail::string(value.find("sandbox_id"));
    if (!sandbox || !canonical_uuid(*sandbox)) { error = "sandbox_id"; return std::nullopt; }
    c.sandbox_id = *sandbox;
    const auto parent = detail::integer(value.find("parent_window"), 1, (std::int64_t{1} << 53) - 1);
    if (!parent) { error = "parent_window"; return std::nullopt; }
    c.parent_window = static_cast<std::uint64_t>(*parent);
    const auto port = detail::integer(value.find("proxy_port"), 1024, 65535);
    if (!port) { error = "proxy_port"; return std::nullopt; }
    c.proxy_port = static_cast<std::uint16_t>(*port);
    const auto* user = detail::string(value.find("proxy_username"));
    const auto* pass = detail::string(value.find("proxy_password"));
    if (!user || !pass || user->empty() || user->size() > 128 || pass->size() < 16 || pass->size() > 256) {
      error = "proxy credentials"; return std::nullopt;
    }
    c.proxy_username = *user;
    c.proxy_password = *pass;
    const auto* profile = detail::string(value.find("profile_dir"));
    if (!profile || !detail::absolute_windows_path(*profile)) { error = "profile_dir"; return std::nullopt; }
    c.profile_dir = *profile;
    const auto* start = detail::string(value.find("start_url"));
    c.start_url = start ? *start : "about:blank";
    if (!allowed_url(c.start_url)) { error = "start_url"; return std::nullopt; }
    return c;
  } catch (const std::exception&) {
    error = "config is not valid JSON";
    return std::nullopt;
  }
}

inline std::optional<Command> parse_command(std::string_view line, std::string& error) {
  try {
    if (line.size() > kMaxLine) { error = "command too large"; return std::nullopt; }
    const auto value = json::Parser(line).parse();
    if (!detail::only_keys(value, {"op", "tab", "url"})) { error = "unknown fields"; return std::nullopt; }
    const auto* op = detail::string(value.find("op"));
    if (!op) { error = "missing op"; return std::nullopt; }
    Command c;
    struct Entry { std::string_view name; Op op; bool needs_url; };
    static constexpr Entry table[] = {
        {"navigate", Op::navigate, true}, {"back", Op::back, false},       {"forward", Op::forward, false},
        {"reload", Op::reload, false},     {"stop", Op::stop, false},       {"new_tab", Op::new_tab, true},
        {"select_tab", Op::select_tab, false}, {"close_tab", Op::close_tab, false},
        {"resize", Op::resize, false},     {"shutdown", Op::shutdown, false}};
    const Entry* found = nullptr;
    for (const auto& e : table) if (e.name == *op) found = &e;
    if (!found) { error = "unknown op"; return std::nullopt; }
    c.op = found->op;
    if (const auto* tab = value.find("tab")) {
      const auto id = detail::integer(tab, 0, 1 << 30);
      if (!id) { error = "tab"; return std::nullopt; }
      c.tab = static_cast<int>(*id);
    }
    if ((c.op == Op::select_tab || c.op == Op::close_tab) && c.tab == 0) { error = "tab required"; return std::nullopt; }
    const auto* url = detail::string(value.find("url"));
    if (found->needs_url) {
      if (!url || !allowed_url(*url)) { error = "url not allowed"; return std::nullopt; }
      c.url = *url;
    } else if (url) {
      error = "unexpected url"; return std::nullopt;
    }
    return c;
  } catch (const std::exception&) {
    error = "command is not valid JSON";
    return std::nullopt;
  }
}

inline std::string json_quote(std::string_view s) {
  std::string out = "\"";
  for (const char ch : s) {
    const auto c = static_cast<unsigned char>(ch);
    switch (ch) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20 || c == 0x7f) {
          static constexpr char hex[] = "0123456789abcdef";
          out += "\\u00";
          out += hex[c >> 4];
          out += hex[c & 15];
        } else {
          out += ch;
        }
    }
  }
  out += '"';
  return out;
}

// The first stdin line, written by the Service before the pipes are handed to
// the client. Inverse of parse_config for every config parse_config accepts.
inline std::string config_line(const Config& c) {
  return "{\"v\":1,\"sandbox_id\":" + json_quote(c.sandbox_id) +
         ",\"parent_window\":" + std::to_string(c.parent_window) +
         ",\"proxy_port\":" + std::to_string(c.proxy_port) +
         ",\"proxy_username\":" + json_quote(c.proxy_username) +
         ",\"proxy_password\":" + json_quote(c.proxy_password) +
         ",\"profile_dir\":" + json_quote(c.profile_dir) + ",\"start_url\":" + json_quote(c.start_url) + "}\n";
}

inline std::string tab_event(const TabState& t) {
  return "{\"ev\":\"tab\",\"tab\":" + std::to_string(t.tab) + ",\"url\":" + json_quote(t.url) +
         ",\"title\":" + json_quote(t.title) + ",\"loading\":" + (t.loading ? "true" : "false") +
         ",\"back\":" + (t.can_back ? "true" : "false") + ",\"forward\":" + (t.can_forward ? "true" : "false") +
         ",\"active\":" + (t.active ? "true" : "false") + "}";
}
inline std::string tab_closed_event(int tab) {
  return "{\"ev\":\"tab_closed\",\"tab\":" + std::to_string(tab) + "}";
}
inline std::string simple_event(std::string_view name) { return "{\"ev\":" + json_quote(name) + "}"; }
inline std::string error_event(std::string_view reason) {
  return "{\"ev\":\"error\",\"reason\":" + json_quote(reason) + "}";
}

}  // namespace orangespace::browserhost
