#pragma once

#include "orangespace/json.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace orangespace {

inline bool valid_uuid(std::string_view value) {
  if (value.size() != 36) return false;
  for (std::size_t i = 0; i < value.size(); ++i) {
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (value[i] != '-') return false;
    } else if (!((value[i] >= '0' && value[i] <= '9') ||
                 (value[i] >= 'a' && value[i] <= 'f') ||
                 (value[i] >= 'A' && value[i] <= 'F'))) return false;
  }
  return true;
}

inline std::string canonical_uuid(std::string_view value) {
  if (!valid_uuid(value)) throw std::runtime_error("invalid UUID");
  std::string result(value);
  for (auto& c : result) if (c >= 'A' && c <= 'F') c = static_cast<char>(c - 'A' + 'a');
  return result;
}

inline std::filesystem::path profile_path(const std::filesystem::path& data_root,
                                          std::string_view user, std::string_view sandbox) {
  if (!valid_uuid(user) || !valid_uuid(sandbox)) throw std::runtime_error("invalid profile identity");
  return data_root / "users" / canonical_uuid(user) / "sandboxes" / canonical_uuid(sandbox) / "profile";
}

struct Sandbox {
  std::string id;
  std::string user_id;
  std::string name;
  std::string node_id;
  std::string state;
  std::string profile;
};

inline std::string field(const json::Value& value, std::string_view key) {
  const auto* item = value.find(key);
  return item ? item->text() : std::string{};
}

struct BrokerResponse {
  bool ok{};
  std::string message;
  std::vector<Sandbox> sandboxes;
};

inline BrokerResponse parse_response(std::string_view input, std::string_view expected_user = {}) {
  const auto document = json::parse(input);
  const auto* version = document.find("schema_version");
  const auto* number = version ? std::get_if<double>(&version->data) : nullptr;
  if (!number || *number != 1) throw std::runtime_error("unsupported broker response schema");
  BrokerResponse result;
  const auto* ok = document.find("ok");
  if (!ok || !std::holds_alternative<bool>(ok->data)) throw std::runtime_error("missing broker outcome");
  result.ok = ok->is_true();
  result.message = field(document, "reason");
  if (const auto* error = document.find("error")) result.message = field(*error, "message");
  if (const auto* items = document.find("sandboxes")) {
    const auto* array = std::get_if<json::Value::Array>(&items->data);
    if (!array) throw std::runtime_error("invalid sandbox collection");
    for (const auto& item : *array) {
      Sandbox sandbox{field(item, "id"), field(item, "user_id"), field(item, "name"),
                      field(item, "node_id"), field(item, "state"), field(item, "profile_path")};
      if (!valid_uuid(sandbox.id) || !valid_uuid(sandbox.user_id) ||
          (!sandbox.node_id.empty() && !valid_uuid(sandbox.node_id)))
        throw std::runtime_error("invalid sandbox identity from broker");
      if (!expected_user.empty() && canonical_uuid(sandbox.user_id) != canonical_uuid(expected_user))
        throw std::runtime_error("broker returned another user's sandbox");
      result.sandboxes.push_back(std::move(sandbox));
    }
  }
  return result;
}

// Windows CommandLineToArgvW / CRT quoting. No shell is involved. Even values
// containing quotes or trailing backslashes remain exactly one argument.
inline std::wstring quote_argument(std::wstring_view argument) {
  std::wstring result = L"\"";
  std::size_t backslashes = 0;
  for (const wchar_t c : argument) {
    if (c == L'\\') { ++backslashes; continue; }
    if (c == L'"') result.append(backslashes * 2 + 1, L'\\');
    else result.append(backslashes, L'\\');
    backslashes = 0;
    result += c;
  }
  result.append(backslashes * 2, L'\\');
  result += L'"';
  return result;
}

struct BrowserLaunchDecision {
  bool allowed;
  std::string reason;
};

inline BrowserLaunchDecision browser_launch_decision() {
  // Deliberately has no boolean, JSON or command-line input that could declare
  // protection ready. A future implementation must obtain a process-bound
  // permit from the protected service after WFP and DNS guards are installed.
  return {false, "Windows 网络防护尚未完成，浏览器启动已阻止。"};
}
}  // namespace orangespace
