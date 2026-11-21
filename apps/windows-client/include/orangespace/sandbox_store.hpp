#pragma once
// The signed-in user's sandbox list on this computer: name and bound node for
// each sandbox. Portable (no Windows dependencies); the client keeps one file
// per Centre user, %LOCALAPPDATA%\OrangeSpace\users\<central user UUID>\sandboxes.json.
//
// The desktop itself (HOME, browser data, downloads) lives in the OrangeSpace
// distribution under the same user and sandbox UUIDs; this file only names
// them. A sandbox is bound to exactly one node; changing it is explicit.
#include "orangespace/json.hpp"

#include <algorithm>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace orangespace::sandbox {

inline constexpr std::size_t kMaxSandboxes = 16;
// Code points. The desktop's window title is "<name> · 橙域", which the guest
// bounds at 64 characters.
inline constexpr std::size_t kMaxNameChars = 40;

class StoreError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

struct Record {
  std::string id;       // canonical lower-case UUID
  std::string name;     // shown in the list and the window title
  std::string node_id;  // canonical lower-case UUID of the bound node
};

inline bool canonical_uuid(std::string_view v) {
  if (v.size() != 36) return false;
  for (std::size_t i = 0; i < v.size(); ++i) {
    const char c = v[i];
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (c != '-') return false;
    } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
      return false;
    }
  }
  return true;
}

// Trimmed, non-empty, printable UTF-8 without control characters.
inline std::string valid_name(std::string_view raw) {
  const auto first = raw.find_first_not_of(" \t");
  const auto last = raw.find_last_not_of(" \t");
  if (first == std::string_view::npos) throw StoreError("empty name");
  const auto name = raw.substr(first, last - first + 1);
  std::size_t chars = 0;
  for (std::size_t i = 0; i < name.size(); ++chars) {
    const auto c = static_cast<unsigned char>(name[i]);
    std::size_t n = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : (c >> 3) == 30 ? 4 : 0;
    if (!n || i + n > name.size()) throw StoreError("name is not UTF-8");
    for (std::size_t k = 1; k < n; ++k)
      if ((static_cast<unsigned char>(name[i + k]) >> 6) != 2) throw StoreError("name is not UTF-8");
    if (n == 1 && (c < 0x20 || c == 0x7f)) throw StoreError("control character in name");
    i += n;
  }
  if (chars > kMaxNameChars) throw StoreError("name too long");
  return std::string(name);
}

class Store {
 public:
  Store() = default;

  // Strict: unknown fields, duplicates or invalid values reject the whole file
  // rather than silently dropping a sandbox.
  static Store parse(std::string_view text) {
    Store out;
    json::Value root;
    try {
      root = json::parse(text);
    } catch (const std::exception&) {
      throw StoreError("sandbox list is not valid JSON");
    }
    const auto* object = std::get_if<json::Value::Object>(&root.data);
    if (!object || object->size() != 2) throw StoreError("invalid sandbox list");
    const auto* schema = root.find("schema");
    if (!schema || !std::get_if<double>(&schema->data) || std::get<double>(schema->data) != 1)
      throw StoreError("unsupported sandbox list schema");
    const auto* list = root.find("sandboxes");
    if (!list || !std::get_if<json::Value::Array>(&list->data)) throw StoreError("invalid sandbox list");
    for (const auto& item : std::get<json::Value::Array>(list->data)) {
      const auto* fields = std::get_if<json::Value::Object>(&item.data);
      if (!fields || fields->size() != 3) throw StoreError("invalid sandbox entry");
      out.add(Record{text_of(item, "id"), text_of(item, "name"), text_of(item, "node_id")});
    }
    return out;
  }

  std::string serialize() const {
    std::string out = "{\"schema\":1,\"sandboxes\":[";
    for (std::size_t i = 0; i < records_.size(); ++i) {
      const auto& r = records_[i];
      out += (i ? "," : "") + std::string("{\"id\":") + quoted(r.id) + ",\"name\":" + quoted(r.name) +
             ",\"node_id\":" + quoted(r.node_id) + "}";
    }
    return out + "]}\n";
  }

  const std::vector<Record>& records() const noexcept { return records_; }

  const Record* find(std::string_view id) const {
    const auto it = std::find_if(records_.begin(), records_.end(), [&](const Record& r) { return r.id == id; });
    return it == records_.end() ? nullptr : &*it;
  }

  void add(Record r) {
    if (!canonical_uuid(r.id) || !canonical_uuid(r.node_id)) throw StoreError("invalid sandbox or node id");
    r.name = valid_name(r.name);
    if (find(r.id)) throw StoreError("duplicate sandbox id");
    if (records_.size() >= kMaxSandboxes) throw StoreError("too many sandboxes");
    records_.push_back(std::move(r));
  }

  void rebind(std::string_view id, std::string_view node_id) {
    if (!canonical_uuid(node_id)) throw StoreError("invalid node id");
    mutable_find(id).node_id = std::string(node_id);
  }

  void rename(std::string_view id, std::string_view name) { mutable_find(id).name = valid_name(name); }

  void remove(std::string_view id) {
    const auto it = std::find_if(records_.begin(), records_.end(), [&](const Record& r) { return r.id == id; });
    if (it == records_.end()) throw StoreError("no such sandbox");
    records_.erase(it);
  }

 private:
  Record& mutable_find(std::string_view id) {
    const auto it = std::find_if(records_.begin(), records_.end(), [&](const Record& r) { return r.id == id; });
    if (it == records_.end()) throw StoreError("no such sandbox");
    return *it;
  }

  static std::string text_of(const json::Value& v, std::string_view key) {
    const auto* f = v.find(key);
    if (!f || !std::get_if<std::string>(&f->data)) throw StoreError("invalid sandbox entry");
    return std::get<std::string>(f->data);
  }

  static std::string quoted(std::string_view text) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string out = "\"";
    for (const unsigned char c : text) {
      if (c == '"' || c == '\\') {
        out += '\\';
        out += static_cast<char>(c);
      } else if (c < 0x20) {
        out += "\\u00";
        out += hex[c >> 4];
        out += hex[c & 15];
      } else {
        out += static_cast<char>(c);
      }
    }
    return out + "\"";
  }

  std::vector<Record> records_;
};

}  // namespace orangespace::sandbox
