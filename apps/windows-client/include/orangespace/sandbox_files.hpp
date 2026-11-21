#pragma once
// Files in a sandbox's Downloads folder, reached through the guest agent.
//
// The agent runs guest/desktop files-*, which opens the sandbox's HOME and
// then acts only as the sandbox's own UID: links or special files the sandbox
// placed there reach nothing the sandbox could not reach itself. Content moves
// in base64 chunks of at most kChunk bytes (one agent frame each). A file put
// into Downloads never replaces another: the guest picks "name (1).ext" etc.
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#include "orangespace/wsl_runtime.hpp"

#include <atomic>
#include <filesystem>
#include <functional>
#endif

namespace orangespace::sandbox {

struct GuestFile {
  std::string name;
  std::uint64_t size{};
  std::int64_t modified_s{};  // seconds since 1970
};

// Raw bytes per files.write / files.read; base64 of it fits one 64 KiB frame.
inline constexpr std::size_t kChunk = 45 * 1024;

namespace base64 {
inline constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

inline std::string encode(std::string_view in) {
  std::string out;
  out.reserve((in.size() + 2) / 3 * 4);
  std::size_t i = 0;
  for (; i + 3 <= in.size(); i += 3) {
    const auto n = (std::uint32_t(std::uint8_t(in[i])) << 16) | (std::uint32_t(std::uint8_t(in[i + 1])) << 8) |
                   std::uint8_t(in[i + 2]);
    out += kAlphabet[n >> 18];
    out += kAlphabet[(n >> 12) & 63];
    out += kAlphabet[(n >> 6) & 63];
    out += kAlphabet[n & 63];
  }
  if (const auto rest = in.size() - i; rest) {
    auto n = std::uint32_t(std::uint8_t(in[i])) << 16;
    if (rest == 2) n |= std::uint32_t(std::uint8_t(in[i + 1])) << 8;
    out += kAlphabet[n >> 18];
    out += kAlphabet[(n >> 12) & 63];
    out += rest == 2 ? kAlphabet[(n >> 6) & 63] : '=';
    out += '=';
  }
  return out;
}

// Strict: canonical padding only, no whitespace. Returns false on bad input.
inline bool decode(std::string_view in, std::string& out) {
  out.clear();
  if (in.size() % 4) return false;
  auto value = [](char c) -> int {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
  };
  out.reserve(in.size() / 4 * 3);
  for (std::size_t i = 0; i < in.size(); i += 4) {
    const bool last = i + 4 == in.size();
    const int pad = last ? (in[i + 3] == '=') + (in[i + 2] == '=') : 0;
    if (pad == 1 && in[i + 2] == '=') return false;
    int v[4]{};
    for (int k = 0; k < 4 - pad; ++k)
      if ((v[k] = value(in[i + k])) < 0) return false;
    const std::uint32_t n = (std::uint32_t(v[0]) << 18) | (std::uint32_t(v[1]) << 12) | (std::uint32_t(v[2]) << 6) |
                            std::uint32_t(v[3]);
    out += static_cast<char>(n >> 16);
    if (pad < 2) out += static_cast<char>((n >> 8) & 255);
    else if ((n >> 8) & 255) return false;  // non-zero bits in padding
    if (pad < 1) out += static_cast<char>(n & 255);
    else if (n & 255) return false;
  }
  return true;
}
}  // namespace base64

#ifdef _WIN32
// Calls are blocking; use them off the UI thread. One instance may serve
// several threads (the agent channel is concurrent).
class GuestFiles {
 public:
  using Progress = std::function<void(std::uint64_t done, std::uint64_t total)>;
  GuestFiles(wsl::Agent& agent, std::string user_id) : agent_(agent), user_id_(std::move(user_id)) {}

  std::vector<GuestFile> list(const std::string& sandbox);
  // Copies a local file into Downloads; returns the name it was given there.
  std::string push(const std::string& sandbox, const std::filesystem::path& local, std::string_view name,
                   const std::atomic<bool>& cancel, const Progress& progress);
  // Copies a Downloads file to a new local file (which must not exist yet).
  void pull(const std::string& sandbox, std::string_view name, const std::filesystem::path& local,
            const std::atomic<bool>& cancel, const Progress& progress);

 private:
  std::string call(const std::string& request, unsigned long timeout_ms = 60000);
  void cancel_transfer(const std::string& transfer) noexcept;
  wsl::Agent& agent_;
  const std::string user_id_;
};
#endif

}  // namespace orangespace::sandbox
