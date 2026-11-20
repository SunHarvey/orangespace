#pragma once
// Client side of the control channel to the OrangeSpace WSL agent
// (linux-desktop/wsl/agent.py). The channel is the stdin/stdout of the
// wsl.exe child the client starts. Portable: no Windows dependencies.
//
//   agent -> client:  MARKER, then REPLY frames
//   client -> agent:  REQUEST frames
//   frame:            u8 kind, u32 number, u32 size (big-endian), payload <= 64 KiB
//
// Anything wsl.exe prints before the agent starts (banners, warnings) is
// skipped up to the marker, within a fixed budget.
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace orangespace::wsl {

inline constexpr std::string_view kMarker = "OrangeSpace-WSL-Agent-v1\n";
inline constexpr std::uint8_t kRequest = 1;
inline constexpr std::uint8_t kReply = 2;
inline constexpr std::size_t kHeader = 9;
inline constexpr std::size_t kMaxPayload = 65536;
inline constexpr std::size_t kMaxPreamble = 65536;

class ProtocolError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

inline std::vector<std::uint8_t> request_frame(std::uint32_t number, std::string_view payload) {
  if (number == 0 || payload.size() > kMaxPayload) throw ProtocolError("invalid request frame");
  std::vector<std::uint8_t> out(kHeader + payload.size());
  out[0] = kRequest;
  for (int i = 0; i < 4; ++i) out[1 + i] = static_cast<std::uint8_t>(number >> (24 - 8 * i));
  const auto size = static_cast<std::uint32_t>(payload.size());
  for (int i = 0; i < 4; ++i) out[5 + i] = static_cast<std::uint8_t>(size >> (24 - 8 * i));
  for (std::size_t i = 0; i < payload.size(); ++i) out[kHeader + i] = static_cast<std::uint8_t>(payload[i]);
  return out;
}

struct Reply {
  std::uint32_t number{};
  std::string payload;
};

// Incremental reader for the agent's output stream: feed() whatever bytes
// arrived, then take next() replies. Throws ProtocolError on anything other
// than marker + well-formed REPLY frames.
class ReplyReader {
 public:
  void feed(const void* data, std::size_t size) {
    const auto* p = static_cast<const std::uint8_t*>(data);
    buffer_.insert(buffer_.end(), p, p + size);
    if (!synced_) sync();
  }
  bool synced() const noexcept { return synced_; }

  std::optional<Reply> next() {
    if (!synced_ || buffer_.size() < kHeader) return std::nullopt;
    const std::uint8_t kind = buffer_[0];
    const std::uint32_t number = u32(1), size = u32(5);
    if (kind != kReply || number == 0 || size > kMaxPayload) throw ProtocolError("invalid reply frame");
    if (buffer_.size() < kHeader + size) return std::nullopt;
    Reply r{number, std::string(buffer_.begin() + kHeader, buffer_.begin() + kHeader + size)};
    buffer_.erase(buffer_.begin(), buffer_.begin() + kHeader + size);
    return r;
  }

 private:
  std::uint32_t u32(std::size_t at) const {
    return (std::uint32_t{buffer_[at]} << 24) | (std::uint32_t{buffer_[at + 1]} << 16) |
           (std::uint32_t{buffer_[at + 2]} << 8) | std::uint32_t{buffer_[at + 3]};
  }
  void sync() {
    const std::string_view view(reinterpret_cast<const char*>(buffer_.data()), buffer_.size());
    const auto at = view.find(kMarker);
    if (at == std::string_view::npos) {
      if (buffer_.size() > kMaxPreamble + kMarker.size()) throw ProtocolError("agent marker not found");
      return;
    }
    buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(at + kMarker.size()));
    synced_ = true;
  }

  std::vector<std::uint8_t> buffer_;
  bool synced_ = false;
};

}  // namespace orangespace::wsl
