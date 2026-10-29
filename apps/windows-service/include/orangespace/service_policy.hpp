#pragma once
#include <cstdint>
#include <array>
#include <algorithm>
#include <span>
#include <optional>
#include <string>
#include <string_view>
namespace orangespace::service {
enum class Command : std::uint16_t { status = 1, browser_open = 2 };
inline constexpr std::size_t request_size = 12;
inline std::optional<Command> decode(std::span<const std::uint8_t> bytes) {
    if (bytes.size() != request_size || bytes[0] != 'O' || bytes[1] != 'S' ||
        bytes[2] != 'P' || bytes[3] != '1' || (bytes[4] != 1 && bytes[4] != 2)) return {};
    // Little-endian u16 command, u16 reserved flags, u32 payload length.
    // Version 1 has no request payloads; identities and credentials cannot be supplied.
    for (std::size_t i = 5; i < request_size; ++i) if (bytes[i] != 0) return {};
    return static_cast<Command>(bytes[4]);
}
inline std::string_view reply(Command command) {
    switch (command) {
    case Command::status:
        return R"({"ok":true,"service":"foundation","authenticated":false,"browser_allowed":false,"credential_ipc":false})";
    case Command::browser_open:
        return R"({"ok":false,"error":"browser_guard_unavailable"})";
    default:
        return R"({"ok":false,"error":"invalid_command"})";
    }
}
inline std::optional<std::string> pipe_sddl(std::string_view sid) {
    // OS-sourced SID only. Also reject control characters/SDDL injection defensively.
    if (!sid.starts_with("S-1-") || sid.size() > 184 || sid.size() < 9 ||
        sid == "S-1-5-18" || sid == "S-1-5-19" || sid == "S-1-5-20") return {};
    bool digit = false;
    for (std::size_t i = 4; i < sid.size(); ++i) {
        if (sid[i] >= '0' && sid[i] <= '9') { digit = true; continue; }
        if (sid[i] != '-' || !digit) return {};
        digit = false;
    }
    if (!digit) return {};
    // Do not grant FILE_CREATE_PIPE_INSTANCE (0x4), included in GENERIC_WRITE.
    return "D:P(A;;GA;;;SY)(A;;0x12019b;;;" + std::string(sid) + ")";
}
struct Peer { std::string sid; std::uint32_t session{}; std::uint64_t logon{}; };
inline bool authorize_peer(const Peer& expected, const Peer& actual) {
    return !expected.sid.empty() && expected.session != 0 && expected.logon != 0 &&
        expected.sid == actual.sid && expected.session == actual.session && expected.logon == actual.logon;
}
}
