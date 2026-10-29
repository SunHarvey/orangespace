#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
namespace orangespace::service_client {
// Deliberately not a BrowserPermit, authentication result, or a readiness boolean.
enum class FoundationStatus { locked_foundation };
// Pure policy fed only by OS observations by the Windows implementation.
struct ServerSnapshot { bool own_process; bool local_system; bool running; std::uint32_t pid; };
inline bool valid_server_binding(ServerSnapshot state, std::uint32_t expected_pid, bool held_process_alive) {
    return state.own_process && state.local_system && state.running && state.pid != 0 &&
        state.pid == expected_pid && held_process_alive;
}
#ifdef _WIN32
enum class ClientError {
    none, service_missing, session_rejected, scm_rejected, service_rejected,
    process_rejected, pipe_unavailable, server_mismatch, io_failed, invalid_response
};
struct StatusResult {
    ClientError error{ClientError::service_rejected};
    std::optional<FoundationStatus> status;
};
// No identity, service/pipe name, payload, credentials, or ready flag inputs.
std::optional<std::uint32_t> current_interactive_session() noexcept;
StatusResult query_foundation_status() noexcept;
#endif
inline std::optional<FoundationStatus> validate_status_frame(std::span<const std::uint8_t> bytes) {
    constexpr std::string_view body = R"({"ok":true,"service":"foundation","authenticated":false,"browser_allowed":false,"credential_ipc":false})";
    if (bytes.size() < 4 || bytes.size() > 1024) return {};
    std::uint32_t length{};
    for (unsigned i = 0; i < 4; ++i) length |= std::uint32_t(bytes[i]) << (8 * i);
    if (length != bytes.size() - 4 || length != body.size() ||
        !std::equal(body.begin(), body.end(), bytes.begin() + 4)) return {};
    return FoundationStatus::locked_foundation;
}
}
