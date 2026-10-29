#include "orangespace/windows_service.hpp"
#include <array>
namespace orangespace::service::win {
namespace {
constexpr DWORD operation_timeout_ms = 1500;
bool wait_operation(HANDLE pipe, OVERLAPPED& operation, HANDLE stop, DWORD timeout, DWORD& transferred) {
    HANDLE waits[]{stop, operation.hEvent};
    if (WaitForMultipleObjects(2, waits, FALSE, timeout) != WAIT_OBJECT_0 + 1) {
        // The stack OVERLAPPED and its buffer must live until cancellation is completed.
        CancelIoEx(pipe, &operation);
        GetOverlappedResult(pipe, &operation, &transferred, TRUE);
        return false;
    }
    return GetOverlappedResult(pipe, &operation, &transferred, FALSE) != FALSE;
}
bool transfer(HANDLE pipe, HANDLE stop, void* data, DWORD size, bool writing) {
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event) return false;
    OVERLAPPED operation{}; operation.hEvent = event.get();
    DWORD transferred{};
    const BOOL done = writing ? WriteFile(pipe, data, size, &transferred, &operation) :
        ReadFile(pipe, data, size, &transferred, &operation);
    if (!done) {
        // ERROR_MORE_DATA rejects oversized messages, not a request to allocate/reassemble.
        if (GetLastError() != ERROR_IO_PENDING ||
            !wait_operation(pipe, operation, stop, operation_timeout_ms, transferred)) return false;
    }
    return transferred == size;
}
class Impersonation {
    bool active_{};
public:
    explicit Impersonation(HANDLE pipe) : active_(ImpersonateNamedPipeClient(pipe) != FALSE) {}
    ~Impersonation() {
        // Never proceed with an uncertain thread security context.
        if (active_ && !RevertToSelf()) TerminateProcess(GetCurrentProcess(), ERROR_CANNOT_IMPERSONATE);
    }
    explicit operator bool() const noexcept { return active_; }
};
bool verified_peer(HANDLE pipe, const Peer& expected) {
    Impersonation impersonation(pipe);
    if (!impersonation) return false;
    HANDLE raw{};
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &raw)) return false;
    Handle token(raw);
    SECURITY_IMPERSONATION_LEVEL level{};
    DWORD bytes{};
    if (!GetTokenInformation(token.get(), TokenImpersonationLevel, &level, sizeof(level), &bytes) ||
        level < SecurityImpersonation) return false;
    try { return authorize_peer(expected, token_peer(token.get())); }
    catch (...) { return false; }
}
}
bool connect_pipe(HANDLE pipe, HANDLE stop) {
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event) return false;
    OVERLAPPED operation{}; operation.hEvent = event.get();
    if (ConnectNamedPipe(pipe, &operation)) return true;
    const DWORD error = GetLastError();
    if (error == ERROR_PIPE_CONNECTED) return true;
    DWORD transferred{};
    return error == ERROR_IO_PENDING && wait_operation(pipe, operation, stop, INFINITE, transferred);
}
bool serve_connection(HANDLE pipe, const Peer& expected, HANDLE stop) {
    std::array<std::uint8_t, request_size> bytes{};
    if (!transfer(pipe, stop, bytes.data(), static_cast<DWORD>(bytes.size()), false)) return false;
    // Impersonation identifies the token of the client whose message was read, not JSON claims.
    if (!verified_peer(pipe, expected)) return false;
    const auto command = decode(bytes);
    if (!command) return false;
    const auto body = reply(*command);
    std::array<std::uint8_t, 1024> response{};
    const auto size = body.size();
    if (size > response.size() - 4) return false;
    for (unsigned i = 0; i < 4; ++i) response[i] = static_cast<std::uint8_t>((size >> (8 * i)) & 255);
    std::copy(body.begin(), body.end(), response.begin() + 4);
    if (!transfer(pipe, stop, response.data(), static_cast<DWORD>(size + 4), true)) return false;
    // Bounded application ACK replaces unbounded FlushFileBuffers, avoiding discarded replies
    // at DisconnectNamedPipe without letting a non-reading client hold service shutdown hostage.
    std::uint8_t ack{};
    return transfer(pipe, stop, &ack, 1, false) && ack == 6;
}
}
