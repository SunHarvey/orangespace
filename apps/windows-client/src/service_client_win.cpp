#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include "orangespace/service_client.hpp"
#include <string>
#include <utility>
#include <vector>
namespace orangespace::service_client {
namespace {
constexpr DWORD timeout_ms = 1500;
constexpr DWORD client_rights = 0x12019b; // excludes FILE_CREATE_PIPE_INSTANCE
static_assert((client_rights & FILE_CREATE_PIPE_INSTANCE) == 0);
class Handle {
    HANDLE value_;
public:
    explicit Handle(HANDLE value = nullptr) : value_(value) {}
    ~Handle() { if (*this) CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE get() const { return value_; }
    explicit operator bool() const { return value_ && value_ != INVALID_HANDLE_VALUE; }
};
class ServiceHandle {
    SC_HANDLE value_;
public:
    explicit ServiceHandle(SC_HANDLE value) : value_(value) {}
    ~ServiceHandle() { if (value_) CloseServiceHandle(value_); }
    ServiceHandle(const ServiceHandle&) = delete;
    ServiceHandle& operator=(const ServiceHandle&) = delete;
    SC_HANDLE get() const { return value_; }
    explicit operator bool() const { return value_ != nullptr; }
};
StatusResult failure(ClientError error) { return {error, {}}; }
std::optional<ServerSnapshot> snapshot(SC_HANDLE service) {
    DWORD required{};
    QueryServiceConfigW(service, nullptr, 0, &required);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || required < sizeof(QUERY_SERVICE_CONFIGW) || required > 65536) return {};
    // vector storage has fundamental alignment suitable for QUERY_SERVICE_CONFIGW.
    std::vector<std::uint8_t> storage(required);
    auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(storage.data());
    if (!QueryServiceConfigW(service, config, required, &required)) return {};
    const bool own = config->dwServiceType == SERVICE_WIN32_OWN_PROCESS;
    const bool system = config->lpServiceStartName && wcscmp(config->lpServiceStartName, L"LocalSystem") == 0;
    SERVICE_STATUS_PROCESS status{};
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE*>(&status), sizeof(status), &required)) return {};
    return ServerSnapshot{own && status.dwServiceType == SERVICE_WIN32_OWN_PROCESS, system,
                          status.dwCurrentState == SERVICE_RUNNING, status.dwProcessId};
}
bool alive(HANDLE process) { return WaitForSingleObject(process, 0) == WAIT_TIMEOUT; }
bool bound(SC_HANDLE service, HANDLE process, HANDLE pipe, DWORD pid) {
    ULONG peer{};
    const auto state = snapshot(service);
    return state && GetNamedPipeServerProcessId(pipe, &peer) && peer == pid &&
        valid_server_binding(*state, pid, alive(process));
}
// One message per operation; ERROR_MORE_DATA is a rejection, not reassembly.
bool transfer(HANDLE pipe, HANDLE process, void* buffer, DWORD capacity, bool write, DWORD& count) {
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event) return false;
    OVERLAPPED operation{};
    operation.hEvent = event.get();
    const BOOL complete = write ? WriteFile(pipe, buffer, capacity, &count, &operation)
                                : ReadFile(pipe, buffer, capacity, &count, &operation);
    if (complete) return alive(process);
    if (GetLastError() != ERROR_IO_PENDING) return false;
    HANDLE waits[]{process, event.get()};
    if (WaitForMultipleObjects(2, waits, FALSE, timeout_ms) != WAIT_OBJECT_0 + 1) {
        // Cancel AND drain before stack OVERLAPPED/buffer destruction. Never FlushFileBuffers.
        CancelIoEx(pipe, &operation);
        GetOverlappedResult(pipe, &operation, &count, TRUE);
        return false;
    }
    return GetOverlappedResult(pipe, &operation, &count, FALSE) && alive(process);
}
}
std::optional<std::uint32_t> current_interactive_session() noexcept {
    HANDLE raw{};
    // Do not silently use the process identity while the calling thread impersonates.
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &raw)) {
        Handle thread_token(raw); return {};
    }
    if (GetLastError() != ERROR_NO_TOKEN) return {};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) return {};
    Handle token(raw);
    DWORD session{}, bytes{}, process_session{};
    if (!GetTokenInformation(token.get(), TokenSessionId, &session, sizeof(session), &bytes) ||
        !ProcessIdToSessionId(GetCurrentProcessId(), &process_session) ||
        !session || session != process_session) return {};
    return session;
}
StatusResult query_foundation_status() noexcept {
    try {
        // NULL machine/database selects local SCM; never accepts caller-selected names.
        ServiceHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        if (!scm) return failure(ClientError::scm_rejected);
        ServiceHandle service(OpenServiceW(scm.get(), L"OrangeSpaceFoundation", SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS));
        if (!service) return failure(GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST ? ClientError::service_missing : ClientError::scm_rejected);
        const auto session = current_interactive_session();
        if (!session) return failure(ClientError::session_rejected);
        const auto initial = snapshot(service.get());
        if (!initial || !valid_server_binding(*initial, initial->pid, true)) return failure(ClientError::service_rejected);
        Handle process(OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, initial->pid));
        if (!process || !alive(process.get())) return failure(ClientError::process_rejected);
        const auto name = L"\\\\.\\pipe\\OrangeSpace.Foundation.v1.session." + std::to_wstring(*session);
        const ULONGLONG deadline = GetTickCount64() + timeout_ms;
        HANDLE raw = INVALID_HANDLE_VALUE;
        do {
            raw = CreateFileW(name.c_str(), client_rights, 0, nullptr, OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION, nullptr);
            if (raw != INVALID_HANDLE_VALUE) break;
            if (GetLastError() != ERROR_PIPE_BUSY || !alive(process.get()) || GetTickCount64() >= deadline)
                return failure(ClientError::pipe_unavailable);
            Sleep(10);
        } while (true);
        Handle pipe(raw);
        DWORD mode = PIPE_READMODE_MESSAGE;
        if (!SetNamedPipeHandleState(pipe.get(), &mode, nullptr, nullptr)) return failure(ClientError::pipe_unavailable);
        // Re-read config + SCM status AFTER connect and compare actual server PID BEFORE bytes.
        if (!bound(service.get(), process.get(), pipe.get(), initial->pid)) return failure(ClientError::server_mismatch);
        std::array<std::uint8_t, 12> request{'O','S','P','1',1,0,0,0,0,0,0,0};
        DWORD count{};
        if (!transfer(pipe.get(), process.get(), request.data(), static_cast<DWORD>(request.size()), true, count) || count != request.size())
            return failure(ClientError::io_failed);
        std::array<std::uint8_t, 1024> response{};
        if (!transfer(pipe.get(), process.get(), response.data(), static_cast<DWORD>(response.size()), false, count)) return failure(ClientError::io_failed);
        const auto status = validate_status_frame(std::span<const std::uint8_t>(response.data(), count));
        if (!status) return failure(ClientError::invalid_response);
        if (!bound(service.get(), process.get(), pipe.get(), initial->pid)) return failure(ClientError::server_mismatch);
        std::uint8_t ack = 6;
        if (!transfer(pipe.get(), process.get(), &ack, 1, true, count) || count != 1) return failure(ClientError::io_failed);
        // ACK lets the server disconnect immediately, so a further pipe query can race
        // normal teardown. Recheck SCM and the retained process, not the disconnected pipe.
        const auto final_state = snapshot(service.get());
        if (!final_state || !valid_server_binding(*final_state, initial->pid, alive(process.get())))
            return failure(ClientError::server_mismatch);
        return {ClientError::none, status};
    } catch (...) { return failure(ClientError::service_rejected); }
}
}
