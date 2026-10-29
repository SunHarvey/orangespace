#include "orangespace/service_client.hpp"
#include <cstdlib>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <filesystem>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
using namespace orangespace::service_client;
void check(bool value, const char* name) {
    if (!value) { std::cerr << "FAIL: " << name << '\n'; std::exit(1); }
}
std::vector<std::uint8_t> frame(std::string body) {
    std::vector<std::uint8_t> bytes(4 + body.size());
    for (unsigned i = 0; i < 4; ++i) bytes[i] = static_cast<std::uint8_t>(body.size() >> (8 * i));
    std::copy(body.begin(), body.end(), bytes.begin() + 4);
    return bytes;
}
#ifdef _WIN32
void lifecycle_test(const std::filesystem::path& directory, DWORD session, DWORD service_pid) {
    const auto marker = [&](const char* name) {
        std::ofstream file(directory / name); file << "test-only";
        check(file.good(), "lifecycle marker written");
    };
    const auto wait_marker = [&](const char* name) {
        const auto until = GetTickCount64() + 15000;
        while (!std::filesystem::exists(directory / name)) {
            check(GetTickCount64() < until, "lifecycle orchestration deadline");
            Sleep(10);
        }
    };
    const auto name = L"\\\\.\\pipe\\OrangeSpace.Foundation.v1.session." + std::to_wstring(session);
    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (unsigned attempt = 0; attempt < 100; ++attempt) {
        pipe = CreateFileW(name.c_str(), 0x12019b, 0, nullptr, OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION, nullptr);
        if (pipe != INVALID_HANDLE_VALUE) break;
        Sleep(10);
    }
    check(pipe != INVALID_HANDLE_VALUE, "old connection established");
    ULONG actual_pid{};
    check(GetNamedPipeServerProcessId(pipe, &actual_pid) && actual_pid == service_pid,
          "old connection bound to actual SCM PID");
    HANDLE process = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, service_pid);
    check(process != nullptr, "old process retained against PID reuse");
    HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    check(event != nullptr, "old read event");
    OVERLAPPED operation{}; operation.hEvent = event;
    std::uint8_t byte{}; DWORD count{};
    check(!ReadFile(pipe, &byte, 1, &count, &operation) && GetLastError() == ERROR_IO_PENDING,
          "old connection read is genuinely pending before stop");
    marker("old-ready.txt");
    wait_marker("stopped.txt");
    if (WaitForSingleObject(event, 5000) != WAIT_OBJECT_0) {
        CancelIoEx(pipe, &operation);
        GetOverlappedResult(pipe, &operation, &count, TRUE);
        check(false, "service stop must close old connection without waiting for client");
    }
    check(!GetOverlappedResult(pipe, &operation, &count, FALSE), "old pending read fails closed on stop");
    const auto error = GetLastError();
    check(error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED || error == ERROR_OPERATION_ABORTED,
          "old read has closed/cancelled pipe error");
    check(WaitForSingleObject(process, 5000) == WAIT_OBJECT_0, "old service process exited");
    const auto stopped = query_foundation_status();
    check(!stopped.status && stopped.error == ClientError::service_rejected,
          "stopped service query fails closed");
    std::cout << "PASS: pending old read closed error=" << error
              << "; stopped query error=" << static_cast<int>(stopped.error) << '\n';
    marker("old-failed.txt");
    wait_marker("restarted.txt");
    ResetEvent(event);
    operation = {}; operation.hEvent = event;
    bool wrote = WriteFile(pipe, &byte, 1, &count, &operation) != FALSE;
    if (!wrote && GetLastError() == ERROR_IO_PENDING) {
        if (WaitForSingleObject(event, 1500) != WAIT_OBJECT_0) CancelIoEx(pipe, &operation);
        wrote = GetOverlappedResult(pipe, &operation, &count, TRUE) != FALSE;
    }
    check(!wrote, "old connection cannot revive after service restart");
    const auto restarted = query_foundation_status();
    check(restarted.error == ClientError::none && restarted.status == FoundationStatus::locked_foundation,
          "fresh SCM-bound canonical query succeeds after restart");
    CloseHandle(event); CloseHandle(pipe); CloseHandle(process);
    std::cout << "PASS: old connection stays dead; fresh installed handshake after restart\n";
}
#endif
int main(int argc, char** argv) {
    const bool lifecycle = argc == 4 && std::string_view(argv[2]) == "--lifecycle-dir";
    const bool installed = (argc == 2 || lifecycle) && std::string_view(argv[1]) == "--installed-service";
    check(argc == 1 || installed, "only explicit --installed-service fixture mode accepted");
#ifndef _WIN32
    check(!installed, "installed service requires Windows");
#endif
    const std::string body = R"({"ok":true,"service":"foundation","authenticated":false,"browser_allowed":false,"credential_ipc":false})";
    check(validate_status_frame(frame(body)).has_value(), "fixed foundation status accepted");
    for (std::size_t n = 0; n < frame(body).size(); ++n) {
        auto bytes = frame(body); bytes.resize(n);
        check(!validate_status_frame(bytes), "truncated frame rejected");
    }
    auto extra = frame(body); extra.push_back(0);
    check(!validate_status_frame(extra), "trailing byte rejected");
    auto wrong_length = frame(body); wrong_length[3] = 128;
    check(!validate_status_frame(wrong_length), "overflow length rejected");
    check(!validate_status_frame(std::vector<std::uint8_t>(1025)), "oversize rejected");
    for (const std::string key : {"authenticated", "browser_allowed", "credential_ipc"}) {
        auto malicious = body;
        malicious.replace(malicious.find(key) + key.size() + 2, 5, "true");
        check(!validate_status_frame(frame(malicious)), "privileged claim rejected");
    }
    auto ready = body; ready.insert(ready.size() - 1, ",\"ready\":true");
    check(!validate_status_frame(frame(ready)), "ready claim rejected");
    check(!validate_status_frame(frame(body + " ")), "noncanonical body rejected");
    auto duplicate = body; duplicate.insert(duplicate.size() - 1, ",\"authenticated\":true");
    check(!validate_status_frame(frame(duplicate)), "duplicate field rejected");
    const auto canonical = frame(body);
    for (std::size_t i = 0; i < canonical.size(); ++i) {
        auto mutated = canonical; mutated[i] ^= 1;
        check(!validate_status_frame(mutated), "each single-byte mutation rejected");
    }
    for (std::size_t n = 0; n <= 2048; ++n)
        check(!validate_status_frame(std::vector<std::uint8_t>(n)), "zero-filled frames rejected");
    check(valid_server_binding({true, true, true, 42}, 42, true), "running own LocalSystem bound");
    check(!valid_server_binding({false, true, true, 42}, 42, true), "shared process rejected");
    check(!valid_server_binding({true, false, true, 42}, 42, true), "non-system rejected");
    check(!valid_server_binding({true, true, false, 42}, 42, true), "stopped rejected");
    check(!valid_server_binding({true, true, true, 0}, 0, true), "zero pid rejected");
    check(!valid_server_binding({true, true, true, 42}, 43, true), "replaced pid rejected");
    check(!valid_server_binding({true, true, true, 42}, 42, false), "dead process rejected");
#ifdef _WIN32
    DWORD os_session{};
    check(ProcessIdToSessionId(GetCurrentProcessId(), &os_session) != FALSE, "OS session observed");
    const auto session = current_interactive_session();
    if (installed && session) {
        const auto name = L"\\\\.\\pipe\\OrangeSpace.Foundation.v1.session." + std::to_wstring(*session);
        const BOOL endpoint = WaitNamedPipeW(name.c_str(), 100);
        const DWORD error = endpoint ? ERROR_SUCCESS : GetLastError();
        std::cout << "OBSERVED: session endpoint available=" << (endpoint ? 1 : 0)
                  << " win32=" << error << '\n';
    }
    if (os_session == 0) check(!session, "actual session zero rejected");
    else check(session && *session == os_session, "actual interactive session derived");
    const auto result = query_foundation_status();
    if (installed) {
        std::cout << "OBSERVED: installed query error=" << static_cast<int>(result.error)
                  << " session=" << (session ? std::to_string(*session) : "rejected") << '\n';
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        check(scm != nullptr, "fixture SCM open");
        SC_HANDLE service = OpenServiceW(scm, L"OrangeSpaceFoundation", SERVICE_QUERY_STATUS);
        check(service != nullptr, "fixture service open");
        SERVICE_STATUS_PROCESS state{}; DWORD needed{};
        check(QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE*>(&state),
                                   sizeof(state), &needed) != FALSE, "fixture SCM PID observed");
        CloseServiceHandle(service); CloseServiceHandle(scm);
        for (DWORD forbidden : {DWORD(PROCESS_TERMINATE), DWORD(PROCESS_VM_WRITE),
                                DWORD(PROCESS_DUP_HANDLE), DWORD(WRITE_DAC)}) {
            HANDLE dangerous = OpenProcess(forbidden, FALSE, state.dwProcessId);
            if (dangerous) CloseHandle(dangerous);
            check(!dangerous, "limited client cannot mutate/duplicate/terminate service process");
        }
        check(session && *session != 0, "installed fixture requires OS-derived nonzero session");
        check(result.error == ClientError::none && result.status == FoundationStatus::locked_foundation,
              "installed LocalSystem SCM/actual pipe PID/canonical locked_foundation/ACK handshake");
        HANDLE token{};
        check(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) != FALSE, "limited token query");
        TOKEN_ELEVATION elevation{}; DWORD token_bytes{};
        check(GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &token_bytes) != FALSE &&
              !elevation.TokenIsElevated, "installed client really uses non-elevated limited token");
        CloseHandle(token);
        std::cout << "PASS: client non-elevated; service process mutation rights denied\n";
        std::cout << "PASS: installed SCM + actual pipe PID + canonical locked_foundation + ACK\n";
        if (lifecycle) lifecycle_test(argv[3], *session, state.dwProcessId);
        return EXIT_SUCCESS;
    }
    check(!result.status, "negative-only runner never accepts live handshake");
    check(result.error == ClientError::service_missing || result.error == ClientError::session_rejected,
          "missing service or session zero rejected");
    if (!session) check(result.error == ClientError::service_missing || result.error == ClientError::session_rejected,
                       "session zero has no status");
    std::cout << "PASS: native negative query error=" << static_cast<int>(result.error)
              << " session=" << (session ? std::to_string(*session) : "rejected") << '\n';
#endif
    std::cout << "PASS: portable frame and service binding validation\n";
}
