#include "orangespace/windows_service.hpp"
#include "orangespace/process_observation_acl.hpp"
#include <wtsapi32.h>
#include <sddl.h>
#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
using namespace orangespace::service;
using namespace orangespace::service::win;
namespace {
constexpr wchar_t service_name[] = L"OrangeSpaceFoundation";
constexpr std::size_t max_sessions = 64;
SERVICE_STATUS_HANDLE status_handle{};
SERVICE_STATUS service_status{};
std::mutex status_mutex;
Handle service_stop;
void publish_status(DWORD state, DWORD error = NO_ERROR) {
    std::lock_guard lock(status_mutex);
    service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    service_status.dwCurrentState = state;
    service_status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    service_status.dwWin32ExitCode = error;
    service_status.dwServiceSpecificExitCode = error == ERROR_SERVICE_SPECIFIC_ERROR ? 1 : 0;
    service_status.dwWaitHint = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING ? 5000 : 0;
    service_status.dwCheckPoint = service_status.dwWaitHint ? 1 : 0;
    SetServiceStatus(status_handle, &service_status);
}
DWORD WINAPI control(DWORD command, DWORD, void*, void*) {
    std::lock_guard lock(status_mutex);
    if (command == SERVICE_CONTROL_STOP || command == SERVICE_CONTROL_SHUTDOWN) {
        service_status.dwCurrentState = SERVICE_STOP_PENDING;
        service_status.dwControlsAccepted = 0;
        service_status.dwWaitHint = 5000;
        service_status.dwCheckPoint = 1;
        if (service_stop) SetEvent(service_stop.get());
        SetServiceStatus(status_handle, &service_status);
        return NO_ERROR;
    }
    if (command == SERVICE_CONTROL_INTERROGATE) {
        SetServiceStatus(status_handle, &service_status);
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}
struct Worker {
    Peer expected;
    Handle stop;
    Handle pipe;
    std::atomic_bool failed{false};
    std::thread thread;
    explicit Worker(Peer peer) : expected(std::move(peer)), stop(CreateEventW(nullptr, TRUE, FALSE, nullptr)) {
        if (!stop) fail("worker event");
        const std::wstring name = L"\\\\.\\pipe\\OrangeSpace.Foundation.v1.session." + std::to_wstring(expected.session);
        pipe = create_pipe(name, expected);
        thread = std::thread([this] {
            try {
                while (WaitForSingleObject(stop.get(), 0) == WAIT_TIMEOUT) {
                    if (!connect_pipe(pipe.get(), stop.get())) {
                        if (WaitForSingleObject(stop.get(), 0) != WAIT_OBJECT_0) failed = true;
                        break;
                    }
                    (void)serve_connection(pipe.get(), expected, stop.get());
                    DisconnectNamedPipe(pipe.get());
                }
            } catch (...) { failed = true; }
        });
    }
    ~Worker() {
        SetEvent(stop.get());
        if (thread.joinable()) thread.join();
    }
};
std::map<DWORD, Peer> logged_on_peers() {
    static_assert(WTSActive == 0 && WTSDisconnected == 4);
    PWTS_SESSION_INFOW sessions{};
    DWORD count{};
    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count)) fail("WTSEnumerateSessions");
    struct Free { PWTS_SESSION_INFOW p; ~Free() { WTSFreeMemory(p); } } free_sessions{sessions};
    std::map<DWORD, Peer> result;
    for (DWORD i = 0; i < count; ++i) {
        if ((sessions[i].State != WTSActive && sessions[i].State != WTSDisconnected) ||
            sessions[i].SessionId == 0) continue;
        HANDLE raw{};
        // Only trusted LocalSystem code obtains identities; requests never select a SID/session.
        if (!WTSQueryUserToken(sessions[i].SessionId, &raw)) continue;
        const Handle token(raw);
        const Peer peer = token_peer(token.get());
        if (!eligible_session(static_cast<std::uint32_t>(sessions[i].State), sessions[i].SessionId, peer)) continue;
        if (result.size() >= max_sessions) throw std::runtime_error("too many interactive sessions");
        result.emplace(peer.session, peer);
    }
    return result;
}
void publish_observation_acl(ProcessObservationAcl& acl, const std::map<DWORD, Peer>& peers) {
    // Retain only query-limited + synchronize handles for SCM PID/death checks.
    // User SID grants span logons; pipe authorization still checks SID/session/LUID.
    acl.publish(peers);
}
void run_service() {
    // No console mode and no impersonated/user-configured service identity fallback.
    if (current_peer().sid != "S-1-5-18") throw std::runtime_error("LocalSystem service context required");
    ProcessObservationAcl observation_acl;
    std::map<DWORD, std::unique_ptr<Worker>> workers;
    while (WaitForSingleObject(service_stop.get(), 0) == WAIT_TIMEOUT) {
        const auto peers = logged_on_peers();
        publish_observation_acl(observation_acl, peers);
        for (auto it = workers.begin(); it != workers.end();) {
            if (it->second->failed) throw std::runtime_error("pipe worker failed");
            const auto found = peers.find(it->first);
            if (found == peers.end() || !authorize_peer(it->second->expected, found->second)) it = workers.erase(it);
            else ++it;
        }
        for (const auto& [session, peer] : peers)
            if (!workers.contains(session)) workers.emplace(session, std::make_unique<Worker>(peer));
        if (WaitForSingleObject(service_stop.get(), 1000) != WAIT_TIMEOUT) break;
    }
}
void WINAPI service_main(DWORD, LPWSTR*) {
    status_handle = RegisterServiceCtrlHandlerExW(service_name, control, nullptr);
    if (!status_handle) return;
    publish_status(SERVICE_START_PENDING);
    {
        std::lock_guard lock(status_mutex);
        service_stop = Handle(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    }
    if (!service_stop) { publish_status(SERVICE_STOPPED, GetLastError()); return; }
    DWORD error = NO_ERROR;
    try {
        publish_status(SERVICE_RUNNING);
        run_service();
    } catch (...) { error = ERROR_SERVICE_SPECIFIC_ERROR; }
    publish_status(SERVICE_STOPPED, error);
}
}
int wmain(int argc, wchar_t**) {
    if (argc != 1) return ERROR_INVALID_PARAMETER;
    SERVICE_TABLE_ENTRYW table[]{{const_cast<LPWSTR>(service_name), service_main}, {nullptr, nullptr}};
    if (!StartServiceCtrlDispatcherW(table)) return static_cast<int>(GetLastError());
    return 0;
}
