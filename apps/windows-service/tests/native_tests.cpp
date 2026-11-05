#include "orangespace/windows_service.hpp"
#include <algorithm>
#include <array>
#include <iostream>
#include <thread>
using namespace orangespace::service;
using namespace orangespace::service::win;
static void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
struct PendingConnect {
    HANDLE pipe;
    Handle event{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    OVERLAPPED operation{};
    explicit PendingConnect(HANDLE value) : pipe(value) {
        operation.hEvent = event.get();
        require(event && !ConnectNamedPipe(pipe, &operation) && GetLastError() == ERROR_IO_PENDING, "pending ACL test connection");
    }
    ~PendingConnect() {
        CancelIoEx(pipe, &operation);
        DWORD ignored{};
        GetOverlappedResult(pipe, &operation, &ignored, TRUE);
        DisconnectNamedPipe(pipe);
    }
};
int main() {
    try {
        const auto peer = current_peer();
        if (peer.session == 0 || !pipe_sddl(peer.sid)) {
            std::cout << "SKIP: native tests require an interactive user token; use run-interactive.ps1 from OpenSSH\n";
            return 77;
        }
        const std::array<std::uint8_t, 6> secret{'s','e','c',0,'r','t'};
        const auto encrypted = protect_credential(secret, "node-token/v1");
        require(!encrypted.empty(), "DPAPI returned no blob");
        require(std::search(encrypted.begin(), encrypted.end(), secret.begin(), secret.end()) == encrypted.end(), "plaintext in blob");
        const auto decrypted = unprotect_credential(encrypted, "node-token/v1");
        require(std::ranges::equal(decrypted.bytes(), secret), "DPAPI roundtrip");
        bool rejected = false;
        try { (void)unprotect_credential(encrypted, "another-node/v1"); } catch (...) { rejected = true; }
        require(rejected, "DPAPI scope mismatch accepted");
        auto tampered = encrypted; tampered.back() ^= 0xff;
        rejected = false;
        try { (void)unprotect_credential(tampered, "node-token/v1"); } catch (...) { rejected = true; }
        require(rejected, "DPAPI tampered blob accepted");
        rejected = false;
        try { (void)protect_credential({}, "node-token/v1"); } catch (...) { rejected = true; }
        require(rejected, "empty credential accepted");
        const auto name = L"\\\\.\\pipe\\OrangeSpace.Test." + std::to_wstring(GetCurrentProcessId());
        Handle pipe = create_pipe(name, peer);
        Handle stop(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        // A second server instance (including one by this user) must not replace our endpoint.
        auto second = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS, 1, 1024, 12, 0, nullptr);
        require(second == INVALID_HANDLE_VALUE, "pipe squatting/second instance accepted");
        second = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS, 1, 1024, 12, 0, nullptr);
        require(second == INVALID_HANDLE_VALUE, "user granted FILE_CREATE_PIPE_INSTANCE");
        DWORD descriptor_size{};
        GetKernelObjectSecurity(pipe.get(), DACL_SECURITY_INFORMATION, nullptr, 0, &descriptor_size);
        require(descriptor_size != 0, "pipe security descriptor size");
        std::vector<BYTE> descriptor(descriptor_size);
        require(GetKernelObjectSecurity(pipe.get(), DACL_SECURITY_INFORMATION, descriptor.data(), descriptor_size,
            &descriptor_size) != FALSE, "pipe security descriptor readback");
        PACL acl{}; BOOL present{}, defaulted{};
        require(GetSecurityDescriptorDacl(descriptor.data(), &present, &acl, &defaulted) != FALSE && present && acl &&
            acl->AceCount == 2, "pipe DACL must contain exactly two explicit principals");
        void* user_ace{};
        require(GetAce(acl, 1, &user_ace) != FALSE, "user ACE readback");
        const auto* allowed = static_cast<ACCESS_ALLOWED_ACE*>(user_ace);
        require(allowed->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && allowed->Mask == 0x12019b &&
            !(allowed->Mask & FILE_CREATE_PIPE_INSTANCE), "user ACE includes server-create access");
        {
            PendingConnect listening(pipe.get());
            HANDLE process_token{};
            require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &process_token) != FALSE, "open token");
            Handle process_owner(process_token);
            std::array<BYTE, SECURITY_MAX_SID_SIZE> world{};
            DWORD world_size = static_cast<DWORD>(world.size());
            require(CreateWellKnownSid(WinWorldSid, nullptr, world.data(), &world_size) != FALSE, "world SID");
            SID_AND_ATTRIBUTES restricting{world.data(), 0};
            HANDLE restricted_token{};
            if (!CreateRestrictedToken(process_owner.get(), DISABLE_MAX_PRIVILEGE, 0, nullptr, 0, nullptr,
                1, &restricting, &restricted_token)) fail("restricted token");
            Handle restricted_owner(restricted_token);
            require(ImpersonateLoggedOnUser(restricted_owner.get()) != FALSE, "restricted impersonation");
            Handle outsider(CreateFileW(name.c_str(), 0x12019b, 0, nullptr, OPEN_EXISTING, 0, nullptr));
            const DWORD outsider_error = GetLastError();
            if (!RevertToSelf()) TerminateProcess(GetCurrentProcess(), ERROR_CANNOT_IMPERSONATE);
            require(!outsider && outsider_error == ERROR_ACCESS_DENIED, "Everyone-restricted token admitted");
        }
        std::string last_response;
        auto transact = [&](const Peer& expected, std::span<const std::uint8_t> frame) {
            bool served = false;
            std::thread server([&] {
                served = connect_pipe(pipe.get(), stop.get()) && serve_connection(pipe.get(), expected, stop.get());
                DisconnectNamedPipe(pipe.get());
            });
            WaitNamedPipeW(name.c_str(), 1500);
            Handle client(CreateFileW(name.c_str(), 0x12019b, 0, nullptr, OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION, nullptr));
            if (!client) {
                const DWORD error = GetLastError();
                SetEvent(stop.get()); server.join();
                throw std::runtime_error("same-user pipe open failed: " + std::to_string(error));
            }
            DWORD mode = PIPE_READMODE_MESSAGE; SetNamedPipeHandleState(client.get(), &mode, nullptr, nullptr);
            DWORD count{};
            const bool wrote = WriteFile(client.get(), frame.data(), static_cast<DWORD>(frame.size()), &count, nullptr) != FALSE;
            std::array<char, 1024> output{};
            const bool got = ReadFile(client.get(), output.data(), static_cast<DWORD>(output.size()), &count, nullptr) != FALSE;
            bool valid_reply = false;
            if (got && count >= 4) {
                const DWORD length = static_cast<unsigned char>(output[0]) |
                    (static_cast<unsigned char>(output[1]) << 8);
                valid_reply = length == count - 4 && output[2] == 0 && output[3] == 0;
                last_response.assign(output.data() + 4, count - 4);
                const char ack = 6;
                WriteFile(client.get(), &ack, 1, &count, nullptr);
            }
            server.join();
            return wrote && got && served && valid_reply;
        };
        const std::array<std::uint8_t,12> status{'O','S','P','1',1,0,0,0,0,0,0,0};
        require(transact(peer, status), "verified same-user peer rejected");
        auto other = peer; ++other.logon;
        require(!transact(other, status), "wrong logon peer accepted");
        other = peer; other.sid = "S-1-5-21-1-2-3-9999";
        require(!transact(other, status), "wrong SID peer accepted");
        other = peer; ++other.session;
        require(!transact(other, status), "wrong session peer accepted");
        auto invalid = status; invalid[8] = 1;
        require(!transact(peer, invalid), "nonzero payload frame accepted");
        require(!transact(peer, std::span(status).first(11)), "truncated frame accepted");
        std::array<std::uint8_t, 13> long_frame{};
        std::copy(status.begin(), status.end(), long_frame.begin());
        require(!transact(peer, long_frame), "oversized frame accepted");
        auto browser = status; browser[4] = 2;
        require(transact(peer, browser) && last_response == reply(Command::browser_open), "browser gate bypassed");
        // A connected peer that never sends data must not hold the service indefinitely.
        bool idle_served = true;
        std::thread idle_server([&] {
            idle_served = connect_pipe(pipe.get(), stop.get()) && serve_connection(pipe.get(), peer, stop.get());
            DisconnectNamedPipe(pipe.get());
        });
        WaitNamedPipeW(name.c_str(), 1500);
        Handle idle_client(CreateFileW(name.c_str(), 0x12019b, 0, nullptr, OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION, nullptr));
        if (!idle_client) { SetEvent(stop.get()); idle_server.join(); throw std::runtime_error("idle client open"); }
        idle_server.join();
        require(!idle_served, "idle client accepted");
        // A stop event must cancel an outstanding overlapped accept without a client.
        idle_client = Handle();
        bool accepted = true;
        std::thread stopping([&] { accepted = connect_pipe(pipe.get(), stop.get()); });
        SetEvent(stop.get()); stopping.join();
        require(!accepted, "stop did not cancel accept");
        std::cout << "Native DPAPI, live named-pipe token verification and endpoint tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "native test failed: " << error.what() << '\n';
        return 1;
    }
}
