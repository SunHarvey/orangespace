#include "orangespace/service_client.hpp"
#include "orangespace/install_identity.hpp"
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
    const auto name = std::wstring(orangespace::install_identity::pipe_prefix) + std::to_wstring(session);
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
    const std::string chain_status=R"({"ok":true,"auth_id":"33333333-3333-4333-8333-333333333333","user_id":"11111111-1111-4111-8111-111111111111","node_id":"22222222-2222-4222-8222-222222222222","browser_allowed":false,"tunnels":[]})";
    check(validate_chain_frame(frame(chain_status), orangespace::service::chain::Op::status).has_value(), "strict OSP2 status response");
    auto forged=chain_status; forged.insert(forged.size()-1,",\"ready\":true");
    check(!validate_chain_frame(frame(forged), orangespace::service::chain::Op::status), "OSP2 rejects ready fields");
    check(!validate_chain_frame(frame(chain_status), orangespace::service::chain::Op::start), "response command confusion rejected");
    using orangespace::service::chain::Op;
    const std::string start_body=R"({"ok":true,"auth_id":"33333333-3333-4333-8333-333333333333","binding":{"user_id":"11111111-1111-4111-8111-111111111111","sandbox_id":"44444444-4444-4444-8444-444444444444","node_id":"22222222-2222-4222-8222-222222222222","tunnel_id":"55555555-5555-4555-8555-555555555555","generation":8},"process_started":true,"tunnel_authenticated":true,"forwarding_verified":true,"browser_allowed":false})";
    ExpectedReply expected{"33333333-3333-4333-8333-333333333333","11111111-1111-4111-8111-111111111111","22222222-2222-4222-8222-222222222222",orangespace::service::chain::Cursor{"44444444-4444-4444-8444-444444444444",7}};
    check(validate_chain_frame(frame(start_body),Op::start,expected).has_value(),"prior exact sandbox and advanced generation validated before ACK");
    expected.prior->generation=8;
    check(!validate_chain_frame(frame(start_body),Op::start,expected),"non-advancing generation cannot be ACKed");
    expected.prior->generation=7; expected.prior->sandbox="66666666-6666-4666-8666-666666666666";
    check(!validate_chain_frame(frame(start_body),Op::start,expected),"different sandbox cannot be ACKed");
    expected.prior.reset(); expected.auth="66666666-6666-4666-8666-666666666666";
    check(!validate_chain_frame(frame(start_body),Op::start,expected),"different authorization cannot be ACKed");
    check(validate_chain_frame(frame(R"({"ok":true,"browser_allowed":false})"),Op::retire).has_value(),"strict op6 response");
    check(!validate_chain_frame(frame(R"({"ok":true,"browser_allowed":false,"auth_id":"33333333-3333-4333-8333-333333333333"})"),Op::retire),"op6 response rejects extra fields");
    namespace nd = orangespace::node_session::detail;
    const std::string diagnostic = "{\"ok\":true,\"browser_allowed\":false,\"binding\":" +
        start_body.substr(start_body.find("{\"user_id\""), start_body.find("},\"process_started\"") - start_body.find("{\"user_id\"") + 1) +
        ",\"server_expiry\":2000000000,\"deadline_ms\":9000,\"clock\":\"" + std::string(nd::lease_clock) +
        "\",\"observed_at_ms\":1100,\"fresh_proof\":true,\"reason\":\"verified\"}";
    check(validate_chain_frame(frame(diagnostic), Op::diagnose).has_value(), "strict op8 completed observation accepted");
    const auto diagnostic_binding = validate_binding(nd::field(*validate_chain_frame(frame(diagnostic),Op::diagnose),"binding"));
    const auto decode = [&](const std::string& value, std::int64_t started=1000, std::int64_t received=1200) {
        return decode_tunnel_diagnostic(frame(value),diagnostic_binding,started,received);
    };
    check(decode(diagnostic).has_value(), "typed full diagnostic decoded before ACK");
    const auto diagnostic_wire=frame(diagnostic);
    const auto diagnostic_root=validate_chain_frame(diagnostic_wire,Op::diagnose);
    const auto prepared=prepare_chain_result<true>(*diagnostic_root,diagnostic_wire,
        [&](std::span<const std::uint8_t> raw) {
            auto typed=decode_tunnel_diagnostic(raw,diagnostic_binding,1000,1200);
            check(typed.has_value(),"raw transport preparation decodes the actual frame");
            return std::move(*typed);
        });
    check(prepared.fresh_proof && prepared.binding==diagnostic_binding,"raw final typed owner constructed before transport ACK");
    const auto legacy_prepared=prepare_chain_result(*diagnostic_root,diagnostic_wire,
        [](const orangespace::json::Value& root){return nd::field(root,"ok").is_true();});
    check(legacy_prepared,"legacy JSON preparation remains unchanged");
    for(const std::uint64_t completed:{std::uint64_t(5999),std::uint64_t(6000),std::uint64_t(999),~std::uint64_t(0)}) {
        auto proof=*decode(diagnostic);auto expired=proof;
        expired.fresh_proof=false;expired.reason="probe_deadline";
        const auto finished=finish_tunnel_diagnostic(std::move(proof),std::move(expired),1000,completed);
        check(finished.fresh_proof==(completed==5999),"ACK completion cannot publish a late positive observation");
        if(!finished.fresh_proof)check(finished.reason=="probe_deadline","preallocated late result keeps consistent reason");
    }
    const auto change = [&](std::string from, std::string to) {
        auto value=diagnostic; value.replace(value.find(from),from.size(),to); return value;
    };
    for (const auto& bad : {
        change("9000","9000.0000000000000001"),change("9000","9e3"),change("9000","9000.0"),
        change("9000","9007199254740992"), change("9000","0"),change("2000000000","0"),
        change("\"generation\":8","\"generation\":8.000000000000001"),
        change(std::string(nd::lease_clock),"unknown-clock"), change("\"browser_allowed\":false","\"browser_allowed\":true"),
        change("\"ok\":true","\"ok\":1"),change("\"fresh_proof\":true","\"fresh_proof\":1"),
        change("\"fresh_proof\":true","\"fresh_proof\":false"),change("verified","probe_deadline"),
        change("verified","unknown"),change("\"reason\":\"verified\"","\"extra\":true"),
        change("\"reason\":\"verified\"","\"reason\":\"verified\",\"extra\":true"),
        change("1100","999"), change("1100","1201")})
        check(!decode(bad), "malformed/contradictory op8 rejected");
    for (int field=0;field<5;++field) {
        auto mismatch=diagnostic_binding;
        if(field==0)mismatch.user="66666666-6666-4666-8666-666666666666";
        if(field==1)mismatch.node="66666666-6666-4666-8666-666666666666";
        if(field==2)mismatch.sandbox="66666666-6666-4666-8666-666666666666";
        if(field==3)mismatch.tunnel="66666666-6666-4666-8666-666666666666";
        if(field==4)++mismatch.generation;
        check(!decode_tunnel_diagnostic(frame(diagnostic),mismatch,1000,1200),"each full tuple mismatch rejected");
    }
    check(!decode(diagnostic,1000,9000),"deadline equality rejected");
    check(!decode(diagnostic,1000,6000),"original 5000ms budget equality rejected");
    check(!decode(diagnostic,1200,1000),"reversed samples rejected");
    check(!decode(diagnostic,-1,1200),"negative sample rejected");
    check(!decode(diagnostic,1000,nd::max_exact_integer+1),"unbounded sample rejected");
    for(const std::string reason:{"probe_unavailable","probe_deadline","stale_authority"}) {
        auto negative=change("\"fresh_proof\":true","\"fresh_proof\":false");
        negative.replace(negative.find("verified"),8,reason);
        negative.replace(negative.find("9000"),4,"1000");
        const auto result=decode(negative,1000,6000);
        check(result && !result->fresh_proof && result->reason==reason && result->deadline_ms==1000,
              "negative observation allows stale authority without readiness");
        check(!decode(negative,1200,6000),"negative observed time must be in actual span");
    }
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
        const auto name = std::wstring(orangespace::install_identity::pipe_prefix) + std::to_wstring(*session);
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
        SC_HANDLE service = OpenServiceW(scm, orangespace::install_identity::service_name, SERVICE_QUERY_STATUS);
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
