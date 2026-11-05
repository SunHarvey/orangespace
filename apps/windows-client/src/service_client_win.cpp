#include "orangespace/install_identity.hpp"
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include "orangespace/service_client.hpp"
#include "orangespace/browser_session.hpp"
#include "orangespace/platform_protocol.hpp"
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
bool transfer(HANDLE pipe, HANDLE process, void* buffer, DWORD capacity, bool write, DWORD& count, DWORD timeout = timeout_ms) {
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event) return false;
    OVERLAPPED operation{};
    operation.hEvent = event.get();
    const BOOL complete = write ? WriteFile(pipe, buffer, capacity, &count, &operation)
                                : ReadFile(pipe, buffer, capacity, &count, &operation);
    if (complete) return alive(process);
    if (GetLastError() != ERROR_IO_PENDING) return false;
    HANDLE waits[]{process, event.get()};
    if (WaitForMultipleObjects(2, waits, FALSE, timeout) != WAIT_OBJECT_0 + 1) {
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
namespace {
template<bool RawFrame=false,class Prepare>
auto exchange(chain::Op op, std::string_view payload,const ExpectedReply& expected,Prepare&& prepare,unsigned protocol=2) {
    struct WipedFrame {
        std::vector<std::uint8_t> bytes;
        ~WipedFrame() { node_session::detail::wipe(bytes.data(),bytes.size()); }
    } storage{chain::request_frame(op,payload)};
    auto& request=storage.bytes;
    node_session::detail::require(protocol==2||protocol==3);
    request[3]=protocol==3?'3':'2';
        // NULL machine/database selects local SCM; never accepts caller-selected names.
        ServiceHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        if (!scm) throw std::runtime_error("authenticated service IPC failed");
        ServiceHandle service(OpenServiceW(scm.get(), orangespace::install_identity::service_name, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS));
        if (!service) throw std::runtime_error("authenticated service IPC failed");
        const auto session = current_interactive_session();
        if (!session) throw std::runtime_error("authenticated service IPC failed");
        const auto initial = snapshot(service.get());
        if (!initial || !valid_server_binding(*initial, initial->pid, true)) throw std::runtime_error("authenticated service IPC failed");
        Handle process(OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, initial->pid));
        if (!process || !alive(process.get())) throw std::runtime_error("authenticated service IPC failed");
        const auto name = std::wstring(orangespace::install_identity::pipe_prefix) + std::to_wstring(*session);
        const ULONGLONG deadline = GetTickCount64() + timeout_ms;
        HANDLE raw = INVALID_HANDLE_VALUE;
        do {
            raw = CreateFileW(name.c_str(), client_rights, 0, nullptr, OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION, nullptr);
            if (raw != INVALID_HANDLE_VALUE) break;
            if (GetLastError() != ERROR_PIPE_BUSY || !alive(process.get()) || GetTickCount64() >= deadline)
                throw std::runtime_error("authenticated service IPC failed");
            Sleep(10);
        } while (true);
        Handle pipe(raw);
        DWORD mode = PIPE_READMODE_MESSAGE;
        if (!SetNamedPipeHandleState(pipe.get(), &mode, nullptr, nullptr)) throw std::runtime_error("authenticated service IPC failed");
        // Re-read config + SCM status AFTER connect and compare actual server PID BEFORE bytes.
        if (!bound(service.get(), process.get(), pipe.get(), initial->pid)) throw std::runtime_error("authenticated service IPC failed");

        DWORD count{};
        if (!transfer(pipe.get(), process.get(), request.data(), static_cast<DWORD>(request.size()), true, count) || count != request.size())
            throw std::runtime_error("authenticated service IPC failed");
        std::array<std::uint8_t, 65540> response{};
        if (!transfer(pipe.get(), process.get(), response.data(), static_cast<DWORD>(response.size()), false, count, 90000)) throw std::runtime_error("authenticated service IPC failed");
        const DWORD response_size=count;
        if (!bound(service.get(), process.get(), pipe.get(), initial->pid)) throw std::runtime_error("authenticated service IPC failed");
        // Strict schema, identity and prior cursor checks precede ownership ACK.
        auto root=[&]() -> std::optional<json::Value> {
            if(static_cast<unsigned>(op)!=9)return validate_chain_frame(std::span<const std::uint8_t>(response.data(),response_size),static_cast<unsigned>(op)==7?chain::Op::stop:op,expected);
            node_session::detail::require(protocol==3 && expected.prior.has_value() && response_size>=4);
            std::uint32_t length{};for(unsigned i=0;i<4;++i)length|=std::uint32_t(response[i])<<(8*i);
            node_session::detail::require(length==response_size-4);
            return validate_browser_reply(std::string_view(reinterpret_cast<const char*>(response.data()+4),length),
                chain::Binding{expected.user,expected.prior->sandbox,expected.node,{},expected.prior->generation});
        }();
        if(!root)throw std::runtime_error("service authorization rejected");
        // Build the FINAL caller-owned type, not merely an owning JSON tree.
        // Every decode/copy/relationship check and allocation precedes ACK.
        auto result=prepare_chain_result<RawFrame>(*root,std::span<const std::uint8_t>(response.data(),response_size),std::forward<Prepare>(prepare));
        static_assert(std::is_nothrow_move_constructible_v<decltype(result)>);
        static_assert(std::is_nothrow_destructible_v<decltype(result)>);
        std::uint8_t ack = 6;
        if (!transfer(pipe.get(), process.get(), &ack, 1, true, count) || count != 1) throw std::runtime_error("authenticated service IPC failed");
        // No fallible validation after adoption. SCM/process/pipe were bound
        // immediately before parsing, while the retained server object was live.
        return result;
}
std::string auth_payload(const Grant& g) { return "{\"auth_id\":"+chain::quote(g.id())+"}"; }
void matching(const Grant& g,const json::Value& r) {
    namespace nd=node_session::detail;
    nd::require(nd::text(nd::field(r,"auth_id"))==g.id());
    nd::require(nd::text(nd::field(r,"user_id"))==g.user() && nd::text(nd::field(r,"node_id"))==g.node());
}
}
Grant authorize(std::string_view alias,const node_session::NodeSession& session) {
    chain::Text envelope(session.credential_envelope());
    chain::Text payload("{\"alias\":"+chain::quote(alias)+",\"envelope\":"+envelope.value+"}");
    return exchange(chain::Op::authorize,payload.value,ExpectedReply{{},session.identity().user_id,session.identity().node_id,{}},[](const json::Value& r) {
      namespace nd=node_session::detail;
      return Grant(nd::text(nd::field(r,"auth_id")),nd::text(nd::field(r,"user_id")),nd::text(nd::field(r,"node_id")));
    });
}
Grant authorize_platform(const platform_session::Session& session,const platform_session::NodeRef& node) {
    auto envelope=session.export_envelope();
    chain::Text payload;
    payload.value="{\"envelope\":"+chain::quote(envelope.view())+",\"node\":"+service::platform::node_json(node)+"}";
    return exchange(chain::Op::authorize,payload.value,ExpectedReply{{},node.remote_legacy_user_id,node.node_id,{}},[&](const json::Value& r){
      namespace nd=node_session::detail;
      Grant g(nd::text(nd::field(r,"auth_id")),nd::text(nd::field(r,"user_id")),nd::text(nd::field(r,"node_id")));
      g.central_user_=session.identity().central_user_id;g.protocol_=3;return g;
    },3);
}
chain::Cursor register_sandbox(const Grant& g,std::string_view sandbox) {
    namespace nd=node_session::detail;nd::require(g.protocol()==3&&nd::uuid(sandbox));
    const auto payload="{\"auth_id\":"+chain::quote(g.id())+",\"sandbox_id\":"+chain::quote(sandbox)+"}";
    return exchange(static_cast<chain::Op>(7),payload,{},[&](const json::Value& r){
      nd::require(nd::text(nd::field(r,"sandbox_id"))==sandbox);
      return chain::Cursor{nd::text(nd::field(r,"sandbox_id")),static_cast<std::uint64_t>(nd::integer(nd::field(r,"generation"),0))};
    },3);
}
chain::Binding start_registered_tunnel(const Grant& g,std::string_view sandbox) {return start_tunnel(g,register_sandbox(g,sandbox));}
chain::Binding start_tunnel(const Grant& g,std::optional<chain::Cursor> prior) {
    node_session::detail::require(g.protocol()!=3||prior.has_value());
    auto payload=auth_payload(g);
    if(prior) {
      node_session::detail::require(node_session::detail::uuid(prior->sandbox));
      payload.pop_back(); payload+=",\"sandbox_id\":"+chain::quote(prior->sandbox)+",\"expected_generation\":"+std::to_string(prior->generation)+"}";
    }
    return exchange(chain::Op::start,payload,ExpectedReply{g.id(),g.user(),g.node(),prior},[](const json::Value& r) {
      return validate_binding(node_session::detail::field(r,"binding"));
    },g.protocol());
}
chain::Cursor stop_tunnel(const Grant& g,const chain::Binding& b) {
    namespace nd=node_session::detail;
    nd::require(nd::uuid(b.sandbox) && b.user==g.user() && b.node==g.node());
    return exchange(chain::Op::stop,"{\"auth_id\":"+chain::quote(g.id())+",\"sandbox_id\":"+chain::quote(b.sandbox)+",\"expected_generation\":"+std::to_string(b.generation)+"}",ExpectedReply{g.id(),g.user(),g.node(),chain::Cursor{b.sandbox,b.generation}},[](const json::Value& r) {
      return chain::Cursor{nd::text(nd::field(r,"sandbox_id")),static_cast<std::uint64_t>(nd::integer(nd::field(r,"generation")))};
    },g.protocol());
}
chain::Cursor sandbox_cursor(const Grant& g,std::string_view sandbox) {
    namespace nd=node_session::detail; nd::require(nd::uuid(sandbox));
    return exchange(chain::Op::status,"{\"auth_id\":"+chain::quote(g.id())+",\"sandbox_id\":"+chain::quote(sandbox)+"}",ExpectedReply{g.id(),g.user(),g.node(),chain::Cursor{std::string(sandbox),0}},[](const json::Value& r) {
      return chain::Cursor{nd::text(nd::field(r,"sandbox_id")),static_cast<std::uint64_t>(nd::integer(nd::field(r,"generation"),0))};
    },g.protocol());
}
void logout(const Grant& g) { (void)exchange(chain::Op::logout,auth_payload(g),{},[](const json::Value&){return true;},g.protocol()); }
void retire(const Grant& g) { (void)exchange(chain::Op::retire,auth_payload(g),{},[](const json::Value&){return true;},g.protocol()); }
std::vector<chain::Binding> active_tunnels(const Grant& g) {
    return exchange(chain::Op::status,auth_payload(g),ExpectedReply{g.id(),g.user(),g.node(),{}},[&](const json::Value& response) {
      matching(g,response);
      const auto& array=std::get<json::Value::Array>(node_session::detail::field(response,"tunnels").data);
      std::vector<chain::Binding> result;
      for(const auto& item:array) result.push_back(validate_binding(node_session::detail::field(item,"binding")));
      return result;
    },g.protocol());
}
void check_status(const Grant& g) { (void)active_tunnels(g); }
TunnelDiagnosticDTO diagnose_tunnel(const AuthGrant& g,const chain::Binding& binding) {
    namespace nd=node_session::detail;
    nd::require(binding.user==g.user() && binding.node==g.node() && nd::uuid(binding.user) &&
        nd::uuid(binding.node) && nd::uuid(binding.sandbox) && nd::uuid(binding.tunnel) &&
        binding.generation>0 && binding.generation<=static_cast<std::uint64_t>(nd::max_exact_integer));
    const auto started=nd::monotonic_ms();
    chain::Text payload("{\"auth_id\":"+chain::quote(g.id())+",\"binding\":"+chain::binding_json(binding)+"}");
    TunnelDiagnosticDTO expired;
    auto observed=exchange<true>(chain::Op::diagnose,payload.value,ExpectedReply{g.id(),g.user(),g.node(),{}},
        [&](std::span<const std::uint8_t> raw) {
            auto result=decode_tunnel_diagnostic(raw,binding,started,nd::monotonic_ms());
            nd::require(result.has_value());
            if(result->fresh_proof) {
                expired=*result;
                expired.fresh_proof=false;expired.reason="probe_deadline";
            }
            return std::move(*result);
        },g.protocol());
    return finish_tunnel_diagnostic(std::move(observed),std::move(expired),started,GetTickCount64());
}

StatusResult query_foundation_status() noexcept {
    try {
        // NULL machine/database selects local SCM; never accepts caller-selected names.
        ServiceHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        if (!scm) return failure(ClientError::scm_rejected);
        ServiceHandle service(OpenServiceW(scm.get(), orangespace::install_identity::service_name, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS));
        if (!service) return failure(GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST ? ClientError::service_missing : ClientError::scm_rejected);
        const auto session = current_interactive_session();
        if (!session) return failure(ClientError::session_rejected);
        const auto initial = snapshot(service.get());
        if (!initial || !valid_server_binding(*initial, initial->pid, true)) return failure(ClientError::service_rejected);
        Handle process(OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, initial->pid));
        if (!process || !alive(process.get())) return failure(ClientError::process_rejected);
        const auto name = std::wstring(orangespace::install_identity::pipe_prefix) + std::to_wstring(*session);
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
namespace orangespace::browser_session {
State exchange(const service_client::Grant& g,const service::chain::Binding& b,Command command,std::string_view url) {
    namespace nd=node_session::detail;namespace sc=service_client;namespace ch=service::chain;
    nd::require(g.protocol()==3 && b.user==g.user() && b.node==g.node() &&
        nd::uuid(b.user) && nd::uuid(b.node) && nd::uuid(b.sandbox) && nd::uuid(b.tunnel) &&
        b.generation>0 && b.generation<=static_cast<std::uint64_t>(nd::max_exact_integer));
    nd::require(static_cast<unsigned>(command)<=6);
    nd::require(command==Command::navigate ? sc::valid_browser_url(url) : url.empty());
    const auto payload="{\"auth_id\":"+ch::quote(g.id())+",\"binding\":"+ch::binding_json(b)+
        ",\"command\":"+std::to_string(static_cast<unsigned>(command))+",\"url\":"+ch::quote(url)+"}";
    return sc::exchange<true>(static_cast<ch::Op>(9),payload,sc::ExpectedReply{g.id(),g.user(),g.node(),ch::Cursor{b.sandbox,b.generation}},
        [&](std::span<const std::uint8_t> raw) {
            const auto text=std::string_view(reinterpret_cast<const char*>(raw.data()+4),raw.size()-4);
            auto root=sc::validate_browser_reply(text,b);nd::require(root.has_value());
            const auto& v=nd::field(*root,"browser");State result;
            result.phase=static_cast<Phase>(nd::integer(nd::field(v,"phase"),0));
            result.sandbox=nd::text(nd::field(v,"sandbox"));result.node=nd::text(nd::field(v,"node"));
            result.package_sid=nd::text(nd::field(v,"package_sid"));result.profile_name=nd::text(nd::field(v,"profile_name"));
            result.url=nd::text(nd::field(v,"url"));result.title=nd::text(nd::field(v,"title"));result.error=nd::text(nd::field(v,"error"));
            result.generation=b.generation;result.process_birth=sc::browser_wire_birth(text);
            result.process_id=static_cast<std::uint32_t>(nd::integer(nd::field(v,"process_id"),0));
            result.loading=std::get<bool>(nd::field(v,"loading").data);
            result.can_go_back=std::get<bool>(nd::field(v,"can_go_back").data);
            result.can_go_forward=std::get<bool>(nd::field(v,"can_go_forward").data);
            return result;
        },3);
}
}
