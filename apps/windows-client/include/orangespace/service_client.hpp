#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <charconv>
#include <limits>
#include <optional>
#include <span>
#include <string_view>
#include <type_traits>
#include "orangespace/service_chain.hpp"
#include "orangespace/platform_session.hpp"
namespace orangespace::service_client {
namespace chain = service::chain;
inline chain::Binding validate_binding(const json::Value& value) {
    namespace nd = node_session::detail;
    nd::object(value,5);
    chain::Binding b{nd::text(nd::field(value,"user_id")),nd::text(nd::field(value,"sandbox_id")),
      nd::text(nd::field(value,"node_id")),nd::text(nd::field(value,"tunnel_id")),
      static_cast<std::uint64_t>(nd::integer(nd::field(value,"generation")))};
    nd::require(nd::uuid(b.user)&&nd::uuid(b.sandbox)&&nd::uuid(b.node)&&nd::uuid(b.tunnel));
    return b;
}
inline void validate_proof(const json::Value& v) {
    namespace nd = node_session::detail;
    nd::require(nd::field(v,"process_started").is_true() && nd::field(v,"tunnel_authenticated").is_true() && nd::field(v,"forwarding_verified").is_true());
}
struct ExpectedReply {
    std::string auth, user, node;
    std::optional<chain::Cursor> prior;
};
inline std::optional<json::Value> validate_chain_frame(std::span<const std::uint8_t> bytes, chain::Op op,const ExpectedReply& expected={}) {
    namespace nd = node_session::detail;
    try {
        nd::require(bytes.size()>=4 && bytes.size()<=65540);
        std::uint32_t length=0;
        for(unsigned i=0;i<4;++i) length |= std::uint32_t(bytes[i])<<(8*i);
        nd::require(length==bytes.size()-4);
        const auto text=std::string_view(reinterpret_cast<const char*>(bytes.data()+4),length);
        nd::require(nd::safe_utf8(text));
        if(op==chain::Op::diagnose) nd::exact_wire_integers(text);
        auto root=json::parse(text);
        nd::require(nd::field(root,"ok").is_true());
        const auto* allowed=std::get_if<bool>(&nd::field(root,"browser_allowed").data);
        nd::require(allowed && !*allowed);
        if(op==chain::Op::diagnose) {
            nd::object(root,9);
            (void)validate_binding(nd::field(root,"binding"));
            (void)nd::integer(nd::field(root,"server_expiry"));
            (void)nd::integer(nd::field(root,"deadline_ms"));
            (void)nd::integer(nd::field(root,"observed_at_ms"),0);
            nd::require(nd::text(nd::field(root,"clock"))==nd::lease_clock);
            const auto* fresh=std::get_if<bool>(&nd::field(root,"fresh_proof").data);
            const auto& reason=nd::text(nd::field(root,"reason"));
            nd::require(fresh && ((*fresh && reason=="verified") || (!*fresh &&
                (reason=="probe_unavailable" || reason=="probe_deadline" || reason=="stale_authority"))));
        }
        else if(op==chain::Op::logout || op==chain::Op::retire) nd::object(root,2);
        else if(op==chain::Op::stop || (op==chain::Op::status && root.find("sandbox_id"))) {
            nd::object(root,op==chain::Op::stop ? 4 : 5);
            nd::require(nd::uuid(nd::text(nd::field(root,"sandbox_id"))));
            (void)nd::integer(nd::field(root,"generation"),0);
            if(op==chain::Op::status) nd::require(nd::uuid(nd::text(nd::field(root,"auth_id"))));
        }
        else {
            nd::require(nd::uuid(nd::text(nd::field(root,"auth_id"))));
            if(op==chain::Op::start) { nd::object(root,7); (void)validate_binding(nd::field(root,"binding")); validate_proof(root); }
            else {
                nd::object(root,6);
                nd::require(nd::uuid(nd::text(nd::field(root,"user_id"))) && nd::uuid(nd::text(nd::field(root,"node_id"))));
                const auto* tunnels=std::get_if<json::Value::Array>(&nd::field(root,"tunnels").data);
                nd::require(tunnels && tunnels->size()<=64);
                for(const auto& item:*tunnels) {
                    nd::object(item,4); auto b=validate_binding(nd::field(item,"binding")); validate_proof(item);
                    nd::require(b.user==nd::text(nd::field(root,"user_id")) && b.node==nd::text(nd::field(root,"node_id")));
                }
            }
        }
        if(!expected.auth.empty() && root.find("auth_id"))
            nd::require(nd::text(nd::field(root,"auth_id"))==expected.auth);
        if(op==chain::Op::start) {
            const auto b=validate_binding(nd::field(root,"binding"));
            if(!expected.user.empty())nd::require(b.user==expected.user && b.node==expected.node);
            if(expected.prior)nd::require(b.sandbox==expected.prior->sandbox && b.generation>expected.prior->generation);
        } else if(op==chain::Op::authorize || (op==chain::Op::status && root.find("user_id"))) {
            if(!expected.user.empty())nd::require(nd::text(nd::field(root,"user_id"))==expected.user && nd::text(nd::field(root,"node_id"))==expected.node);
            if(op==chain::Op::authorize)nd::require(std::get<json::Value::Array>(nd::field(root,"tunnels").data).empty());
        } else if(expected.prior && (op==chain::Op::stop || op==chain::Op::status)) {
            nd::require(nd::text(nd::field(root,"sandbox_id"))==expected.prior->sandbox);
            const auto generation=static_cast<std::uint64_t>(nd::integer(nd::field(root,"generation"),0));
            nd::require(op==chain::Op::stop ? generation>expected.prior->generation : generation>=expected.prior->generation);
        }
        return root;
    } catch (...) { return {}; }
}
// Browser OSP3 observations are not authority. The Service authenticates the
// complete Grant + Binding; the client rejects foreign/stale presentation data.
inline bool valid_browser_url(std::string_view url) {
    if(url.empty() || url.size()>2048 || !node_session::detail::safe_utf8(url,true))return false;
    if(!url.starts_with("https://") && !url.starts_with("http://"))return false;
    const auto start=url.find("://")+3;
    if(start==url.size() || url[start]=='/' || url[start]=='?' || url[start]=='#')return false;
    for(unsigned char c:url)if(c<=32 || c==127 || c=='\\')return false;
    return true;
}
struct BrowserBirthToken { std::size_t begin{},end{};std::uint64_t value{}; };
inline BrowserBirthToken browser_birth_token(std::string_view text) {
    namespace nd=node_session::detail;
    // Skip complete JSON strings, not substring matches inside URL/title text.
    for(std::size_t i=0;i<text.size();) {
        if(text[i++]!='"')continue;
        const auto start=i-1;
        while(i<text.size()) {const char c=text[i++];if(c=='\\') {nd::require(i<text.size());++i;}else if(c=='"')break;}
        if(text.substr(start,i-start)!="\"process_birth\"")continue;
        while(i<text.size() && (text[i]==' ' || text[i]=='\t' || text[i]=='\r' || text[i]=='\n'))++i;
        if(i==text.size() || text[i]!=':')continue; // value string, not a key
        ++i;
        while(i<text.size() && (text[i]==' ' || text[i]=='\t' || text[i]=='\r' || text[i]=='\n'))++i;
        const auto begin=i;while(i<text.size() && text[i]>='0' && text[i]<='9')++i;
        nd::require(i>begin && (i-begin==1 || text[begin]!='0'));
        std::uint64_t value{};const auto parsed=std::from_chars(text.data()+begin,text.data()+i,value);
        nd::require(parsed.ec==std::errc{} && parsed.ptr==text.data()+i);
        return {begin,i,value};
    }
    nd::require(false);return {};
}
inline std::uint64_t browser_wire_birth(std::string_view text) {return browser_birth_token(text).value;}
inline std::optional<json::Value> validate_browser_reply(std::string_view text,const chain::Binding& expected) {
    namespace nd=node_session::detail;
    try {
        nd::require(text.size()<=32768 && nd::safe_utf8(text));
        const auto birth=browser_birth_token(text);
        // FILETIME is an exact uint64 wire integer, often above the DOM double
        // range. Never round it through json::Value; all other integers retain
        // the shared exact-wire restriction.
        std::string numeric(text);numeric.replace(birth.begin,birth.end-birth.begin,"0");
        nd::exact_wire_integers(numeric);
        auto root=json::parse(text);nd::object(root,3);
        nd::require(nd::integer(nd::field(root,"schema"))==1 && nd::field(root,"ok").is_true());
        const auto& b=nd::field(root,"browser");nd::object(b,14);
        const auto phase=nd::integer(nd::field(b,"phase"),0);nd::require(phase<=4);
        nd::require(nd::text(nd::field(b,"sandbox"))==expected.sandbox &&
            nd::text(nd::field(b,"node"))==expected.node &&
            static_cast<std::uint64_t>(nd::integer(nd::field(b,"generation")))==expected.generation);
        const auto pid=nd::integer(nd::field(b,"process_id"),0);nd::require(pid<=std::numeric_limits<std::uint32_t>::max());
        for(auto key:{"loading","can_go_back","can_go_forward"})nd::require(std::get_if<bool>(&nd::field(b,key).data)!=nullptr);
        for(auto key:{"package_sid","profile_name","url","title","error"}) {
            const auto& value=nd::text(nd::field(b,key));
            nd::require(value.size()<=((std::string_view(key)=="url" || std::string_view(key)=="title")?2048u:256u) && nd::safe_utf8(value));
        }
        if(phase>=1 && phase<=3) {
            nd::require(pid>0 && birth.value>0);
            const auto& sid=nd::text(nd::field(b,"package_sid"));
            nd::require(sid.starts_with("S-1-15-2-"));
            const auto& profile=nd::text(nd::field(b,"profile_name"));
            nd::require(!profile.empty() && profile.size()<=64);
        }
        return root;
    } catch (...) {return {};}
}
// A completed observation, never a BrowserPermit or browser-readiness result.
struct TunnelDiagnosticDTO {
    chain::Binding binding;
    std::int64_t server_expiry{}, deadline_ms{}, observed_at_ms{};
    std::string clock;
    bool fresh_proof{};
    std::string reason;
};
static_assert(std::is_nothrow_move_constructible_v<TunnelDiagnosticDTO>);
static_assert(std::is_nothrow_destructible_v<TunnelDiagnosticDTO>);
// Transport must construct this final typed owner BEFORE sending its ACK.
inline std::optional<TunnelDiagnosticDTO> decode_tunnel_diagnostic(
    std::span<const std::uint8_t> bytes, const chain::Binding& expected,
    std::int64_t request_started_ms, std::int64_t received_ms) {
    namespace nd = node_session::detail;
    try {
        nd::require(request_started_ms>=0 && request_started_ms<=received_ms &&
                    received_ms<=nd::max_exact_integer);
        auto root=validate_chain_frame(bytes,chain::Op::diagnose);
        nd::require(root.has_value());
        auto binding=validate_binding(nd::field(*root,"binding"));
        nd::require(binding.user==expected.user && binding.sandbox==expected.sandbox &&
            binding.node==expected.node && binding.tunnel==expected.tunnel && binding.generation==expected.generation);
        TunnelDiagnosticDTO result{std::move(binding),nd::integer(nd::field(*root,"server_expiry")),
            nd::integer(nd::field(*root,"deadline_ms")),nd::integer(nd::field(*root,"observed_at_ms"),0),
            nd::text(nd::field(*root,"clock")),std::get<bool>(nd::field(*root,"fresh_proof").data),
            nd::text(nd::field(*root,"reason"))};
        nd::require(request_started_ms<=result.observed_at_ms && result.observed_at_ms<=received_ms);
        // Ordered, bounded samples make subtraction safe; never re-anchor at receipt.
        if(result.fresh_proof)nd::require(received_ms<result.deadline_ms && received_ms-request_started_ms<5000);
        return result;
    } catch (...) {return {};}
}
// Both alternatives are fully allocated before ACK. Its completion can only
// select a nothrow move; a slow ACK must not make a stale proof look current.
inline TunnelDiagnosticDTO finish_tunnel_diagnostic(TunnelDiagnosticDTO&& observed,
    TunnelDiagnosticDTO&& expired,std::int64_t started,std::uint64_t completed) noexcept {
    if(observed.fresh_proof && (started<0 || observed.deadline_ms<=0 ||
        completed<static_cast<std::uint64_t>(started) ||
        completed>=static_cast<std::uint64_t>(observed.deadline_ms) ||
        completed-static_cast<std::uint64_t>(started)>=5000))return std::move(expired);
    return std::move(observed);
}
// Select only an explicit raw-frame preparation path; legacy callbacks keep
// receiving the validated DOM. Both construct the final owner before ACK.
template<bool RawFrame=false,class Prepare>
auto prepare_chain_result(const json::Value& root,std::span<const std::uint8_t> raw,Prepare&& prepare) {
    if constexpr(RawFrame)return std::forward<Prepare>(prepare)(raw);
    else return std::forward<Prepare>(prepare)(root);
}
#ifdef _WIN32
class Grant {
    std::string id_, user_, node_;
    std::string central_user_;
    unsigned protocol_{2};
    Grant(std::string id,std::string user,std::string node):id_(std::move(id)),user_(std::move(user)),node_(std::move(node)){}
    friend Grant authorize(std::string_view,const node_session::NodeSession&);
    friend Grant authorize_platform(const platform_session::Session&,const platform_session::NodeRef&);
public:
    Grant(const Grant&) = default;
    Grant(Grant&&) noexcept = default;
    Grant& operator=(const Grant&) = delete;
    Grant& operator=(Grant&&) = delete;
    const std::string& id() const noexcept {return id_;}
    const std::string& user() const noexcept {return user_;}
    const std::string& node() const noexcept {return node_;}
    const std::string& central_user() const noexcept {return central_user_;}
    unsigned protocol() const noexcept {return protocol_;}
};
using AuthGrant = Grant;
TunnelDiagnosticDTO diagnose_tunnel(const AuthGrant&,const chain::Binding&);
Grant authorize_platform(const platform_session::Session&,const platform_session::NodeRef&);
chain::Cursor register_sandbox(const Grant&,std::string_view localSandboxUUID);
chain::Binding start_registered_tunnel(const Grant&,std::string_view localSandboxUUID);
Grant authorize(std::string_view alias,const node_session::NodeSession& session);
chain::Binding start_tunnel(const Grant&,std::optional<chain::Cursor> prior = {});
chain::Cursor stop_tunnel(const Grant&,const chain::Binding& expected);
chain::Cursor sandbox_cursor(const Grant&,std::string_view service_sandbox);
void logout(const Grant&);
// Local helper/grant retirement only; saved API login remains valid.
void retire(const Grant&);
void check_status(const Grant&);
std::vector<chain::Binding> active_tunnels(const Grant&);
#endif
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
