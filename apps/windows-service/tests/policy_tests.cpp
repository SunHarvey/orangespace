#include "orangespace/service_policy.hpp"
#include <cstdlib>
#include <iostream>
#ifdef _WIN32
// Exercise the same stateful publisher used by the service.
#include "orangespace/process_observation_acl.hpp"
using namespace orangespace::service;
using namespace orangespace::service::win;
void require_acl(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
std::vector<BYTE> process_descriptor() {
    DWORD needed{};
    constexpr auto info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    GetKernelObjectSecurity(GetCurrentProcess(), info, nullptr, 0, &needed);
    std::vector<BYTE> bytes(needed);
    require_acl(needed && GetKernelObjectSecurity(GetCurrentProcess(), info, bytes.data(), needed, &needed), "read process descriptor");
    return bytes;
}
void install_test_dacl(const std::string& sddl) {
    PSECURITY_DESCRIPTOR sd{};
    require_acl(ConvertStringSecurityDescriptorToSecurityDescriptorA(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr), "test SDDL");
    const bool ok = SetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION, sd);
    LocalFree(sd);
    require_acl(ok, "install test DACL");
}
bool access_check(DWORD right) {
    auto sd = process_descriptor();
    HANDLE raw{}, duplicate{};
    require_acl(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &raw), "open token");
    const Handle token(raw);
    require_acl(DuplicateToken(token.get(), SecurityImpersonation, &duplicate), "duplicate token");
    const Handle impersonation(duplicate);
    GENERIC_MAPPING mapping{PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | READ_CONTROL,
                            PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | READ_CONTROL,
                            SYNCHRONIZE | READ_CONTROL, PROCESS_ALL_ACCESS};
    PRIVILEGE_SET privileges{};
    DWORD size = sizeof(privileges), granted{};
    BOOL allowed{};
    require_acl(AccessCheck(sd.data(), impersonation.get(), right, &mapping, &privileges, &size, &granted, &allowed), "AccessCheck");
    return allowed != FALSE;
}
void observation_acl_tests() {
    const auto original = process_descriptor();
    struct Restore { const std::vector<BYTE>& sd; ~Restore() { SetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION, const_cast<BYTE*>(sd.data())); } } restore{original};
    const auto peer = current_peer();
    install_test_dacl("D:P(D;;0x1;;;BA)(A;;0x1ffffe;;;SY)(A;;0x10;;;WD)(A;;0x60000;;;BA)");
    require_acl(!access_check(PROCESS_TERMINATE) && access_check(PROCESS_VM_READ), "baseline denial/unrelated allow fixture");
    const auto baseline = process_descriptor();
    ProcessObservationAcl publisher;
    publisher.publish({{peer.session, peer}});
    require_acl(!access_check(PROCESS_TERMINATE), "FAIL: publication weakened baseline BA PROCESS_TERMINATE deny");
    require_acl(access_check(PROCESS_VM_READ), "FAIL: publication discarded unrelated allow");
    std::cout << "PASS: native AccessCheck baseline deny and unrelated allow survive publication\n";
    require_acl(access_check(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE), "managed observation grant missing");
    const auto published = process_descriptor();
    publisher.publish({{peer.session, peer}, {999, peer}});
    require_acl(process_descriptor() == published, "same user SID across sessions must not duplicate grants");
    publisher.publish({{peer.session, peer}});
    require_acl(process_descriptor() == published, "unchanged peers must be byte-idempotent");
    auto other = peer;
    other.sid = "S-1-5-21-10-20-30-1002";
    publisher.publish({{peer.session, peer}, {999, other}});
    require_acl(access_check(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE), "adding peer lost current grant");
    publisher.publish({{999, other}});
    require_acl(!access_check(PROCESS_QUERY_LIMITED_INFORMATION) && !access_check(SYNCHRONIZE), "removed managed grant accumulated");
    require_acl(!access_check(PROCESS_TERMINATE) && access_check(PROCESS_VM_READ), "peer removal changed baseline policy");
    publisher.publish({});
    // This baseline is captured after installation, before any managed grant.
    // Whole-descriptor equality additionally checks owner/group/control and ACE bytes.
    require_acl(process_descriptor() == baseline, "empty peers must restore exact original descriptor");
    std::cout << "PASS: peer add/remove, baseline exact restoration, byte-idempotence\n";
    publisher.publish({{peer.session, peer}});
    install_test_dacl("D:P(D;;0x1;;;BA)(A;;0x60000;;;BA)");
    const auto drift = process_descriptor();
    bool rejected = false;
    try { publisher.publish({}); } catch (const std::exception&) { rejected = true; }
    require_acl(rejected && process_descriptor() == drift, "external DACL drift must fail closed without overwrite");
    rejected = false;
    try { publisher.publish({{peer.session, peer}}); } catch (const std::exception&) { rejected = true; }
    require_acl(rejected && process_descriptor() == drift, "drift publisher must remain poisoned");
    std::cout << "PASS: external DACL drift fails closed without overwriting external policy\n";
    install_test_dacl("D:P(A;;0x60000;;;BA)(A;;0x1000;;;" + peer.sid + ")");
    const auto same_sid_baseline = process_descriptor();
    ProcessObservationAcl same_sid;
    same_sid.publish({{peer.session, peer}});
    require_acl(access_check(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE), "same SID observation missing");
    same_sid.publish({});
    require_acl(access_check(PROCESS_QUERY_LIMITED_INFORMATION) && !access_check(SYNCHRONIZE), "removal changed baseline same-SID rights");
    require_acl(process_descriptor() == same_sid_baseline, "baseline same-SID ACE was not preserved exactly");
    std::cout << "PASS: baseline same-SID query grant survives removal of managed synchronize grant\n";
    for (const char* prefix : {"D:P", "D:", "D:PAI", "D:PAR"}) {
        install_test_dacl(std::string(prefix) + "(A;;0x60000;;;BA)(A;;0x10;;;WD)(D;ID;0x1000;;;BA)");
        require_acl(!access_check(PROCESS_QUERY_LIMITED_INFORMATION), "inherited query deny baseline fixture");
        const auto denied_baseline = process_descriptor();
        ProcessObservationAcl inherited;
        inherited.publish({{peer.session, peer}});
        require_acl(!access_check(PROCESS_QUERY_LIMITED_INFORMATION), "appended allow bypassed inherited query deny");
        require_acl(access_check(SYNCHRONIZE), "non-denied managed synchronize right missing");
        require_acl(access_check(PROCESS_VM_READ), "inherited deny case lost unrelated allow");
        inherited.publish({});
        require_acl(process_descriptor() == denied_baseline, "inherited deny/control restoration differs");
    }
    std::cout << "PASS: inherited query deny remains effective in actual AccessCheck; protected/unprotected control preserved\n";
    for (const char* unsupported : {"D:NO_ACCESS_CONTROL", "D:P(OA;;0x10;00000000-0000-0000-0000-000000000001;;WD)(A;;0x60000;;;BA)"}) {
        install_test_dacl(unsupported);
        const auto unsupported_baseline = process_descriptor();
        rejected = false;
        try { ProcessObservationAcl invalid; invalid.publish({{peer.session, peer}}); }
        catch (const std::exception&) { rejected = true; }
        require_acl(rejected && process_descriptor() == unsupported_baseline, "unsupported/null DACL must not widen");
    }
    std::cout << "PASS: null and object-specific unsupported DACL rejected without mutation\n";
}
#endif
using namespace orangespace::service;
int main() {
#ifdef _WIN32
    try { observation_acl_tests(); }
    catch (const std::exception& e) { std::cerr << e.what() << '\n'; return EXIT_FAILURE; }
#endif
    const Peer expected{"S-1-5-21-10-20-30-1001", 7, 42};
    const std::optional<Peer> token(expected);
    if (!eligible_session(4, 7, token)) {
        std::cerr << "FAIL: validated logged-on Disconnected token must retain background IPC\n";
        return EXIT_FAILURE;
    }
    if (!eligible_session(0, 7, token)) return EXIT_FAILURE;
    for (std::uint32_t state : {1u, 2u, 3u, 5u, 6u, 7u, 8u, 9u, 10u, 0xffffffffu})
        if (eligible_session(state, 7, token)) return EXIT_FAILURE;
    if (eligible_session(4, 0, token) || eligible_session(4, 8, token) ||
        eligible_session(4, 7, std::optional<Peer>{})) return EXIT_FAILURE;
    for (auto bad : {Peer{"",7,42}, Peer{"S-1-5-18",7,42}, Peer{expected.sid,7,0},
                     Peer{expected.sid,0,42}, Peer{"S-1-5-21-1)(A;;GA;;;WD)",7,42}})
        if (eligible_session(4, 7, std::optional<Peer>(bad))) return EXIT_FAILURE;
    std::cout << "PASS: Active/Disconnected require validated OS token; zero/transitional/logoff denied\n";
    if (!authorize_peer(expected, expected)) {
        std::cerr << "FAIL: exact OS peer identity must be accepted\n";
        return EXIT_FAILURE;
    }
    auto other = expected;
    other.sid = "S-1-5-21-10-20-30-1002";
    if (authorize_peer(expected, other)) return EXIT_FAILURE;
    other = expected; other.session = 8;
    if (authorize_peer(expected, other)) return EXIT_FAILURE;
    other = expected; other.logon = 43;
    if (authorize_peer(expected, other)) return EXIT_FAILURE;
    if (authorize_peer({}, {})) return EXIT_FAILURE;
    const std::array<std::uint8_t, 12> status{'O','S','P','1',1,0,0,0,0,0,0,0};
    const auto decoded = decode(status);
    if (!decoded || *decoded != Command::status) {
        std::cerr << "FAIL: canonical status frame must decode\n";
        return EXIT_FAILURE;
    }
    for (std::size_t i = 0; i < status.size(); ++i) {
        auto corrupt = status; corrupt[i] = 255;
        if (decode(corrupt)) return EXIT_FAILURE;
    }
    for (std::size_t size = 0; size < status.size(); ++size)
        if (decode(std::span(status).first(size))) return EXIT_FAILURE;
    std::array<std::uint8_t, 13> oversized{};
    std::copy(status.begin(), status.end(), oversized.begin());
    if (decode(oversized)) return EXIT_FAILURE;
    auto browser = status; browser[4] = 2;
    if (decode(browser) != Command::browser_open) return EXIT_FAILURE;
    if (reply(Command::browser_open) != "{\"ok\":false,\"error\":\"browser_guard_unavailable\"}") {
        std::cerr << "FAIL: browser-open must always deny\n";
        return EXIT_FAILURE;
    }
    if (reply(Command::status).find("\"authenticated\":false") == std::string_view::npos)
        return EXIT_FAILURE;
    if (reply(static_cast<Command>(999)).find("invalid_command") == std::string_view::npos)
        return EXIT_FAILURE;
    const auto acl = pipe_sddl(expected.sid);
    if (!acl || *acl != "D:P(A;;GA;;;SY)(A;;0x12019b;;;S-1-5-21-10-20-30-1001)") {
        std::cerr << "FAIL: protected DACL must only grant SYSTEM and expected SID\n";
        return EXIT_FAILURE;
    }
    for (auto sid : {"", "WD", "S-1-5-21-1)(A;;GA;;;WD)", "S-1-5-18", "S-1-5-", "S-1-5--21"})
        if (pipe_sddl(sid)) return EXIT_FAILURE;
    return EXIT_SUCCESS;
}
