#include "orangespace/service_policy.hpp"
#include <cstdlib>
#include <iostream>
using namespace orangespace::service;
int main() {
    const Peer expected{"S-1-5-21-10-20-30-1001", 7, 42};
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
