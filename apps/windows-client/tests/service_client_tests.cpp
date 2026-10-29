#include "orangespace/service_client.hpp"
#include <cstdlib>
#include <iostream>
#include <vector>
#include <string>
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
int main() {
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
    if (os_session == 0) check(!session, "actual session zero rejected");
    else check(session && *session == os_session, "actual interactive session derived");
    const auto result = query_foundation_status();
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
