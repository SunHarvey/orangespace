#include "orangespace/windows_service.hpp"
#include <sddl.h>
#include <system_error>
namespace orangespace::service::win {
[[noreturn]] void fail(const char* operation) {
    throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), operation);
}
Peer token_peer(HANDLE token) {
    DWORD size{};
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    if (size == 0 || size > 65536) fail("TokenUser size");
    std::vector<BYTE> user(size);
    if (!GetTokenInformation(token, TokenUser, user.data(), size, &size)) fail("TokenUser");
    LPSTR text{};
    if (!ConvertSidToStringSidA(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid, &text)) fail("SID conversion");
    struct Free { LPSTR p; ~Free() { LocalFree(p); } } free_text{text};
    Peer peer;
    peer.sid = text;
    DWORD session{};
    if (!GetTokenInformation(token, TokenSessionId, &session, sizeof(session), &size)) fail("TokenSessionId");
    TOKEN_STATISTICS stats{};
    if (!GetTokenInformation(token, TokenStatistics, &stats, sizeof(stats), &size)) fail("TokenStatistics");
    peer.session = session;
    peer.logon = static_cast<std::uint64_t>(static_cast<std::uint32_t>(stats.AuthenticationId.HighPart)) << 32 |
        stats.AuthenticationId.LowPart;
    return peer;
}
Peer current_peer() {
    HANDLE token{};
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
        if (GetLastError() != ERROR_NO_TOKEN) fail("OpenThreadToken");
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) fail("OpenProcessToken");
    }
    const Handle owner(token);
    return token_peer(owner.get());
}
Handle create_pipe(const std::wstring& name, const Peer& expected) {
    const auto sddl = pipe_sddl(expected.sid);
    if (!sddl || !expected.session || !expected.logon) throw std::invalid_argument("interactive OS identity required");
    PSECURITY_DESCRIPTOR descriptor{};
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(sddl->c_str(), SDDL_REVISION_1, &descriptor, nullptr)) fail("pipe ACL");
    struct Free { PSECURITY_DESCRIPTOR p; ~Free() { LocalFree(p); } } free_descriptor{descriptor};
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
    Handle pipe(CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, 1024, static_cast<DWORD>(request_size), 1500, &attributes));
    if (!pipe) fail("CreateNamedPipe");
    return pipe;
}
}
