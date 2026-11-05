#include "orangespace/node_session.hpp"

#include <iostream>
#include <stdexcept>
#include <string>

#include <type_traits>
#ifdef _WIN32
#include <windows.h>
#endif

namespace ns = orangespace::node_session;
static_assert(!std::is_default_constructible_v<ns::TrustedCatalog>);
static_assert(!std::is_constructible_v<ns::TrustedCatalog, std::vector<ns::detail::NodeEntry>>);
static_assert(!std::is_copy_constructible_v<ns::NodeSession>);
static unsigned checks = 0;
static void check(bool value, const char* message) {
  ++checks;
  if (!value) throw std::runtime_error(message);
}
template<class F> static void rejects(F f, const char* message) {
  bool rejected = false;
  try { f(); } catch (const std::exception&) { rejected = true; }
  check(rejected, message);
}
static constexpr auto node_id = "11111111-1111-4111-8111-111111111111";
static std::string config(std::string origin = "https://node.example:443") {
  return std::string(R"({"schema":1,"nodes":[{"name":"office","node_id":")") + node_id +
      R"(","api_origin":")" + origin + R"("}]})";
}
int main() {
  try {
    const auto catalog = ns::detail::parse_catalog(config());
    check(catalog.size() == 1, "one pinned node");
    check(catalog[0].node_id == node_id, "pinned identity preserved");
    check(catalog[0].host == "node.example" && catalog[0].port == 443, "origin parsed");
    rejects([] { ns::detail::parse_catalog(config("http://node.example")); }, "reject plaintext origin");
    for (const auto* bad : {"https://node.example/path", "https://user@node.example", "https://node.example?x", "https://node.example#x", "https://node.example\\\\x", "https://node.example:0", "https://node.example:65536", "https://node.example:0443", "https://node.example:", "https://node..example", "https://-node.example", "https://node.example.", "https://NODE.example", "https://[::1]", "https://node.example:443:1", "https://node.example%2f"})
      rejects([&] { ns::detail::parse_catalog(config(bad)); }, "reject ambiguous origin");
    auto duplicate = config();
    auto entry = duplicate.substr(duplicate.find("{\"name\""), duplicate.rfind('}') - duplicate.find("{\"name\"") - 1);
    duplicate.insert(duplicate.size() - 2, "," + entry);
    rejects([&] { ns::detail::parse_catalog(duplicate); }, "reject duplicate node");
    rejects([] { ns::detail::parse_catalog(R"({"schema":1,"nodes":[],"extra":true})"); }, "reject unknown schema field");
    rejects([] { ns::detail::parse_catalog(R"({"schema":1,"nodes":[]})"); }, "reject empty trust");
    rejects([] { ns::detail::parse_catalog(config() + "{}"); }, "reject trailing JSON");
    const auto login_body = std::string(R"({"access_token":")") + std::string(43, 'a') + R"(","token_type":"bearer","expires_at":2000000000,"node_id":")" + node_id + R"("})";
    const auto login = ns::detail::validate_login(catalog[0], 200, node_id, login_body, 1900000000);
    check(login.token == std::string(43, 'a') && login.expires_at == 2000000000, "validated login");
    const auto me_body = std::string(R"({"user_id":"22222222-2222-4222-8222-222222222222","username":"alice","node_id":")") + node_id + R"("})";
    const auto me = ns::detail::validate_me(catalog[0], 200, node_id, me_body);
    check(me.user_id == "22222222-2222-4222-8222-222222222222" && me.username == "alice" && me.node_id == node_id, "identity from authenticated me");
    for (unsigned status : {201u, 301u, 302u, 307u, 401u, 429u, 500u}) {
      rejects([&] { ns::detail::validate_login(catalog[0], status, node_id, login_body, 1900000000); }, "login must be 200");
      rejects([&] { ns::detail::validate_me(catalog[0], status, node_id, me_body); }, "me must be 200");
    }
    for (const auto* bad : {"", "22222222-2222-4222-8222-222222222222", "11111111-1111-4111-8111-111111111111, 11111111-1111-4111-8111-111111111111"}) {
      rejects([&] { ns::detail::validate_login(catalog[0], 200, bad, login_body, 1900000000); }, "login header pin");
      rejects([&] { ns::detail::validate_me(catalog[0], 200, bad, me_body); }, "me header pin");
    }
    const auto changed = [](std::string value, std::string_view from, std::string_view to) {
      const auto at = value.find(from);
      if (at == std::string::npos) throw std::runtime_error("bad test fixture");
      value.replace(at, from.size(), to);
      return value;
    };
    for (const auto& body : {
        changed(login_body, "bearer", "Bearer"), changed(login_body, "2000000000", "1900000000"),
        changed(login_body, "2000000000", "2000000000.5"), changed(login_body, "2000000000", "\"2000000000\""),
        changed(login_body, std::string(43, 'a'), std::string(42, 'a')), changed(login_body, std::string(43, 'a'), std::string(42, 'a') + "\\r"),
        changed(login_body, node_id, "22222222-2222-4222-8222-222222222222"),
        changed(login_body, "\"token_type\":\"bearer\"", "\"token_type\":\"bearer\",\"user_id\":\"spoof\""),
        changed(login_body, "\"token_type\":\"bearer\"", "\"token_type\":\"bearer\",\"token_type\":\"bearer\""),
        std::string(16385, 'x')})
      rejects([&] { ns::detail::validate_login(catalog[0], 200, node_id, body, 1900000000); }, "reject invalid login body");
    for (const auto& body : {
        changed(me_body, node_id, "22222222-2222-4222-8222-222222222222"),
        changed(me_body, "alice", ""), changed(me_body, "alice", "bad\\u001bname"),
        changed(me_body, "alice", std::string(1, static_cast<char>(0xff))),
        changed(me_body, "22222222-2222-4222-8222-222222222222", "not-a-uuid"),
        changed(me_body, "\"username\":\"alice\"", "\"username\":false"),
        changed(me_body, "\"username\":\"alice\"", "\"username\":\"alice\",\"extra\":0"),
        changed(me_body, "\"username\":\"alice\"", "\"username\":\"alice\",\"username\":\"bob\""),
        me_body + "false"})
      rejects([&] { ns::detail::validate_me(catalog[0], 200, node_id, body); }, "reject invalid me body");
    using ns::detail::Ace;
    using ns::detail::AceKind;
    const std::vector<Ace> safe_acl{{AceKind::allow, true, 0x1f01ff}, {AceKind::allow, false, 0x1200a9}};
    check(ns::detail::secure_acl(true, true, true, safe_acl), "admin-owned protected ACL accepts users RX");
    check(!ns::detail::secure_acl(false, true, true, safe_acl), "reject user owner");
    check(!ns::detail::secure_acl(true, false, true, safe_acl), "reject inherited file ACL");
    check(!ns::detail::secure_acl(true, true, false, safe_acl), "reject null DACL");
    for (std::uint32_t mask : {2u, 4u, 16u, 256u, 64u, 0x10000u, 0x40000u, 0x80000u, 0x40000000u, 0x10000000u, 0x02000000u}) {
      auto acl = safe_acl;
      acl.push_back({AceKind::allow, false, mask});
      check(!ns::detail::secure_acl(true, true, true, acl), "reject ordinary writer");
    }
    check(!ns::detail::secure_acl(true, true, true, {{AceKind::unsupported, true, 0}}), "reject unknown ACL semantics");
    check(ns::detail::secure_acl(true, false, true, {{AceKind::allow, false, 6}}, true), "ancestors may permit child creation only");
    check(ns::detail::explicit_local_path(L"C:\\OrangeSpaceTrust\\nodes.json"), "explicit local path");
    for (const auto* path : {L"nodes.json", L"C:nodes.json", L"\\\\server\\share\\nodes.json", L"\\\\?\\C:\\nodes.json", L"C:\\a\\..\\nodes.json", L"C:\\nodes.json:ads", L"C:\\a.\\nodes.json", L"C:\\a \\nodes.json", L"C:/nodes.json", L"C:\\CON\\nodes.json", L"C:\\a\\", L"C:\\\\nodes.json"})
      check(!ns::detail::explicit_local_path(path), "reject ambiguous trust path");
#ifdef _WIN32
    // Real Win32 loader rejection, no network and no credential material. The
    // temporary file belongs to this user and must never authorize requests.
    wchar_t temp[MAX_PATH + 1]{};
    check(GetTempPathW(MAX_PATH, temp) != 0, "temporary directory available");
    const std::wstring temporary = std::wstring(temp) + L"orangespace-trust-negative-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()) + L".json";
    struct RemoveTestFile { std::wstring path; ~RemoveTestFile() { DeleteFileW(path.c_str()); } } cleanup{temporary};
    const auto file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    check(file != INVALID_HANDLE_VALUE, "create harmless user-owned trust fixture");
    DWORD written = 0;
    const auto fixture = config();
    const auto wrote = WriteFile(file, fixture.data(), static_cast<DWORD>(fixture.size()), &written, nullptr);
    CloseHandle(file);
    check(wrote && written == fixture.size(), "write harmless trust fixture");
    rejects([&] { ns::TrustedCatalog::load(temporary); }, "native loader rejects user-editable trust");
    rejects([] { ns::TrustedCatalog::load(L"nodes.json"); }, "native loader rejects relative path");
#endif
    std::cout << "node session: " << checks << " checks passed\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "FAILED: " << e.what() << '\n';
    return 1;
  }
}
