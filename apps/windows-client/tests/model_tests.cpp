#include "orangespace/model.hpp"

#include <cstdlib>
#include <iostream>
#include <stdexcept>

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#endif

namespace {
void require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}
template <class F> void rejects(F action, const char* message) {
  try { action(); } catch (const std::exception&) { return; }
  throw std::runtime_error(message);
}
}  // namespace

int main() {
  try {
    using namespace orangespace;
    const std::string user = "11111111-1111-4111-8111-111111111111";
    const std::string sandbox = "22222222-2222-4222-8222-222222222222";
    require(valid_uuid(user), "UUID rejected");
    require(!valid_uuid("../profile"), "path accepted as UUID");
    const auto a = profile_path("root", user, sandbox);
    const auto b = profile_path("root", user, "33333333-3333-4333-8333-333333333333");
    require(a != b, "sandbox profile paths overlap");
    rejects([&] { profile_path("root", user, "../../another-user"); }, "profile traversal accepted");
    require(quote_argument(L"a b") == L"\"a b\"", "space quoting");
    require(quote_argument(L"C:\\data\\") == L"\"C:\\data\\\\\"", "trailing slash quoting");
    require(quote_argument(L"a\"b") == L"\"a\\\"b\"", "quote quoting");
#ifdef _WIN32
    const std::vector<std::wstring> arguments = {L"OrangeSpace.exe", L"", L"深圳 工作区", L"C:\\path with space\\", L"quote\"and\\\"end"};
    std::wstring command;
    for (const auto& argument : arguments) command += (command.empty() ? L"" : L" ") + quote_argument(argument);
    int argc{};
    auto** argv = CommandLineToArgvW(command.c_str(), &argc);
    require(argv && argc == static_cast<int>(arguments.size()), "Windows argument count roundtrip failed");
    bool matches = true;
    for (int i = 0; i < argc; ++i) matches = matches && argv[i] == arguments[static_cast<std::size_t>(i)];
    LocalFree(argv);
    require(matches, "Windows argument values roundtrip failed");
#endif
    const auto response = parse_response(R"({"schema_version":1,"ok":true,"browsing_allowed":true,"sandboxes":[{"id":"22222222-2222-4222-8222-222222222222","user_id":"11111111-1111-4111-8111-111111111111","name":"\u6df1\u5733\ud83c\udf4a","node_id":null,"state":"blocked","profile_path":"x"}]})", user);
    require(response.ok && response.sandboxes.size() == 1, "sandbox response parse");
    require(response.sandboxes.front().name == "深圳🍊", "Unicode decode");
    require(canonical_uuid("ABCDEF01-ABCD-4ABC-8ABC-ABCDEF012345") == "abcdef01-abcd-4abc-8abc-abcdef012345", "UUID canonicalization");
    // The broker response claiming browsing_allowed=true cannot unlock a host.
    require(!browser_launch_decision().allowed, "unprotected browser was allowed");
    rejects([&] { parse_response(R"({"schema_version":2,"ok":true})"); }, "unknown schema accepted");
    rejects([&] { parse_response(R"({"schema_version":1,"ok":true,"sandboxes":[{"id":"22222222-2222-4222-8222-222222222222","user_id":"33333333-3333-4333-8333-333333333333"}]})", user); }, "cross-user response accepted");
    for (const auto* invalid : {"{} junk", "{\"a\":1,\"a\":2}", "[1,]", "01", "1.", "1e", "\"\\ud800\"", "\"\\udc00\"", "NaN"})
      rejects([&] { json::parse(invalid); }, "malformed JSON accepted");
    std::string deep(40, '['); deep += "0"; deep += std::string(40, ']');
    rejects([&] { json::parse(deep); }, "excessive JSON nesting accepted");
    const auto failed = parse_response(R"({"schema_version":1,"ok":false,"error":{"code":"guard_unavailable","message":"guard unavailable"}})");
    require(!failed.ok && failed.message == "guard unavailable", "broker error response lost");
    std::cout << "client model: identity isolation, response validation, quoting and guard checks passed\n";
    return EXIT_SUCCESS;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return EXIT_FAILURE;
  }
}
