// Opt-in transport integration: a controlled endpoint must present an untrusted
// certificate. Pair this process with a fixture recording zero HTTP app bytes.
// No real account, token, trust-store change, or certificate bypass is used.
#include "orangespace/node_session.hpp"
#include <iostream>
#include <windows.h>
#include <winhttp.h>
#include <string_view>
#include <system_error>

int wmain(int argc, wchar_t** argv) {
  if (argc != 3) {
    std::cout << "SKIP: explicit protected catalog path and fixture alias required\n";
    return 77;
  }
  try {
    const auto catalog = orangespace::node_session::TrustedCatalog::load(argv[1]);
    std::string alias;
    for (const wchar_t* p = argv[2]; *p; ++p) {
      if (*p > 127) return 2;
      alias.push_back(static_cast<char>(*p));
    }
    try {
      const auto session = orangespace::node_session::NodeSession::login(
          catalog, alias, "fixture-user", "fixture-password-not-a-real-account");
      (void)session;
      std::cerr << "FAIL: untrusted fixture created an authenticated session\n";
      return 1;
    } catch (const std::system_error& error) {
      if (error.code().category() != std::system_category() || error.code().value() != ERROR_WINHTTP_SECURE_FAILURE) {
        std::cerr << "FAIL: native secure-failure evidence missing\n";
        return 1;
      }
      std::cout << "WinHTTP secure failure 12175 preserved; peer must independently record zero HTTP application bytes\n";
      return 0;
    }
  } catch (const std::exception&) {
    std::cerr << "FAIL: protected fixture setup invalid\n";
    return 1;
  }
}
