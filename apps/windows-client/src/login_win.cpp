#include "orangespace/node_session.hpp"

#ifdef _WIN32
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

namespace ns = orangespace::node_session;
namespace {
// This executable intentionally has no token output, save, restore, environment
// input, redirected-password input, or browser-launch command.
struct Secret {
  std::vector<char> bytes;
  Secret() = default;
  Secret(const Secret&) = delete;
  Secret& operator=(const Secret&) = delete;
  Secret(Secret&&) = default;
  ~Secret() { ns::detail::wipe(bytes.data(), bytes.size()); }
  std::string_view view() const { return {bytes.data(), bytes.size()}; }
};
struct ConsoleMode {
  HANDLE handle;
  DWORD original{};
  explicit ConsoleMode(bool hidden) : handle(GetStdHandle(STD_INPUT_HANDLE)) {
    if (!GetConsoleMode(handle, &original)) throw std::runtime_error("interactive console stdin required");
    if (hidden && !SetConsoleMode(handle, (original | ENABLE_LINE_INPUT) & ~(ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT)))
      throw std::runtime_error("cannot disable password echo");
  }
  ~ConsoleMode() { SetConsoleMode(handle, original); }
};
Secret read_line(bool hidden, std::size_t limit) {
  ConsoleMode mode(hidden);
  struct WideBuffer {
    std::vector<wchar_t> data;
    ~WideBuffer() { ns::detail::wipe(data.data(), data.size() * sizeof(wchar_t)); }
  } buffer{std::vector<wchar_t>(limit + 2)};
  DWORD count = 0;
  if (!ReadConsoleW(mode.handle, buffer.data.data(), static_cast<DWORD>(buffer.data.size()), &count, nullptr))
    throw std::runtime_error("console input failed");
  if (!count || buffer.data[count - 1] != L'\n') throw std::runtime_error("input line exceeds limit");
  while (count && (buffer.data[count - 1] == L'\n' || buffer.data[count - 1] == L'\r')) --count;
  if (!count || count > limit) throw std::runtime_error("invalid input length");
  // Ctrl-C is read as input while echo is off, so normal unwinding restores the
  // console mode rather than terminating the process with echo disabled.
  for (DWORD i = 0; i < count; ++i) if (buffer.data[i] < 32) throw std::runtime_error("input cancelled or contains controls");
  const int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, buffer.data.data(), static_cast<int>(count), nullptr, 0, nullptr, nullptr);
  if (!needed) throw std::runtime_error("invalid Unicode input");
  Secret result;
  result.bytes.resize(static_cast<std::size_t>(needed));
  if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, buffer.data.data(), static_cast<int>(count), result.bytes.data(), needed, nullptr, nullptr))
    throw std::runtime_error("cannot encode console input");
  return result;
}
std::string alias(const wchar_t* arg) {
  std::string value;
  for (; *arg; ++arg) {
    if (*arg > 127) throw std::runtime_error("invalid node alias");
    value.push_back(static_cast<char>(*arg));
  }
  return value;
}
}
int wmain(int argc, wchar_t** argv) {
  try {
    if (argc == 3 && std::wstring_view(argv[1]) == L"--check-trust") {
      const auto catalog = ns::TrustedCatalog::load(argv[2]);
      const auto names = catalog.names();
      std::cout << "Protected trust configuration accepted; nodes=" << names.size() << '\n';
      for (const auto& name : names) std::cout << "node alias: " << name << '\n';
      return 0;
    }
    if (argc != 3) {
      std::cerr << "Usage: OrangeSpaceLogin.exe <absolute-trust-path> <pinned-alias>\n"
                   "       OrangeSpaceLogin.exe --check-trust <absolute-trust-path>\n"
                   "Credentials are accepted only from interactive console stdin.\n";
      return 2;
    }
    const auto catalog = ns::TrustedCatalog::load(argv[1]);
    const auto node = alias(argv[2]);
    const auto names = catalog.names();
    bool present = false;
    for (const auto& name : names) present = present || name == node;
    if (!present) throw std::runtime_error("node alias is not administrator pinned");
    std::cout << "Username: " << std::flush;
    auto username = read_line(false, 64);
    std::cout << "Password (not echoed): " << std::flush;
    auto password = read_line(true, 1024);
    std::cout << '\n';
    const auto session = ns::NodeSession::login(catalog, node, username.view(), password.view());
    ns::detail::wipe(password.bytes.data(), password.bytes.size());
    password.bytes.clear();
    std::cout << "Authenticated user_id=" << session.identity().user_id
              << " node_id=" << session.identity().node_id
              << " expires_at=" << session.expires_at() << '\n'
              << "Ephemeral diagnostic session only; no credentials persisted. Browser remains blocked.\n";
    return 0;
  } catch (const std::exception& error) {
    // All component exceptions are constant diagnostics; never server bodies,
    // request headers, passwords, access tokens, or serialized JSON.
    std::cerr << "Login diagnostic failed: " << error.what() << '\n';
    return 1;
  }
}
#endif
