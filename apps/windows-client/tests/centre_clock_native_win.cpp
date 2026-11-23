// orangespace-centre-clock-check: manual acceptance of the Centre clock offset
// against the real Centre over the real WinHTTP path. Not run by ctest: it
// needs a Centre account, the administrator-protected trust file and the
// network.
//
//   orangespace-centre-clock-check <platform.json> <username> <shift seconds> [--no-date] < password
//
// The session's clock is this machine's clock plus <shift> (the system clock
// is not changed), standing in for a machine whose clock runs ahead (positive)
// or behind (negative). Steps: sign in, list the granted nodes, take an
// exchange ticket for the first one (never used; it lapses at the Centre in
// 30 s), sign out. With --no-date the replies' Date header is dropped, as
// before this check existed: a shift past a ticket's 30 s should then fail.
// The password is read from redirected stdin and never printed; only the
// offset, counts and PASS/FAIL lines are.
#include "orangespace/platform_session.hpp"
#include "orangespace/sandbox_engine.hpp"

#include <windows.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <optional>
#include <string>

namespace ps = orangespace::platform_session;
namespace nd = orangespace::node_session::detail;

namespace {
struct Secret {
  std::string value;
  Secret() = default;
  Secret(const Secret&) = delete;
  Secret& operator=(const Secret&) = delete;
  ~Secret() { nd::wipe(value.data(), value.size()); }
};

void read_password(Secret& out) {
  HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
  char c;
  DWORD n = 0;
  while (out.value.size() < 1024 && ReadFile(in, &c, 1, &n, nullptr) && n == 1 && c != '\n') out.value += c;
  if (!out.value.empty() && out.value.back() == '\r') out.value.pop_back();
  if (out.value.empty()) throw std::runtime_error("no password on stdin");
}

std::int64_t wall_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

// The production Centre transport (strict WinHTTP, system roots), optionally
// without the Date header.
class Transport final : public ps::Transport {
 public:
  explicit Transport(bool date) : date_(date) {}
  ps::Response request(const ps::Bootstrap& b, std::string_view method, std::string_view path, std::string_view body,
                       std::string_view token) override {
    nd::NodeEntry node;
    node.host = b.host;
    node.port = b.port;
    node.ca_pem = b.ca_pem;
    ps::Response response;
    nd::central_https_request(node, method, path, body, token, [&](unsigned status, std::string_view bytes, std::int64_t d) {
      response.status = status;
      response.body = ps::SerializedSecret(bytes);
      response.date = date_ ? d : 0;
      seen_ = seen_ || d > 0;
    });
    return response;
  }
  bool seen() const { return seen_; }

 private:
  bool date_, seen_{false};
};

bool failed = false;
void step(const char* what, bool ok) {
  std::printf("%s %s\n", ok ? "PASS" : "FAIL", what);
  if (!ok) failed = true;
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
  if (argc != 4 && !(argc == 5 && std::wstring(argv[4]) == L"--no-date")) {
    std::fputs("usage: orangespace-centre-clock-check <platform.json> <username> <shift seconds> [--no-date] < password\n", stderr);
    return 2;
  }
  try {
    const auto to_utf8 = [](const wchar_t* w) {
      const int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
      std::string s(static_cast<std::size_t>(n > 0 ? n - 1 : 0), '\0');
      if (n > 1) WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
      return s;
    };
    const auto config = ps::PlatformConfig::load(argv[1]);
    const auto username = to_utf8(argv[2]);
    const auto shift = std::stoll(to_utf8(argv[3]));
    Transport transport(argc == 4);
    const auto clock = [shift] { return wall_ms() / 1000 + shift; };
    std::printf("session clock shifted by %+lld s%s\n", static_cast<long long>(shift), argc == 4 ? "" : ", Date dropped");
    std::optional<ps::Session> session;
    try {
      Secret password;
      read_password(password);
      session.emplace(ps::Session::login(config, username, password.value, transport, clock));
      step("sign in", true);
    } catch (const std::exception& e) {
      step("sign in", false);
      std::printf("  (%s)\n", e.what());
      return 1;
    }
    std::printf("Date header %s; Centre clock offset %+lld s\n", transport.seen() ? "present" : "absent",
                static_cast<long long>(session->centre_offset()));
    try {
      const auto nodes = session->nodes();
      step("list granted nodes", !nodes.empty());
      if (!nodes.empty()) {
        (void)session->issue(nodes.front().node_id);
        step("exchange ticket accepted", true);
      }
    } catch (const std::exception& e) {
      step("list nodes and take a ticket", false);
      std::printf("  (%s)\n", e.what());
    }
    // A generation taken now, against the Centre's real time in ms.
    const auto local = wall_ms() + shift * 1000;
    const auto generation = orangespace::sandbox::next_generation(0, local, session->centre_offset());
    std::printf("tunnel generation minus real time: %+lld ms\n", static_cast<long long>(generation - wall_ms()));
    try {
      session->logout();
      step("sign out", true);
    } catch (const std::exception&) {
      step("sign out", false);
    }
    std::puts(failed ? "FAIL" : "PASS all steps");
    return failed ? 1 : 0;
  } catch (const std::exception& e) {
    std::fprintf(stderr, "error: %s\n", e.what());
    return 1;
  }
}
