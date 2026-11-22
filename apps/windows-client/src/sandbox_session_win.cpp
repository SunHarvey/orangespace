// orangespace-sandbox: runs sandboxes whose network is authorized by node leases.
// Acceptance/dev front end for L3 (the product UI arrives in L4). Run it in the
// user's interactive session, like orangespace-wsl.
//
//   orangespace-sandbox <session.json> [--password-stdin] [--seconds N]
//
// session.json (no secrets):
//   {"platform": "C:\\...\\platform.json",   administrator-protected Centre bootstrap
//    "catalog":  "C:\\...\\catalog.json",    administrator-protected node pins
//    "username": "alice",
//    "probe": {"ipv4": "1.1.1.1", "port": 443, "tls_name": "one.one.one.one", "path": "/"},  optional
//    "sandboxes": [{"sandbox": "<uuid>", "node": "<node uuid>", "title": "OrangeSpace 沙盒 A"}]}
//
// It signs in to the Centre (the password is typed without echo, or read from
// stdin with --password-stdin), then for every sandbox separately: exchanges a
// node session of its own, creates a tunnel lease, gives the lease to the guest
// (desktop.lease: credentials go over the agent's stdin, never a command line),
// starts the desktop and renews the lease every few seconds (desktop.renew
// extends the guest's kernel permit to the renewed lease). A failed renewal
// gets a new tunnel with a higher generation. When this program stops for any
// reason the renewals stop, so every sandbox's network permit lapses on its own
// within the lease (at most 30 s); a normal exit also revokes the tunnels and
// closes the agent, which stops the desktops. The sandbox logic is the
// OrangeSpace window's (sandbox_engine); this tool only reads the session file.
#include "orangespace/json.hpp"
#include "orangespace/node_session.hpp"
#include "orangespace/platform_session.hpp"
#include "orangespace/sandbox_engine.hpp"
#include "orangespace/wsl_runtime.hpp"

#include <atomic>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace ps = orangespace::platform_session;
namespace ns = orangespace::node_session;
namespace nd = orangespace::node_session::detail;
namespace sb = orangespace::sandbox;
namespace wsl = orangespace::wsl;
namespace json = orangespace::json;

namespace {
std::atomic<bool> stopping{false};

BOOL WINAPI on_console(DWORD) {
  stopping = true;
  return TRUE;
}

struct Secret {
  std::string value;
  Secret() = default;
  Secret(const Secret&) = delete;
  Secret& operator=(const Secret&) = delete;
  ~Secret() { nd::wipe(value.data(), value.size()); }
};

std::string json_string(std::string_view text) {
  std::string out = "\"";
  static constexpr char hex[] = "0123456789abcdef";
  for (const unsigned char c : text) {
    if (c == '"' || c == '\\') {
      out += '\\';
      out += static_cast<char>(c);
    } else if (c < 0x20) {
      out += "\\u00";
      out += hex[c >> 4];
      out += hex[c & 15];
    } else {
      out += static_cast<char>(c);
    }
  }
  return out + "\"";
}

std::wstring widen(std::string_view s) {
  const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
  std::wstring out(n > 0 ? n : 0, L'\0');
  if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
  return out;
}

std::string narrow(std::wstring_view w) {
  const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
  std::string out(n > 0 ? n : 0, '\0');
  if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), out.data(), n, nullptr, nullptr);
  return out;
}

// The password never echoes and is wiped after sign-in.
void read_password(Secret& out, bool from_stdin) {
  HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
  if (from_stdin) {
    std::string line;
    char c;
    DWORD n = 0;
    while (line.size() < 1024 && ReadFile(in, &c, 1, &n, nullptr) && n == 1 && c != '\n') line += c;
    if (!line.empty() && line.back() == '\r') line.pop_back();
    out.value.swap(line);
    return;
  }
  DWORD mode = 0;
  if (!GetConsoleMode(in, &mode)) throw std::runtime_error("no console for the password (use --password-stdin)");
  SetConsoleMode(in, (mode & ~ENABLE_ECHO_INPUT) | ENABLE_LINE_INPUT);
  std::fputs("Password: ", stdout);
  std::fflush(stdout);
  std::wstring wide(1100, L'\0');
  DWORD read = 0;
  const BOOL ok = ReadConsoleW(in, wide.data(), 1024, &read, nullptr);
  SetConsoleMode(in, mode);
  std::fputs("\n", stdout);
  if (!ok) throw std::runtime_error("cannot read the password");
  wide.resize(read);
  while (!wide.empty() && (wide.back() == L'\n' || wide.back() == L'\r')) wide.pop_back();
  out.value = narrow(wide);
  nd::wipe(wide.data(), wide.size() * sizeof(wchar_t));
}

std::string text_field(const json::Value& v, std::string_view key) {
  const auto* f = v.find(key);
  if (!f || !std::get_if<std::string>(&f->data)) throw std::runtime_error("invalid session file: " + std::string(key));
  return std::get<std::string>(f->data);
}

std::string json_of(const json::Value& v) {
  if (const auto* s = std::get_if<std::string>(&v.data)) return json_string(*s);
  if (const auto* n = std::get_if<double>(&v.data)) return std::to_string(static_cast<long long>(*n));
  if (const auto* o = std::get_if<json::Value::Object>(&v.data)) {
    std::string out = "{";
    for (const auto& [key, value] : *o) out += (out.size() > 1 ? "," : "") + json_string(key) + ":" + json_of(value);
    return out + "}";
  }
  throw std::runtime_error("invalid probe in session file");
}

int run(const json::Value& config, bool password_stdin, int seconds) {
  const auto platform = ps::PlatformConfig::load(widen(text_field(config, "platform")));
  const auto catalog = ns::TrustedCatalog::load(widen(text_field(config, "catalog")));
  std::mutex out;
  const auto print = [&out](const std::string& line) {
    std::lock_guard lock(out);
    std::printf("%s\n", line.c_str());
    std::fflush(stdout);
  };
  std::unique_ptr<sb::Centre> centre;
  {
    Secret password;
    read_password(password, password_stdin);
    centre = std::make_unique<sb::Centre>(ps::Session::login(platform, text_field(config, "username"), password.value), print);
  }
  std::string probe;
  if (const auto* p = config.find("probe")) probe = json_of(*p);
  std::vector<sb::Spec> specs;
  const auto* list = config.find("sandboxes");
  if (!list || !std::get_if<json::Value::Array>(&list->data)) throw std::runtime_error("invalid session file: sandboxes");
  for (const auto& item : std::get<json::Value::Array>(list->data)) {
    sb::Spec s{text_field(item, "sandbox"), text_field(item, "node"), text_field(item, "title")};
    nd::require(nd::uuid(s.id) && nd::uuid(s.node_id));
    for (const auto& other : specs) nd::require(other.id != s.id);
    specs.push_back(std::move(s));
  }
  nd::require(!specs.empty() && specs.size() <= 16);
  const auto identity = centre->identity();
  std::printf("signed in as %s (%s); %zu sandbox(es)\n", identity.username.c_str(), identity.central_user_id.c_str(),
              specs.size());
  std::fflush(stdout);

  wsl::Agent agent;
  sb::Engine engine(catalog, *centre, agent, probe, print);
  for (const auto& s : specs) engine.open(s);
  const auto until = seconds > 0 ? nd::monotonic_ms() + seconds * 1000LL : INT64_MAX;
  while (!stopping && nd::monotonic_ms() < until && agent.running()) Sleep(250);
  engine.shutdown();  // revokes every tunnel and stops every desktop
  agent.shutdown();
  std::puts("stopped; tunnels revoked, desktops closed");
  return 0;
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
  try {
    SetConsoleOutputCP(CP_UTF8);
    if (argc < 2) {
      std::fputs("usage: orangespace-sandbox <session.json> [--password-stdin] [--seconds N]\n", stderr);
      return 2;
    }
    bool password_stdin = false;
    int seconds = 0;
    for (int i = 2; i < argc; ++i) {
      const std::wstring arg = argv[i];
      if (arg == L"--password-stdin") password_stdin = true;
      else if (arg == L"--seconds" && i + 1 < argc) seconds = _wtoi(argv[++i]);
      else throw std::runtime_error("unknown option");
    }
    std::ifstream in(argv[1], std::ios::binary);
    if (!in) throw std::runtime_error("cannot read the session file");
    std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (text.rfind("\xEF\xBB\xBF", 0) == 0) text.erase(0, 3);
    const auto config = json::Parser(text).parse();
    SetConsoleCtrlHandler(on_console, TRUE);
    return run(config, password_stdin, seconds);
  } catch (const std::exception& e) {
    std::fprintf(stderr, "error: %s\n", e.what());
    return 1;
  }
}
