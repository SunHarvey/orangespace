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
// closes the agent, which stops the desktops.
#include "orangespace/json.hpp"
#include "orangespace/node_session.hpp"
#include "orangespace/platform_protocol.hpp"
#include "orangespace/platform_session.hpp"
#include "orangespace/wsl_runtime.hpp"

#include <bcrypt.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

namespace ps = orangespace::platform_session;
namespace ns = orangespace::node_session;
namespace nd = orangespace::node_session::detail;
namespace pp = orangespace::service::platform;
namespace wsl = orangespace::wsl;
namespace json = orangespace::json;

namespace {
constexpr std::int64_t kRenewEveryMs = 10000;
constexpr std::int64_t kRetryMs = 3000;
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

std::int64_t unix_seconds() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
std::int64_t unix_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string uuid4() {
  unsigned char b[16];
  if (BCryptGenRandom(nullptr, b, sizeof b, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) throw std::runtime_error("no randomness");
  b[6] = static_cast<unsigned char>((b[6] & 0x0f) | 0x40);
  b[8] = static_cast<unsigned char>((b[8] & 0x3f) | 0x80);
  static constexpr char hex[] = "0123456789abcdef";
  std::string out;
  for (int i = 0; i < 16; ++i) {
    if (i == 4 || i == 6 || i == 8 || i == 10) out += '-';
    out += hex[b[i] >> 4];
    out += hex[b[i] & 15];
  }
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

// One sandbox's own node session: never shared with another sandbox.
struct Bound {
  ns::NodeSession session;
  Bound(const ns::TrustedCatalog& catalog, const std::string& name, std::string_view token)
      : session(ns::NodeSession::restore(catalog, name, token)) {}
};

struct Sandbox {
  std::string id, node_id, title;
  ps::NodeRef ref;
  const nd::NodeEntry* pin{};
  std::unique_ptr<Bound> bound;
  std::string tunnel;
  std::int64_t generation{};
  int failures{};
  bool started{false};
  std::int64_t next_ms{};
};

class Runner {
 public:
  Runner(const json::Value& config, bool password_stdin)
      : platform_(ps::PlatformConfig::load(widen(text_field(config, "platform")))),
        catalog_(ns::TrustedCatalog::load(widen(text_field(config, "catalog")))),
        central_(sign_in(platform_, text_field(config, "username"), password_stdin)) {
    if (const auto* probe = config.find("probe")) probe_ = json_of(*probe);
    const auto refs = central_->nodes();
    const auto* list = config.find("sandboxes");
    if (!list || !std::get_if<json::Value::Array>(&list->data)) throw std::runtime_error("invalid session file: sandboxes");
    for (const auto& item : std::get<json::Value::Array>(list->data)) {
      Sandbox s;
      s.id = text_field(item, "sandbox");
      s.node_id = text_field(item, "node");
      s.title = text_field(item, "title");
      nd::require(nd::uuid(s.id) && nd::uuid(s.node_id));
      for (const auto& other : sandboxes_) nd::require(other.id != s.id);
      const auto found = std::find_if(refs.begin(), refs.end(), [&](const auto& r) { return r.node_id == s.node_id; });
      if (found == refs.end()) throw std::runtime_error("the Centre grants no access to node " + s.node_id);
      if (std::find(found->scopes.begin(), found->scopes.end(), "tunnel") == found->scopes.end())
        throw std::runtime_error("no tunnel grant on node " + s.node_id);
      s.ref = *found;
      s.pin = &catalog_.federation_node(s.node_id);
      pp::match_catalog(s.ref, *s.pin);
      sandboxes_.push_back(std::move(s));
    }
    nd::require(!sandboxes_.empty() && sandboxes_.size() <= 16);
    std::printf("signed in as %s (%s); %zu sandbox(es)\n", central_->identity().username.c_str(),
                central_->identity().central_user_id.c_str(), sandboxes_.size());
  }

  int run(int seconds) {
    const auto until = seconds > 0 ? nd::monotonic_ms() + seconds * 1000LL : INT64_MAX;
    while (!stopping && nd::monotonic_ms() < until && agent_.running()) {
      for (auto& s : sandboxes_) {
        if (stopping || nd::monotonic_ms() < s.next_ms) continue;
        try {
          if (s.tunnel.empty()) connect(s);
          else renew(s);
          s.failures = 0;
          s.next_ms = nd::monotonic_ms() + kRenewEveryMs;
        } catch (const std::exception& e) {
          // A renewal the node refuses (or that cannot be checked) is never
          // retried on the same tunnel: the next attempt creates a new one with a
          // higher generation, which the Centre makes the only valid one. The old
          // permit lapses in the guest on its own. Repeated failures to set up a
          // tunnel start over with a new node session.
          const auto* status = dynamic_cast<const ns::HttpStatusError*>(&e);
          const auto reason = status ? "HTTP " + std::to_string(status->status_code()) : std::string(e.what());
          if (!s.tunnel.empty()) {
            std::printf("[%s] renewal failed (%s); new tunnel next\n", s.id.c_str(), reason.c_str());
            s.tunnel.clear();
          } else {
            std::printf("[%s] tunnel setup failed (%s); retrying\n", s.id.c_str(), reason.c_str());
            if ((status && status->status_code() == 401) || ++s.failures >= 2) {
              s.bound.reset();
              s.failures = 0;
            }
          }
          s.next_ms = nd::monotonic_ms() + kRetryMs;
        }
        std::fflush(stdout);
      }
      Sleep(250);
    }
    for (auto& s : sandboxes_) {
      if (s.bound && !s.tunnel.empty()) {
        try { s.bound->session.revoke_tunnel(s.tunnel); } catch (const std::exception&) {}
      }
    }
    agent_.shutdown();  // the agent stops every desktop it started
    std::puts("stopped; tunnels revoked, desktops closed");
    return 0;
  }

 private:
  static std::unique_ptr<ps::Session> sign_in(const ps::PlatformConfig& platform, const std::string& user, bool from_stdin) {
    Secret password;
    read_password(password, from_stdin);
    return std::make_unique<ps::Session>(ps::Session::login(platform, user, password.value));
  }

  static std::string json_of(const json::Value& v) {
    if (const auto* s = std::get_if<std::string>(&v.data)) return json_string(*s);
    if (const auto* n = std::get_if<double>(&v.data)) return std::to_string(static_cast<long long>(*n));
    if (const auto* o = std::get_if<json::Value::Object>(&v.data)) {
      std::string out = "{";
      for (const auto& [key, value] : *o) out += (out.size() > 1 ? "," : "") + json_string(key) + ":" + json_of(value);
      return out + "}";
    }
    throw std::runtime_error("invalid probe in session file");
  }

  std::string agent(std::string_view request, DWORD timeout_ms) {
    auto reply = agent_.request(request, timeout_ms);
    if (reply.find("\"error\"") != std::string::npos) throw std::runtime_error("guest: " + reply.substr(0, 240));
    return reply;
  }

  void exchange(Sandbox& s) {
    s.bound.reset();
    central_->revalidate();
    auto ticket = central_->issue(s.node_id);
    Secret body;
    body.value = "{\"schema\":1,\"exchange_id\":\"" + ticket.exchange_id + "\",\"exchange_token\":\"";
    body.value.append(ticket.exchange_token.view());
    body.value += "\"}";
    catalog_.federation_exchange(s.node_id, body.value, false, [&](std::string_view bytes) {
      nd::exact_wire_integers(bytes);
      nd::JsonGuard doc(bytes);
      const auto expiry = pp::validate_exchange(doc.value, central_->identity(), s.ref, unix_seconds());
      const auto& token = nd::text(nd::field(nd::field(doc.value, "node_credential"), "access_token"));
      auto bound = std::make_unique<Bound>(catalog_, s.pin->name, token);
      nd::require(bound->session.identity().user_id == s.ref.remote_legacy_user_id &&
                  bound->session.identity().node_id == s.node_id && bound->session.expires_at() == expiry);
      s.bound = std::move(bound);
    });
    nd::require(s.bound != nullptr);
  }

  void connect(Sandbox& s) {
    if (!s.bound || s.bound->session.expires_at() <= unix_seconds() + 60) exchange(s);
    // Generations only rise, also across runs: the Centre refuses any other.
    s.generation = std::max(s.generation + 1, unix_ms());
    const auto tunnel = uuid4();
    const auto request = "{\"sandbox_id\":\"" + s.id + "\",\"generation\":" + std::to_string(s.generation) +
                         ",\"tunnel_id\":\"" + tunnel + "\"}";
    auto lease = s.bound->session.create_tunnel(request);
    Secret message;
    {
      nd::JsonGuard reply(lease.payload);
      const auto& r = reply.value;
      nd::require(nd::text(nd::field(r, "tunnel_id")) == tunnel && nd::text(nd::field(r, "sandbox_id")) == s.id);
      const auto remaining = lease.budget.deadline_ms - nd::monotonic_ms();
      nd::require(remaining > 1000);
      Secret record;
      record.value = "{\"node_id\":" + json_string(s.node_id) + ",\"tunnel_id\":" + json_string(tunnel) +
                     ",\"endpoint_ip\":" + json_string(nd::text(nd::field(r, "endpoint_ip"))) +
                     ",\"endpoint_port\":" + std::to_string(nd::integer(nd::field(r, "endpoint_port"))) +
                     ",\"tls_server_name\":" + json_string(nd::text(nd::field(r, "tls_server_name"))) +
                     ",\"certificate_pem\":" + json_string(*s.pin->ca_pem) +
                     ",\"uuid\":" + json_string(nd::text(nd::field(r, "tuic_uuid"))) +
                     ",\"password\":" + json_string(nd::text(nd::field(r, "tuic_password"))) +
                     ",\"remaining_ms\":" + std::to_string(remaining) +
                     (probe_.empty() ? std::string() : ",\"probe\":" + probe_) + "}";
      message.value = "{\"op\":\"desktop.lease\",\"user\":" + json_string(central_->identity().central_user_id) +
                      ",\"sandbox\":" + json_string(s.id) + ",\"node\":" + json_string(s.node_id) +
                      ",\"lease\":" + json_string(record.value) + "}";
    }
    agent(message.value, 60000);
    s.tunnel = tunnel;
    std::printf("[%s] tunnel %s generation %lld on node %s\n", s.id.c_str(), tunnel.c_str(),
                static_cast<long long>(s.generation), s.pin->name.c_str());
    if (!s.started) {
      const auto reply = agent("{\"op\":\"desktop.start\",\"user\":" + json_string(central_->identity().central_user_id) +
                               ",\"sandbox\":" + json_string(s.id) + ",\"node\":" + json_string(s.node_id) +
                               ",\"title\":" + json_string(s.title) + "}", 300000);
      s.started = true;
      std::printf("[%s] desktop %s\n", s.id.c_str(), reply.c_str());
    }
  }

  void renew(Sandbox& s) {
    const auto result = s.bound->session.renew_tunnel(s.tunnel);
    const auto remaining = result.budget.deadline_ms - nd::monotonic_ms();
    nd::require(remaining > 1000);
    agent("{\"op\":\"desktop.renew\",\"user\":" + json_string(central_->identity().central_user_id) +
          ",\"sandbox\":" + json_string(s.id) + ",\"tunnel\":" + json_string(s.tunnel) +
          ",\"remaining_ms\":" + std::to_string(remaining) + "}", 15000);
  }

  ps::PlatformConfig platform_;
  ns::TrustedCatalog catalog_;
  std::unique_ptr<ps::Session> central_;
  std::string probe_;
  std::vector<Sandbox> sandboxes_;
  wsl::Agent agent_;
};
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
    Runner runner(config, password_stdin);
    return runner.run(seconds);
  } catch (const std::exception& e) {
    std::fprintf(stderr, "error: %s\n", e.what());
    return 1;
  }
}
