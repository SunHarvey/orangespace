// orangespace-tunnel-replay-check: manual acceptance of the Centre's tunnel
// replay protection against the real Centre and one real node. Not run by
// ctest: it needs a Centre account, the administrator-protected trust files
// and the network.
//
//   orangespace-tunnel-replay-check <platform.json> <catalog.json> <username> <node uuid> < password
//
// The password is read from redirected stdin and never printed. A random
// sandbox id is used, so no real sandbox's tunnels are touched. Steps:
//   1. generation G with a new tunnel id: accepted;
//   2. generation G-1, then G again, each with a new tunnel id: refused;
//   3. generation G+1 with the tunnel id of step 1: refused;
//   4. generation G+1 with a new tunnel id: accepted, after which renewing the
//      step-1 tunnel is refused (only the latest generation is valid);
//   5. both tunnels are revoked.
// Prints one line per step (status codes only, never credentials) and exits 0
// only when every step behaved as above.
#include "orangespace/json.hpp"
#include "orangespace/node_federation.hpp"
#include "orangespace/node_session.hpp"
#include "orangespace/platform_session.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <memory>
#include <optional>
#include <string>

namespace ps = orangespace::platform_session;
namespace ns = orangespace::node_session;
namespace nd = orangespace::node_session::detail;
namespace pp = orangespace::node_federation;

namespace {
struct Secret {
  std::string value;
  Secret() = default;
  Secret(const Secret&) = delete;
  Secret& operator=(const Secret&) = delete;
  ~Secret() { nd::wipe(value.data(), value.size()); }
};

std::string uuid4() {
  unsigned char b[16];
  if (BCryptGenRandom(nullptr, b, sizeof b, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) throw std::runtime_error("no random");
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

std::int64_t unix_seconds() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
std::int64_t unix_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

std::wstring widen(const char* s) {
  const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, nullptr, 0);
  if (n <= 1) throw std::runtime_error("bad argument");
  std::wstring out(static_cast<std::size_t>(n - 1), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s, -1, out.data(), n);
  return out;
}

void read_password(Secret& out) {
  HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
  char c;
  DWORD n = 0;
  while (out.value.size() < 1024 && ReadFile(in, &c, 1, &n, nullptr) && n == 1 && c != '\n') out.value += c;
  if (!out.value.empty() && out.value.back() == '\r') out.value.pop_back();
  if (out.value.empty()) throw std::runtime_error("no password on stdin");
}

// HTTP status of a refused request, or 0 when it was accepted.
template <class F>
unsigned refused(F f) {
  try {
    f();
    return 0;
  } catch (const ns::HttpStatusError& e) {
    return e.status_code();
  }
}

// NodeSession is neither copyable nor movable: construct it in place.
struct Bound {
  ns::NodeSession session;
  Bound(const ns::TrustedCatalog& catalog, const std::string& name, std::string_view token)
      : session(ns::NodeSession::restore(catalog, name, token)) {}
};

bool failed = false;
void step(const char* what, bool ok, unsigned status) {
  std::printf("%s %s (HTTP %u)\n", ok ? "PASS" : "FAIL", what, status);
  if (!ok) failed = true;
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
  if (argc != 5) {
    std::fputs("usage: orangespace-tunnel-replay-check <platform.json> <catalog.json> <username> <node uuid> < password\n", stderr);
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
    const auto catalog = ns::TrustedCatalog::load(argv[2]);
    const auto username = to_utf8(argv[3]);
    const auto node_id = to_utf8(argv[4]);
    std::optional<ps::Session> centre;
    {
      Secret password;
      read_password(password);
      centre.emplace(ps::Session::login(config, username, password.value));
    }
    const auto refs = centre->nodes();
    const auto ref = std::find_if(refs.begin(), refs.end(), [&](const auto& r) { return r.node_id == node_id; });
    if (ref == refs.end()) throw std::runtime_error("the Centre grants no access to this node");
    const auto& pin = catalog.federation_node(node_id);
    pp::match_catalog(*ref, pin);
    auto ticket = centre->issue(node_id);
    std::unique_ptr<Bound> node;
    {
      Secret body;
      body.value = "{\"schema\":1,\"exchange_id\":\"" + ticket.exchange_id + "\",\"exchange_token\":\"";
      body.value.append(ticket.exchange_token.view());
      body.value += "\"}";
      catalog.federation_exchange(node_id, body.value, false, [&](std::string_view bytes) {
        nd::exact_wire_integers(bytes);
        nd::JsonGuard doc(bytes);
        pp::validate_exchange(doc.value, centre->identity(), *ref, unix_seconds());
        const auto& token = nd::text(nd::field(nd::field(doc.value, "node_credential"), "access_token"));
        node = std::make_unique<Bound>(catalog, pin.name, token);
      });
    }
    if (!node) throw std::runtime_error("node exchange gave no session");

    const auto sandbox = uuid4();
    const auto create = [&](std::int64_t generation, const std::string& tunnel) {
      const auto request = "{\"sandbox_id\":\"" + sandbox + "\",\"generation\":" + std::to_string(generation) +
                           ",\"tunnel_id\":\"" + tunnel + "\"}";
      const auto lease = node->session.create_tunnel(request);
      nd::JsonGuard reply(lease.payload);
      nd::require(nd::text(nd::field(reply.value, "tunnel_id")) == tunnel);
    };
    const auto g = unix_ms();
    const auto first = uuid4();
    unsigned s = refused([&] { create(g, first); });
    step("generation G, new tunnel id: accepted", s == 0, s);
    if (s != 0) return 1;
    s = refused([&] { create(g - 1, uuid4()); });
    step("generation G-1, new tunnel id: refused", s != 0, s);
    s = refused([&] { create(g, uuid4()); });
    step("generation G again, new tunnel id: refused", s != 0, s);
    s = refused([&] { create(g + 1, first); });
    step("generation G+1, used tunnel id: refused", s != 0, s);
    const auto second = uuid4();
    s = refused([&] { create(g + 1, second); });
    step("generation G+1, new tunnel id: accepted", s == 0, s);
    s = refused([&] { (void)node->session.renew_tunnel(first); });
    step("renewing the generation-G tunnel after G+1: refused", s != 0, s);
    for (const auto& t : {first, second}) {
      try {
        node->session.revoke_tunnel(t);
      } catch (const ns::HttpStatusError&) {
        // The superseded tunnel may already be gone at the node.
      }
    }
    try {
      centre->logout();
    } catch (...) {
    }
    std::puts(failed ? "FAIL" : "PASS all steps");
    return failed ? 1 : 0;
  } catch (const std::exception& e) {
    std::fprintf(stderr, "error: %s\n", e.what());
    return 1;
  }
}
