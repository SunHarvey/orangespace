// Remember-login against the real current-user DPAPI store, with a fake Centre.
// Run it in an interactive desktop session (the store refuses session 0, so not
// over SSH). It uses a random fixture origin, so it never touches a real saved
// sign-in, and erases its entry at the end. Not HTTPS acceptance.
#include "orangespace/platform_credential_store.hpp"

#include <cassert>
#include <chrono>
#include <cstdio>
#include <string>

#include <windows.h>
#include <bcrypt.h>

using namespace orangespace::platform_session;
namespace orangespace::platform_session::detail {
struct TestAccess {
  static PlatformConfig config(const std::string& origin) {
    return PlatformConfig(validate_bootstrap("{\"schema\":1,\"api_origin\":\"" + origin + "\"}"));
  }
};
}  // namespace orangespace::platform_session::detail

namespace {
const std::string uid = "11111111-1111-4111-8111-111111111111", sid = "22222222-2222-4222-8222-222222222222";
std::int64_t wall() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

// Rotates like the Centre: only the latest refresh credential works; any other
// one is refused (the real Centre would also revoke the session).
struct Centre final : Transport {
  std::string origin;
  char access = 'A', renewal = 'R';
  bool offline = false;
  unsigned status = 200;
  int refreshes = 0;
  std::int64_t base = wall();
  std::string identity(std::int64_t expiry) const {
    return "\"schema\":1,\"central_session_id\":\"" + sid + "\",\"expires_at\":" + std::to_string(expiry) +
           ",\"user\":{\"central_user_id\":\"" + uid + "\",\"username\":\"alice\",\"role\":\"user\",\"enabled\":true,\"user_epoch\":3,\"created_at\":1}";
  }
  std::string deadline() const { return std::to_string(base + 30 * 86400); }
  Response request(const Bootstrap& b, std::string_view, std::string_view path, std::string_view body,
                   std::string_view bearer) override {
    assert(b.api_origin == origin);
    if (path == "/control/v1/auth/login")
      return {200, SerializedSecret("{" + identity(base + 3600) + ",\"access_token\":\"" + std::string(43, access) +
                                    "\",\"token_type\":\"bearer\",\"nodes\":[],\"nodes_next_cursor\":null,\"session_deadline\":" +
                                    deadline() + ",\"refresh_token\":\"" + std::string(43, renewal) +
                                    "\",\"refresh_expires_at\":" + std::to_string(base + 14 * 86400) + "}")};
    if (path == "/control/v1/auth/refresh") {
      if (offline) throw std::runtime_error("connection reset");
      if (status != 200) return {status, SerializedSecret("{}")};
      if (body.find("\"refresh_token\":\"" + std::string(43, renewal) + "\"") == body.npos) return {401, SerializedSecret("{}")};
      ++refreshes; ++access; ++renewal;
      return {200, SerializedSecret("{" + identity(base + 3600) + ",\"access_token\":\"" + std::string(43, access) +
                                    "\",\"token_type\":\"bearer\",\"session_deadline\":" + deadline() + ",\"refresh_token\":\"" +
                                    std::string(43, renewal) + "\",\"refresh_expires_at\":" + std::to_string(base + 14 * 86400) + "}")};
    }
    assert(path == "/control/v1/session" && bearer == std::string(43, access));
    return {200, SerializedSecret("{" + identity(base + 3600) + "}")};
  }
};
template <class F> bool kept(F f) {
  try { f(); } catch (const SavedSignInKept&) { return true; } catch (...) {}
  return false;
}
}  // namespace

int main() {
  try {
    unsigned char random[8]{};
    if (BCryptGenRandom(nullptr, random, sizeof random, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return 1;
    std::string suffix;
    for (auto c : random) { suffix += "0123456789abcdef"[c >> 4]; suffix += "0123456789abcdef"[c & 15]; }
    Centre centre;
    centre.origin = "https://fixture-" + suffix + ".invalid";
    const auto config = detail::TestAccess::config(centre.origin);
    struct Erase { const PlatformConfig& c; ~Erase() { try { CredentialStore::erase(c); } catch (...) {} } } erase{config};

    assert(!CredentialStore::load(config, centre, wall));  // nothing saved
    auto first = Session::login(config, "alice", "password-for-test", centre, wall);
    CredentialStore::save(config, first);

    // Start 1: signs in from the saved renewal and saves the rotated one.
    auto resumed = CredentialStore::load(config, centre, wall);
    assert(resumed && centre.refreshes == 1 && resumed->renewable() && resumed->identity().central_session_id == sid);
    resumed->revalidate();
    // Start 2 works only if start 1 stored the new renewal (the old one is spent).
    assert(CredentialStore::load(config, centre, wall) && centre.refreshes == 2);

    // A refresh while running, then saving it (what the window's Centre does).
    auto running = CredentialStore::load(config, centre, wall);
    running->refresh();
    CredentialStore::save(config, *running);
    assert(CredentialStore::load(config, centre, wall) && centre.refreshes == 5);

    // Centre unreachable or failing: the saved sign-in is kept for next time.
    centre.offline = true;
    assert(kept([&] { (void)CredentialStore::load(config, centre, wall); }));
    centre.offline = false;
    centre.status = 503;
    assert(kept([&] { (void)CredentialStore::load(config, centre, wall); }));
    centre.status = 200;
    assert(CredentialStore::load(config, centre, wall));

    // Refused (session revoked, or a spent renewal): erased, next start shows sign-in.
    centre.status = 401;
    bool refused = false;
    try { (void)CredentialStore::load(config, centre, wall); } catch (const HttpStatusError& e) { refused = e.status_code() == 401; }
    assert(refused);
    centre.status = 200;
    assert(!CredentialStore::load(config, centre, wall));

    // Sign-out erases.
    auto again = Session::login(config, "alice", "password-for-test", centre, wall);
    CredentialStore::save(config, again);
    CredentialStore::erase(config);
    assert(!CredentialStore::load(config, centre, wall));
    std::puts("remember-login native store passed; central HTTPS not tested");
    return 0;
  } catch (const std::exception& e) {
    std::fprintf(stderr, "remember-login native store failed: %s\n", e.what());
    return 1;
  }
}
