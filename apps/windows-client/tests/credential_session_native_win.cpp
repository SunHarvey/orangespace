// Native integration runner. Input is supplied over a protected stdin pipe,
// never argv/environment: first line username, second line password.
#include "orangespace/credential_store.hpp"
#include <iostream>
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
namespace ns = orangespace::node_session;
int wmain(int argc, wchar_t** argv) {
  if (argc != 3 && argc != 4) return 2; // Catalog, alias, optional --tunnels.
  if (argc == 4 && std::wstring_view(argv[3]) != L"--tunnels") return 2;
  std::string username, password;
  struct Cleanup { std::string& a; std::string& b; ~Cleanup() { ns::detail::wipe(a.data(), a.size()); ns::detail::wipe(b.data(), b.size()); } } cleanup{username, password};
  try {
    std::getline(std::cin, username); std::getline(std::cin, password);
    const std::wstring wide_alias(argv[2]);
    const std::string alias(wide_alias.begin(), wide_alias.end());
    // Use an isolated administrator-protected TEST node UUID: save replaces the
    // current user's entry for that node. Never point this runner at a live user.
    const auto catalog = ns::TrustedCatalog::load(argv[1]);
    auto session = ns::NodeSession::login(catalog, alias, username, password);
    struct RemoveSaved {
      const ns::TrustedCatalog& catalog; const std::string& alias;
      ~RemoveSaved() { try { ns::CredentialStore::erase(catalog, alias); } catch (...) {} }
    } remove_saved{catalog, alias};
    ns::CredentialStore::save(catalog, alias, session);
    auto restored = ns::CredentialStore::load(catalog, alias);
    if (restored.identity().user_id != session.identity().user_id) return 3;
    auto envelope = session.credential_envelope();
    struct Wipe { std::string& s; ~Wipe() { ns::detail::wipe(s.data(), s.size()); } } wipe{envelope};
    auto again = ns::NodeSession::restore_envelope(catalog, alias, envelope);
    if (again.identity().user_id != session.identity().user_id) return 4;
    if (argc == 4) {
      // Requires an explicitly enabled TEST grant and protected runtime. No
      // implicit permission follows from login; the default runner omits this.
      const auto fresh_id = [] {
        unsigned char bytes[16]{};
        if (BCryptGenRandom(nullptr, bytes, sizeof(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG)) throw std::runtime_error("test random failed");
        constexpr char hex[] = "0123456789abcdef"; std::string id;
        for (auto c : bytes) { id += hex[c >> 4]; id += hex[c & 15]; }
        for (auto p : {8u, 13u, 18u, 23u}) id.insert(p, "-");
        return id;
      };
      const auto tunnel = fresh_id();
      const auto request = "{\"sandbox_id\":\"" + fresh_id() + "\",\"generation\":1,\"tunnel_id\":\"" + tunnel + "\"}";
      struct Revoke {
        const ns::NodeSession& session; const std::string& id;
        ~Revoke() { try { session.revoke_tunnel(id); } catch (...) {} }
      } revoke{again, tunnel};
      const auto lease = again.create_tunnel(request); (void)lease;
      const auto renewal = again.renew_tunnel(tunnel); (void)renewal;
      again.revoke_tunnel(tunnel);
      again.revoke_tunnel(tunnel); // Owner-only idempotence, never resurrection.
      std::cout << "native tunnel lifecycle: passed\n";
    }
    restored.logout();
    bool rejected = false;
    try { (void)ns::CredentialStore::load(catalog, alias); } catch (...) { rejected = true; }
    ns::CredentialStore::erase(catalog, alias);
    if (!rejected) return 5;
    std::cout << "native credential/session roundtrip and revoked restore: passed\n";
    return 0;
  } catch (...) { std::cerr << "native credential/session test failed\n"; return 1; }
}
#endif
