#include "orangespace/node_session.hpp"
#include <iostream>
namespace d = orangespace::node_session::detail;
int main() {
  const std::string first = "11111111-1111-4111-8111-111111111111";
  const std::string second = "22222222-2222-4222-8222-222222222222";
  auto entry = [](const std::string& alias, const std::string& id, const std::string& origin) {
    return "{\"name\":\"" + alias + "\",\"node_id\":\"" + id + "\",\"api_origin\":\"" + origin + "\"}";
  };
  auto catalog = [](const std::string& entries) { return "{\"schema\":1,\"nodes\":[" + entries + "]}"; };
  auto parsed = d::parse_catalog(catalog(entry("a", first, "https://node.example") + "," +
      entry("b", second, "https://node.example/nodes/" + second)));
  if (parsed.size() != 2 || !parsed[0].api_prefix.empty() || parsed[1].api_prefix != "/nodes/" + second) return 1;
  if (d::api_origin(parsed[1]) != "https://node.example:443/nodes/" + second) return 2;
  for (const auto* route : {"/healthz", "/v1/me", "/v1/session", "/v1/auth/login", "/v1/auth/logout", "/v1/tunnels"}) {
    if (d::api_path(parsed[0], route) != route || d::api_path(parsed[1], route) != "/nodes/" + second + route) return 5;
  }
  for (const auto& prefix : std::vector<std::string>{"/", "/v1", "/nodes/" + first, "/nodes/" + second + "/", "/nodes/" + second + "?x=1",
        "/nodes/" + second + "#x", "/nodes/" + second + "/../", "/nodes%2f" + second, "/nodes//" + second}) {
    bool rejected = false;
    try { (void)d::parse_catalog(catalog(entry("b", second, "https://node.example" + prefix))); } catch (...) { rejected = true; }
    if (!rejected) return 3;
  }
  auto prefixed = d::parse_catalog(catalog(entry("b", second, "https://node.example:443/nodes/" + second)));
  const auto envelope = "{\"schema\":1,\"node_id\":\"" + second + "\",\"api_origin\":\"" + d::api_origin(prefixed[0]) +
      "\",\"access_token\":\"" + std::string(43, 'a') + "\",\"expires_at\":2000000000}";
  (void)d::validate_envelope(prefixed[0], envelope, 1900000000);
  auto unprefixed = prefixed[0]; unprefixed.api_prefix.clear();
  bool rejected = false;
  try { (void)d::validate_envelope(unprefixed, envelope, 1900000000); } catch (...) { rejected = true; }
  if (!rejected) return 4;
  const auto rejected_catalog = [&](const std::string& entries) {
    bool denied = false;
    try { (void)d::parse_catalog(catalog(entries)); } catch (...) { denied = true; }
    if (!denied) throw std::runtime_error("duplicate origin or identity accepted");
  };
  rejected_catalog(entry("a", first, "https://node.example") + "," + entry("b", second, "https://node.example:443"));
  rejected_catalog(entry("a", second, "https://node.example/nodes/" + second) + "," +
      entry("b", second, "https://node.example:443/nodes/" + second));
  auto both_prefixed = d::parse_catalog(catalog(entry("a", first, "https://node.example/nodes/" + first) + "," +
      entry("b", second, "https://node.example/nodes/" + second)));
  if (both_prefixed.size() != 2) return 6;
  std::cout << "controlled node prefix: passed\n";
}
