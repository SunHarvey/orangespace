#include "orangespace/node_session.hpp"
#include <iostream>
namespace d = orangespace::node_session::detail;
int main() {
  const d::NodeEntry n{"office", "11111111-1111-4111-8111-111111111111", "node.example", 443};
  const d::Identity i{"22222222-2222-4222-8222-222222222222", "alice", n.node_id};
  const std::string b = "{\"user_id\":\"" + i.user_id + "\",\"username\":\"alice\",\"node_id\":\"" + n.node_id + "\",\"expires_at\":2000000000}";
  if (d::validate_session(n, i, 200, n.node_id, b, 1900000000) != 2000000000) return 1;
  bool rejected = false;
  try { (void)d::validate_session(n, i, 200, n.node_id, b, 2000000000); } catch (...) { rejected = true; }
  if (!rejected) return 2;
  const std::string envelope = "{\"schema\":1,\"node_id\":\"" + n.node_id + "\",\"api_origin\":\"https://node.example:443\",\"access_token\":\"" + std::string(43, 'a') + "\",\"expires_at\":2000000000}";
  const auto saved = d::validate_envelope(n, envelope, 1900000000);
  if (saved.token.size() != 43 || saved.expires_at != 2000000000) return 3;
  for (const auto& bad : {std::string("http://node.example:443"), std::string("https://other.example:443")}) {
    auto tampered = envelope; const auto at = tampered.find("https://node.example:443");
    tampered.replace(at, std::string("https://node.example:443").size(), bad);
    rejected = false;
    try { (void)d::validate_envelope(n, tampered, 1900000000); } catch (...) { rejected = true; }
    if (!rejected) return 4;
  }
  rejected = false;
  try { (void)d::validate_envelope(n, envelope, 2000000000); } catch (...) { rejected = true; }
  if (!rejected) return 5;
  const std::string request = "{\"sandbox_id\":\"" + i.user_id + "\",\"generation\":1,\"tunnel_id\":\"" + n.node_id + "\"}";
  d::validate_tunnel_request(request);
  rejected = false;
  try { d::validate_tunnel_request("{\"sandbox_id\":\"spoof\",\"generation\":0,\"tunnel_id\":\"bad\"}"); } catch (...) { rejected = true; }
  if (!rejected) return 6;
  const std::string renew = "{\"lease_schema\":2,\"remaining_ttl_ms\":29000,\"tunnel_id\":\"" + n.node_id + "\",\"expires_at\":1900000020,\"node_id\":\"" + n.node_id + "\"}";
  d::validate_renew(n, n.node_id, 200, n.node_id, renew, 1900000000, 2000000000, 100000, 100100);
  rejected = false;
  try { d::validate_renew(n, i.user_id, 200, n.node_id, renew, 1900000000, 2000000000, 100000, 100100); } catch (...) { rejected = true; }
  if (!rejected) return 7;
  std::string lease = "{\"lease_schema\":2,\"remaining_ttl_ms\":29000,\"user_id\":\"" + i.user_id + "\",\"node_id\":\"" + n.node_id + "\",\"sandbox_id\":\"" + i.user_id + "\",\"generation\":1,\"tunnel_id\":\"" + n.node_id + "\",\"expires_at\":1900000020,\"endpoint_ip\":\"192.0.2.1\",\"endpoint_port\":443,\"tls_server_name\":\"node.example\",\"tuic_uuid\":\"33333333-3333-4333-8333-333333333333\",\"tuic_password\":\"" + std::string(43, 'b') + "\",\"probe_host\":\"127.0.0.1\",\"probe_port\":8000,\"probe_request\":\"" + std::string(43, 'c') + "\",\"probe_response\":\"" + std::string(43, 'd') + "\"}";
  d::validate_tunnel(n, i, request, 200, n.node_id, lease, 1900000000, 2000000000, std::string(43, 'a'), 100000, 100100);
  // Captured native failure: server +subsecond skew/epoch rounding produced
  // 31 client-wall seconds for an authenticated <=30-second lease.
  auto skewed = lease;
  skewed.replace(skewed.find("1900000020"), 10, "1900000031");
  d::validate_tunnel(n, i, request, 200, n.node_id, skewed, 1900000000, 2000000000, std::string(43, 'a'), 100000, 100100);
  for (const auto& pair : {std::pair{"192.0.2.1", "node.example"}, {"127.0.0.1", "192.0.2.2"}, {"33333333-3333-4333-8333-333333333333", "22222222-2222-4222-8222-222222222222"}}) {
    auto bad = lease; const auto at = bad.find(pair.first); bad.replace(at, std::string(pair.first).size(), pair.second);
    rejected = false;
    try { d::validate_tunnel(n, i, request, 200, n.node_id, bad, 1900000000, 2000000000, std::string(43, 'a'), 100000, 100100); } catch (...) { rejected = true; }
    if (!rejected) return 8;
  }
  const auto changed = [](std::string value, std::string_view from, std::string_view to) {
    const auto at = value.find(from);
    if (at == std::string::npos) throw std::runtime_error("invalid test fixture");
    value.replace(at, from.size(), to); return value;
  };
  const auto rejects = [](auto run) {
    bool denied = false;
    try { run(); } catch (const std::exception& error) {
      denied = true;
      if (std::string_view(error.what()).find(std::string(43, 'a')) != std::string_view::npos)
        throw std::runtime_error("credential in error");
    }
    if (!denied) throw std::runtime_error("expected rejection");
  };
  for (const auto& bad : {
      changed(b, i.user_id, n.node_id), changed(b, "alice", "bob"),
      changed(b, "2000000000", "1900000000"), changed(b, "2000000000", "2000000000.5"),
      changed(b, "2000000000", "9007199254740992"), changed(b, "\"expires_at\"", "\"expiry\""),
      changed(b, "\"alice\"", "\"alice\",\"extra\":true"), b + "{}"})
    rejects([&] { (void)d::validate_session(n, i, 200, n.node_id, bad, 1900000000); });
  for (const auto& bad : {
      changed(envelope, "\"schema\":1", "\"schema\":2"),
      changed(envelope, n.node_id, i.user_id), changed(envelope, std::string(43, 'a'), std::string(42, 'a')),
      changed(envelope, "2000000000", "1900000000"),
      changed(envelope, "\"schema\":1", "\"schema\":1,\"user_id\":\"spoof\""),
      changed(envelope, "\"schema\":1", "\"schema\":1,\"schema\":1"), std::string(16385, 'x')})
    rejects([&] { (void)d::validate_envelope(n, bad, 1900000000); });
  for (const auto& bad : {
      changed(request, "\"generation\":1", "\"generation\":0"),
      changed(request, "\"generation\":1", "\"generation\":1.5"),
      changed(request, "\"generation\":1", "\"generation\":9007199254740992"),
      changed(request, "\"generation\":1", "\"generation\":true"),
      changed(request, "\"generation\":1", "\"generation\":1,\"user_id\":\"spoof\""),
      changed(request, n.node_id, "00000000-0000-0000-0000-000000000000")})
    rejects([&] { d::validate_tunnel_request(bad); });
  for (const auto& bad : {
      changed(lease, "\"user_id\":\"" + i.user_id, "\"user_id\":\"" + n.node_id),
      changed(lease, "\"node_id\":\"" + n.node_id, "\"node_id\":\"" + i.user_id),
      changed(lease, "\"sandbox_id\":\"" + i.user_id, "\"sandbox_id\":\"" + n.node_id),
      changed(lease, "\"generation\":1", "\"generation\":2"),
      changed(lease, "\"tunnel_id\":\"" + n.node_id, "\"tunnel_id\":\"" + i.user_id),
      changed(lease, "1900000020", "0"),
      changed(lease, "\"endpoint_port\":443", "\"endpoint_port\":0"),
      changed(lease, "\"endpoint_port\":443", "\"endpoint_port\":65536"),
      changed(lease, "\"probe_port\":8000", "\"probe_port\":8000.5"),
      changed(lease, "node.example", "node.example:443"), changed(lease, "node.example", "node.example/path"),
      changed(lease, "node.example", "node\\\\u002eexample"),
      changed(lease, std::string(43, 'b'), std::string(43, 'a')),
      changed(lease, std::string(43, 'c'), std::string(43, 'd')),
      changed(lease, "\"probe_host\":\"127.0.0.1\"", "\"probe_host\":\"localhost\""),
      changed(lease, "\"generation\":1", "\"generation\":1,\"extra\":true")})
    rejects([&] { d::validate_tunnel(n, i, request, 200, n.node_id, bad, 1900000000, 2000000000, std::string(43, 'a'), 100000, 100100); });
  for (const auto& bad : {
      changed(lease, "\"lease_schema\":2", "\"lease_schema\":1"),
      changed(lease, "\"lease_schema\":2,", ""),
      changed(lease, "\"lease_schema\":2", "\"lease_schema\":2.0"),
      changed(lease, "\"lease_schema\":2", "\"lease_schema\":true"),
      changed(lease, "\"remaining_ttl_ms\":29000", "\"remaining_ttl_ms\":29000.000000000001"),
      changed(lease, "\"expires_at\":1900000020", "\"expires_at\":9007199254740990.5"),
      changed(lease, "\"remaining_ttl_ms\":29000", "\"remaining_ttl_ms\":0"),
      changed(lease, "\"remaining_ttl_ms\":29000", "\"remaining_ttl_ms\":30001"),
      changed(lease, "\"remaining_ttl_ms\":29000", "\"remaining_ttl_ms\":1.5"),
      changed(lease, "\"remaining_ttl_ms\":29000", "\"remaining_ttl_ms\":9007199254740992")})
    rejects([&] { d::validate_tunnel(n, i, request, 200, n.node_id, bad, 1900000000, 2000000000, std::string(43, 'a'), 100000, 100100); });
  const auto budget = d::validate_tunnel(n, i, request, 200, n.node_id, skewed, 1900000000, 2000000000, std::string(43, 'a'), 100000, 100100);
  if (budget.request_started_ms != 100000 || budget.deadline_ms != 129000 || budget.remaining_ttl_ms != 29000) return 9;
  d::validate_tunnel(n, i, request, 200, n.node_id, lease, 1900000035, 2000000000, std::string(43, 'a'), 100000, 100100);
  rejects([&] { d::validate_tunnel(n, i, request, 200, n.node_id, lease, 1900000000, 2000000000, std::string(43, 'a'), 100000, 129000); });
  rejects([&] { d::validate_tunnel(n, i, request, 200, n.node_id, lease, 1900000000, 2000000000, std::string(43, 'a'), 9007199254740990LL, 9007199254740990LL); });
  for (const auto& bad : {changed(renew, "\"lease_schema\":2", "\"lease_schema\":0"), changed(renew, "\"lease_schema\":2", "\"lease_schema\":2.0"), changed(renew, "\"remaining_ttl_ms\":29000", "\"remaining_ttl_ms\":2.9e4"), changed(renew, "\"remaining_ttl_ms\":29000", "\"remaining_ttl_ms\":0"), changed(renew, "\"lease_schema\":2,", ""), changed(renew, "\"lease_schema\":2", "\"lease_schema\":2,\"extra\":1")})
    rejects([&] { d::validate_renew(n, n.node_id, 200, n.node_id, bad, 1900000000, 2000000000, 100000, 100100); });
  for (unsigned status : {201u, 204u, 301u, 401u, 403u, 500u}) {
    rejects([&] { (void)d::validate_session(n, i, status, n.node_id, b, 1900000000); });
    rejects([&] { d::validate_tunnel(n, i, request, status, n.node_id, lease, 1900000000, 2000000000, std::string(43, 'a'), 100000, 100100); });
    rejects([&] { d::validate_renew(n, n.node_id, status, n.node_id, renew, 1900000000, 2000000000, 100000, 100100); });
  }
  rejects([&] { d::validate_tunnel(n, i, request, 200, n.node_id, lease, 1900000000, 1900000010, std::string(43, 'a'), 100000, 100100); });
  rejects([&] { d::validate_renew(n, n.node_id, 200, n.node_id, renew, 1900000000, 1900000010, 100000, 100100); });
  for (const auto* ip : {"127.0.0.1", "192.0.2.1", "2001:db8::1", "::1", "::", "1:2:3:4:5:6:7:8"})
    if (!d::literal_ip(ip)) throw std::runtime_error("valid literal rejected");
  for (const auto* ip : {"", "localhost", "1.2.3.4.", "01.2.3.4", "256.2.3.4", ":::", "1:2:3", "1::2::3", "[::1]", "fe80::1%1", "::ffff:192.0.2.1"})
    if (d::literal_ip(ip)) throw std::runtime_error("ambiguous literal accepted");
  std::cout << "session authority/envelope/lifecycle policy: passed\n";
}
