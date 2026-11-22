#include "orangespace/node_session.hpp"
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace ns = orangespace::node_session;
template<class F> void http_rejection(unsigned expected, F action) {
  try { action(); }
  catch (const ns::HttpStatusError& error) {
    if (error.status_code() == expected && std::string_view(error.what()) == "node HTTPS response rejected") return;
    throw std::runtime_error("HTTP failure metadata changed or exposed response text");
  }
  catch (const std::exception&) {
    throw std::runtime_error("HTTP rejection lost its fixed failure category");
  }
  throw std::runtime_error("HTTP failure accepted");
}
int main() {
  const ns::detail::NodeEntry node{"test", "11111111-1111-4111-8111-111111111111", "node.example.test", 443};
  const ns::detail::Identity identity{"22222222-2222-4222-8222-222222222222", "test-user", node.node_id};
  constexpr std::string_view rejected_body = "{\"detail\":\"DO_NOT_ECHO_RESPONSE_SECRET\"}";
  for (unsigned status : {401u, 403u, 429u, 503u})
    http_rejection(status, [&] { (void)ns::detail::validate_login(node, status, node.node_id, rejected_body, 100); });
  http_rejection(403, [&] { (void)ns::detail::validate_me(node, 403, node.node_id, rejected_body); });
  http_rejection(401, [&] { (void)ns::detail::validate_session(node, identity, 401, node.node_id, rejected_body, 100); });
  // Tunnel create and renew refusals (e.g. the Centre refusing a replayed
  // generation) keep their status, so the caller can tell 401 from the rest.
  const std::string tunnel_request = "{\"sandbox_id\":\"44444444-4444-4444-8444-444444444444\",\"generation\":1,\"tunnel_id\":\"55555555-5555-4555-8555-555555555555\"}";
  for (unsigned status : {401u, 409u, 503u}) {
    http_rejection(status, [&] { (void)ns::detail::validate_tunnel(node, identity, tunnel_request, status, node.node_id, rejected_body, 100, 200, std::string(43, 'a'), 1000, 1100); });
    http_rejection(status, [&] { (void)ns::detail::validate_renew(node, "55555555-5555-4555-8555-555555555555", status, node.node_id, rejected_body, 100, 200, 1000, 1100); });
  }
  for (const auto& foreign : {std::string_view("33333333-3333-4333-8333-333333333333"), std::string_view()}) {
    bool tunnel_foreign = false, renew_foreign = false;
    try { (void)ns::detail::validate_tunnel(node, identity, tunnel_request, 409, foreign, rejected_body, 100, 200, std::string(43, 'a'), 1000, 1100); }
    catch (const ns::HttpStatusError&) {} catch (const std::exception&) { tunnel_foreign = true; }
    try { (void)ns::detail::validate_renew(node, "55555555-5555-4555-8555-555555555555", 409, foreign, rejected_body, 100, 200, 1000, 1100); }
    catch (const ns::HttpStatusError&) {} catch (const std::exception&) { renew_foreign = true; }
    if (!tunnel_foreign || !renew_foreign) throw std::runtime_error("a tunnel refusal from another node must not expose a status");
  }
  bool untrusted_header_rejected = false;
  try { (void)ns::detail::validate_login(node, 401, "33333333-3333-4333-8333-333333333333", rejected_body, 100); }
  catch (const std::exception& error) { untrusted_header_rejected = std::string_view(error.what()) != "node HTTPS response rejected"; }
  if (!untrusted_header_rejected) throw std::runtime_error("foreign node must not be classified as authenticated HTTP rejection");
  std::cout << "node HTTP rejection classification policy passed; not native HTTPS acceptance\n";
}
