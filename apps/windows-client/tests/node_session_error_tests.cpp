#include "orangespace/node_session.hpp"
#include <iostream>
#include <stdexcept>
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
  bool untrusted_header_rejected = false;
  try { (void)ns::detail::validate_login(node, 401, "33333333-3333-4333-8333-333333333333", rejected_body, 100); }
  catch (const std::exception& error) { untrusted_header_rejected = std::string_view(error.what()) != "node HTTPS response rejected"; }
  if (!untrusted_header_rejected) throw std::runtime_error("foreign node must not be classified as authenticated HTTP rejection");
  std::cout << "node HTTP rejection classification policy passed; not native HTTPS acceptance\n";
}
