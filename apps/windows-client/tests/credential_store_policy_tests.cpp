#include "orangespace/credential_store.hpp"
#include <iostream>
namespace ns = orangespace::node_session;
int main() {
  using ns::detail::AceKind;
  using ns::detail::Ace;
  const std::vector<Ace> good{{AceKind::allow, true, 0x1f01ff}};
  if (!ns::credential_detail::secure_user_acl(true, true, true, good)) return 1;
  if (ns::credential_detail::secure_user_acl(false, true, true, good)) return 2;
  if (ns::credential_detail::secure_user_acl(true, false, true, good)) return 3;
  if (ns::credential_detail::secure_user_acl(true, true, false, good)) return 4;
  for (unsigned mask : {1u, 2u, 4u, 0x10000u, 0x40000u, 0x10000000u}) {
    auto bad = good; bad.push_back({AceKind::allow, false, mask});
    if (ns::credential_detail::secure_user_acl(true, true, true, bad)) return 5;
  }
  if (ns::credential_detail::secure_user_acl(true, true, true, {{AceKind::unsupported, true, 0}})) return 6;
  const ns::detail::NodeEntry node{"office", "11111111-1111-4111-8111-111111111111", "node.example", 443};
  const auto entropy = ns::credential_detail::entropy("S-1-5-21-100", node);
  if (entropy == ns::credential_detail::entropy("S-1-5-21-101", node)) return 7;
  auto other = node; other.host = "other.example";
  if (entropy == ns::credential_detail::entropy("S-1-5-21-100", other)) return 8;
  other = node; other.node_id = "22222222-2222-4222-8222-222222222222";
  if (entropy == ns::credential_detail::entropy("S-1-5-21-100", other)) return 9;
  other = node; other.api_prefix = "/nodes/" + node.node_id;
  if (entropy == ns::credential_detail::entropy("S-1-5-21-100", other)) return 10;
  std::cout << "credential ACL/entropy policy: passed\n";
}
