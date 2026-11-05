#include "network_policy_win.hpp"
#include <cassert>
#include <iostream>
using namespace orangespace::wfp_prototype;
int main() {
  const auto offline = policyRules(Mode::Offline, 0);
  assert(offline.size() == 4);
  for (auto r : offline) assert(r.kind == RuleKind::All);
  const auto proxy = policyRules(Mode::ProxyOnly, 3128);
  assert(proxy.size() == 6);
  assert(proxy[0].kind == RuleKind::NonTcp);
  assert(proxy[1].kind == RuleKind::WrongAddress);
  assert(proxy[2].kind == RuleKind::WrongPort && proxy[2].port == 3128);
  for (unsigned protocol : {6u, 17u, 1u})
    for (auto address : {0x7f000001u, 0x7f000002u, 0x08080808u})
      for (unsigned port : {3128u, 3129u, 53u}) {
        bool denied = false;
        for (auto r : proxy) if (r.layer == Layer::ConnectV4)
          denied |= ruleMatches(r, protocol, address, port);
        assert(denied == !(protocol == 6 && address == 0x7f000001u && port == 3128));
      }
  for (unsigned i = 3; i < proxy.size(); ++i) assert(proxy[i].kind == RuleKind::All);
  bool rejected = false;
  try { (void)policyRules(Mode::ProxyOnly, 0); } catch (...) { rejected = true; }
  assert(rejected);
  rejected = false;
  try { (void)policyRules(Mode::Offline, 3128); } catch (...) { rejected = true; }
  assert(rejected);
  assert(policyRules(Mode::Offline, 0) == offline);
  std::cout << "policy condition/transition tests passed\n";
}
