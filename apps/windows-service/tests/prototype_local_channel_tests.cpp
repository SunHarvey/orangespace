#include "orangespace/prototype_local_channel.hpp"
#include <cassert>
#include <iostream>
using namespace orangespace::service;
int main() {
  chain::Binding b{"11111111-1111-4111-8111-111111111111","22222222-2222-4222-8222-222222222222","33333333-3333-4333-8333-333333333333","44444444-4444-4444-8444-444444444444",1,9000,31000};
  chain::LeaseBudget budget{std::string(chain::nd::lease_clock),1000,30000,31000};
  const auto text="{\"schema\":2,\"binding\":"+chain::binding_json(b)+",\"host\":\"127.0.0.1\",\"port\":19080,\"username\":\"FIXTURE_ONLY_USER\",\"password\":\"FIXTURE_ONLY_PASSWORD\",\"clock\":"+chain::quote(budget.clock)+",\"request_started_ms\":1000,\"remaining_ttl_ms\":30000,\"deadline_ms\":31000,\"proof_observed_at_ms\":1500}";
  auto channel=win::decode_local_channel(text,b,budget,2000);
  assert(channel.binding.same_authority(b) && channel.port==19080);
  assert(channel.username.view()=="FIXTURE_ONLY_USER" && channel.password.view()=="FIXTURE_ONLY_PASSWORD");
  static_assert(!std::is_copy_constructible_v<win::LocalChannel>);
  static_assert(std::is_nothrow_move_constructible_v<win::LocalChannel>);
  int negatives=0;
  auto reject=[&](std::string wire,std::int64_t now=2000,const chain::Binding* tuple=nullptr) {
    bool failed=false;try{(void)win::decode_local_channel(wire,tuple ? *tuple : b,budget,now);}catch(...){failed=true;}
    assert(failed);++negatives;
  };
  auto changed=[&](std::string_view from,std::string_view to){auto s=text;auto p=s.find(from);assert(p!=s.npos);s.replace(p,from.size(),to);return s;};
  reject(changed("127.0.0.1","localhost"));
  reject(changed("19080","0"));reject(changed("19080","65536"));
  reject(changed("19080","19080.0"));reject(changed("\"schema\":2","\"schema\":2e0"));
  reject(changed("FIXTURE_ONLY_USER","short"));reject(changed("FIXTURE_ONLY_PASSWORD",std::string(256,'X')));
  reject(changed("FIXTURE_ONLY_USER","FIXTURE ONLY USER"));
  reject(changed("\"schema\":2","\"extra\":1,\"schema\":2"));
  reject(changed("\"schema\":2","\"schema\":2,\"schema\":2"));
  reject(changed("\"schema\":2,",""));reject(text+"{}");
  reject(changed("request_started_ms\":1000","request_started_ms\":1001"));
  reject(changed("remaining_ttl_ms\":30000","remaining_ttl_ms\":29999"));
  reject(changed("deadline_ms\":31000","deadline_ms\":31001"));
  reject(changed(budget.clock,"wrong-clock"));
  reject(changed("proof_observed_at_ms\":1500","proof_observed_at_ms\":2001"));
  reject(text,4500);reject(text,31000);
  auto wrong=b;wrong.generation++;reject(text,2000,&wrong);
  std::cout << "prototype channel positive + " << negatives << " strict negative cases passed\n";
}
