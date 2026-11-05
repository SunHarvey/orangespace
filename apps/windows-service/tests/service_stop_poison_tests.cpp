#define SERVICE_STOP_MAIN stop_sweep_main
#include "service_stop_tests.cpp"
#include "orangespace_runtime.h"
namespace detail = orangespace::service::chain::nd;
#include "stop_poison_under_test.hpp"
struct ProductionPoisonBackend : StopBackend, ExtractedPoison {
  void reserve(std::string_view realm,const Binding& b) override {ExtractedPoison::reserve(realm,b);StopBackend::reserve(realm,b);}
  void fail_closed() noexcept override {ExtractedPoison::fail_closed();StopBackend::fail_closed();}
};
int main() {
  orangespace::service::Peer p{"S-1-5-21-100",1,99},other{"S-1-5-21-200",2,100};
  ProductionPoisonBackend backend;bool fail_save=false;
  auto space=std::make_shared<Namespace>([]{return std::vector<Persisted>{};},[&](const auto&){
    if(fail_save){allocation_budget=0;sticky_failure=true;throw std::bad_alloc();}
  });
  Engine first(p,backend,[]{return 100;},space),second(other,backend,[]{return 100;});
  auto a=first.authorize(p,"first","{}"),b=second.authorize(other,"second","{}");
  auto x=first.start(p,a),y=second.start(other,b);
  auto sx=backend.realms_.at(a),sy=backend.realms_.at(b);
  constexpr std::string_view helper="/usr/bin/true";
  sx->runtime=os_runtime_new(reinterpret_cast<const uint8_t*>(helper.data()),helper.size(),1000);
  sy->runtime=os_runtime_new(reinterpret_cast<const uint8_t*>(helper.data()),helper.size(),1000);
  check(sx->runtime && sy->runtime,"real host Rust runtimes created (no helper launch)");
  const auto old_x=sx->runtime,old_y=sy->runtime;
  Cursor c{x.sandbox,x.generation};fail_save=true;bool failed=false;
  try{(void)first.stop(p,a,c);}catch(const std::bad_alloc&){failed=true;}
  allocation_budget=-1;sticky_failure=false;
  check(failed && backend.close_calls==1,"exact local close precedes failed durable write");
  check(backend.live.empty() && backend.realms_.empty() && sx->retired && sy->retired && !sx->runtime && !sy->runtime,
        "shared production poison synchronously retires both realms and frees real runtimes");
  constexpr std::string_view poll=R"({"schema":2,"op":"poll"})";
  std::array<uint8_t,65536> response{};
  for(auto token:{old_x,old_y})check(os_runtime_call(token,reinterpret_cast<const uint8_t*>(poll.data()),poll.size(),response.data(),response.size())==OS_RUNTIME_ERROR_HANDLE,
                                   "both freed real Rust handles reject future calls");
  bool denied=false;try{ExtractedPoison& native=backend;native.reserve(b,y);}catch(...){denied=true;}
  check(denied,"extracted production reservation sticky-denied after poison");
  denied=false;try{(void)first.status(p,a);}catch(...){denied=true;}check(denied,"failed namespace exposes no proof");
  denied=false;try{(void)second.status(other,b);}catch(...){denied=true;}check(denied,"other namespace cannot expose poisoned backend proof");
  first.retire(p,a);second.retire(other,b);
  std::cout<<"PASS shared backend poison: extracted production retire/free/reservation with real Rust; modeled helper liveness, NOT native acceptance\n";
}
