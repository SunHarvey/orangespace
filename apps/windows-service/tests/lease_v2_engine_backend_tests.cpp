// Production Engine and exact backend cleanup, real Rust no-helper handle.
#define SERVICE_STOP_MAIN supplied_stop_main
#include "service_stop_tests.cpp"
#include "orangespace_runtime.h"
#include <set>
namespace detail=orangespace::node_session::detail;
#include "engine_backend_under_test.hpp"
struct EngineBackend : FakeBackend, ExactBackend {
  void fail_closed() noexcept override {ExactBackend::fail_closed();}
  void reserve(std::string_view realm,const Binding& b) override {ExactBackend::reserve(realm,b);}
  void close(std::string_view realm,const Binding& b) noexcept override {ExactBackend::close(realm,b);}
  void release(std::string_view realm) noexcept override {ExactBackend::release(realm);}
};
static void reserve_allocation_tests() {
  const std::string realm="44444444-4444-4444-8444-444444444444";
  const Binding first{"11111111-1111-4111-8111-111111111111","22222222-2222-4222-8222-222222222222","33333333-3333-4333-8333-333333333333","55555555-5555-4555-8555-555555555555",1,130,130000};
  auto second=first;second.tunnel="66666666-6666-4666-8666-666666666666";
  long counts[2]{};
  for(bool existing:{false,true}) {
    ExactBackend backend;
    if(existing)backend.reserve(realm,first);
    allocations=0;backend.reserve(realm,existing?second:first);counts[existing]=allocations;
    backend.release(realm);
  }
  check(counts[0]>0 && counts[1]>0,"reserve allocation positive controls");
  for(bool existing:{false,true})for(bool sticky:{false,true})for(long seam=0;seam<counts[existing];++seam) {
    ExactBackend backend;
    if(existing)backend.reserve(realm,first);
    const auto saved=existing?backend.realms_.at(realm):nullptr;
    // Repeat the same failure without retiring: neither empty realms nor active
    // reservations may accumulate and silently consume the global 64-slot cap.
    for(int attempt=0;attempt<64;++attempt) {
      allocation_budget=seam;sticky_failure=sticky;bool denied=false;
      try{backend.reserve(realm,existing?second:first);}catch(const std::bad_alloc&){denied=true;}
      allocation_budget=-1;sticky_failure=false;
      check(denied,"every counted reserve allocation must fail");
      check(backend.realms_.size()==(existing?1u:0u),"failed reserve must not publish a null/empty realm");
      if(existing)check(backend.realms_.at(realm)==saved && !saved->retired && saved->active.size()==1 && saved->active.at(first.tunnel).same_authority(first) && !saved->active.at(first.tunnel).submitted,"existing realm reserve has strong rollback including metadata/submitted state");
    }
    // Cleanup is allocation-free even after persistent reserve failure.
    allocation_budget=0;sticky_failure=true;backend.release(realm);
    allocation_budget=-1;sticky_failure=false;
    check(backend.realms_.empty(),"release after reserve failure clears safely");
    std::array<std::string,64> realms;
    for(int i=0;i<64;++i){realms[i]=realm+std::to_string(i);backend.reserve(realms[i],first);}
    bool denied=false;try{backend.reserve("overflow",first);}catch(...){denied=true;}
    check(denied && backend.realms_.size()==64,"64 failed attempts cannot drift new-realm capacity; exact 64 bound retained");
    allocation_budget=0;sticky_failure=true;for(const auto& name:realms)backend.release(name);
    allocation_budget=-1;sticky_failure=false;
  }
  std::cout<<"PASS exact reserve counted seams new="<<counts[0]<<" existing="<<counts[1]<<" transient+sticky x64, safe release and capacity\n";
}
struct ReserveFaultBackend : EngineBackend {
  bool arm_after_reserve{};
  long after_reserve_budget{};
  bool persistent{};
  int reserves{},completed{};
  long before_reserve_allocations{},reserve_allocations{};
  void reserve(std::string_view realm,const Binding& b) override {
    ++reserves;before_reserve_allocations=allocations;
    ExactBackend::reserve(realm,b);++completed;
    reserve_allocations=allocations-before_reserve_allocations;
    if(arm_after_reserve){allocation_budget=after_reserve_budget;sticky_failure=persistent;}
  }
};
static std::size_t retained(const ReserveFaultBackend& backend) {
  std::size_t count=0;
  for(const auto& [_,state]:backend.realms_){check(bool(state),"no null realm after Engine failure");count+=state->active.size();}
  return count;
}
static void pending_reservation_boundary_tests() {
  const orangespace::service::Peer p{"S-1-5-21-100",1,99};
  for(bool sticky:{false,true}) {
    ReserveFaultBackend backend;Engine engine(p,backend,[]{return 100;});
    const auto auth=engine.authorize(p,"reserve-fault","{}");
    backend.arm_after_reserve=true;backend.persistent=sticky;
    for(int attempt=0;attempt<64;++attempt) {
      bool denied=false;try{(void)engine.start(p,auth);}catch(const std::bad_alloc&){denied=true;}
      allocation_budget=-1;sticky_failure=false;
      check(denied && backend.completed==attempt+1 && backend.started==0,"postreserve failure reached real Engine boundary before backend start");
      check(retained(backend)==0,"failed pending preparation must not strand an uncounted backend reservation");
    }
    backend.arm_after_reserve=false;
    std::array<std::string,64> realms;
    Binding probe{"u","s","n","t",1};
    for(int i=0;i<64;++i){realms[i]="probe-"+std::to_string(i);backend.ExactBackend::reserve(realms[i],probe);}
    check(retained(backend)==64,"64 failed Engine starts leave all backend slots available");
    for(const auto& realm:realms)backend.release(realm);
    engine.retire(p,auth);
    check(backend.realms_.empty(),"retire after failed start has no null realm");
  }
  std::cout<<"PASS real Engine postreserve allocation failure x64 transient+sticky, no uncounted reservations\n";
}
static void prepared_pending_sweeps() {
  const orangespace::service::Peer p{"S-1-5-21-100",1,99};
  for(bool provisional:{false,true})for(bool existing:{false,true}) {
    long before=0,reserve=0,after=0;
    {
      ReserveFaultBackend backend;Engine engine(p,backend,[]{return 100;});
      const auto auth=engine.authorize(p,"count-pending","{}");
      if(existing)(void)engine.start(p,auth);
      allocations=0;(void)engine.start(p,auth,{},provisional);
      before=backend.before_reserve_allocations;reserve=backend.reserve_allocations;
      after=allocations-before-reserve;
    }
    check(before>0 && reserve>0 && after>0,"counted real Engine preparation/reserve/publication positive controls");
    for(bool sticky:{false,true})for(bool postreserve:{false,true})for(long seam=0;seam<(postreserve?after:before+reserve);++seam) {
      ReserveFaultBackend backend;Engine engine(p,backend,[]{return 100;});
      const auto auth=engine.authorize(p,"sweep-pending","{}");
      std::optional<Binding> sibling;
      if(existing)sibling=engine.start(p,auth);
      const auto held=existing?backend.realms_.at(auth):nullptr;
      const auto saved=sibling?std::optional<Binding>{held->active.at(sibling->tunnel)}:std::nullopt;
      const auto reserves_before=backend.completed;
      backend.arm_after_reserve=postreserve;backend.after_reserve_budget=seam;backend.persistent=sticky;
      allocation_budget=postreserve?-1:seam;sticky_failure=sticky;
      bool denied=false;try{(void)engine.start(p,auth,{},provisional);}catch(const std::bad_alloc&){denied=true;}
      allocation_budget=-1;sticky_failure=false;backend.arm_after_reserve=false;
      check(denied,"every counted prepared/reserved/published allocation seam must fail");
      if(postreserve)check(backend.completed==reserves_before+1,"postreserve sweep actually owns a reservation");
      else check(backend.completed==reserves_before,"all preparation/reserve failures precede successful reservation");
      if(backend.poisoned_) {
        check(!postreserve && retained(backend)==0 && backend.realms_.empty(),"durable preparation failure retains production fatal fail-closed policy");
        if(held)check(held->retired && held->active.size()==1,"held sibling realm retired by production poison");
      } else {
        check(retained(backend)==(existing?1u:0u),"no uncounted reservation after any prepared/pending/publication allocation failure");
        if(sibling) {
          check(!held->retired && backend.realms_.at(auth)==held && held->active.at(sibling->tunnel).same_authority(*saved),"ordinary allocation rollback preserves sibling and exact metadata");
          auto wrong=*sibling;++wrong.generation;
          allocation_budget=0;sticky_failure=true;backend.close(auth,wrong);
          allocation_budget=-1;sticky_failure=false;
          check(held->active.contains(sibling->tunnel),"wrong-tuple allocation-free close cannot clear surviving owner");
          check(engine.status(p,auth).find(sibling->tunnel)!=std::string::npos,"surviving sibling remains authorized");
        }
        // Counted a->pending is restored, not merely backend capacity. Fill all
        // remaining slots through the Engine itself without retire as a crutch.
        for(int i=existing?1:0;i<64;++i)(void)engine.start(p,auth);
        check(retained(backend)==64,"failed pending setup cannot drift Engine or backend 64-capacity");
        bool bounded=false;try{(void)engine.start(p,auth);}catch(...){bounded=true;}
        check(bounded && retained(backend)==64,"original 64 bound still denies new work");
      }
      allocation_budget=0;sticky_failure=true;engine.retire(p,auth);
      allocation_budget=-1;sticky_failure=false;
      check(backend.realms_.empty(),"allocation-free retire after every swept failure");
    }
    std::cout<<"PASS Engine allocation sweep provisional="<<provisional<<" existing="<<existing<<" prepared="<<before<<" reserve="<<reserve<<" postreserve="<<after<<" transient+sticky, sibling/poison/exact/capacity\n";
  }
}
static void pending_exact_tuple_test() {
  const orangespace::service::Peer p{"S-1-5-21-100",1,99};
  EngineBackend backend;Engine engine(p,backend,[]{return 100;});
  const auto auth=engine.authorize(p,"exact-pending","{}");
  const auto sibling=engine.start(p,auth);const auto state=backend.realms_.at(auth);
  bool visited=false;
  backend.last->on_create=[&] {
    visited=true;
    const auto it=std::find_if(state->active.begin(),state->active.end(),[&](const auto& entry){return entry.first!=sibling.tunnel;});
    check(it!=state->active.end(),"real Engine pending tuple is reserved before remote create");
    const Binding pending=it->second;auto wrong=pending;++wrong.generation;
    auto peer=p;++peer.logon;
    for(int scenario=0;scenario<3;++scenario) {
      bool denied=false;
      try {
        if(scenario==0)(void)engine.start(peer,auth,Cursor{pending.sandbox,pending.generation});
        if(scenario==1)(void)engine.start(p,auth,Cursor{pending.sandbox,pending.generation+1});
        if(scenario==2)(void)engine.stop(p,auth,Cursor{pending.sandbox,pending.generation+1});
      }catch(...){denied=true;}
      check(denied && state->active.size()==2 && state->active.contains(pending.tunnel),"wrong peer/CAS cannot clear old pending owner");
    }
    allocation_budget=0;sticky_failure=true;backend.close(auth,wrong);
    allocation_budget=-1;sticky_failure=false;
    check(state->active.size()==2,"wrong-tuple backend close preserves pending and sibling without allocations");
  };
  const auto live=engine.start(p,auth);
  check(visited && engine.cursor(p,auth,live.sandbox).generation==live.generation && engine.status(p,auth).find(live.tunnel)!=std::string::npos,"rejected wrong tuples leave exact pending publication intact");
}
int main(int argc,char** argv) {
  if(argc==2 && std::string_view(argv[1])=="own1"){reserve_allocation_tests();return 0;}
  if(argc==2 && std::string_view(argv[1])=="own2"){pending_reservation_boundary_tests();return 0;}
  reserve_allocation_tests();
  pending_reservation_boundary_tests();
  prepared_pending_sweeps();
  pending_exact_tuple_test();
  orangespace::service::Peer peer{"S-1-5-21-100",1,99};
  std::int64_t mono=100000;EngineBackend backend;
  Engine engine(peer,backend,[]{return 100;},std::make_shared<Namespace>(),[&]{return mono;});
  auto auth=engine.authorize(peer,"budget-sibling","{}");backend.last->clock=[&]{return mono;};
  auto sibling=engine.start(peer,auth);
  auto state=backend.realms_.at(auth);
  constexpr std::string_view helper="/usr/bin/true";
  state->runtime=os_runtime_new(reinterpret_cast<const std::uint8_t*>(helper.data()),helper.size(),1000);
  check(state->runtime!=nullptr,"real Rust no-helper runtime created");auto handle=state->runtime;
  backend.last->on_create=[&]{mono+=30000;};
  bool denied=false;try{(void)engine.start(peer,auth);}catch(...){denied=true;}
  check(denied && backend.started==1,"actual Engine create-budget failure before backend submission");
  check(!state->retired && state->runtime==handle && backend.realms_.contains(auth) && state->active.size()==1 && state->active.contains(sibling.tunnel),"reserved-only rollback must preserve sibling realm and remove exact reservation");
  constexpr std::string_view poll=R"({"schema":2,"op":"poll"})";
  std::array<std::uint8_t,65536> output{};
  check(os_runtime_call(handle,reinterpret_cast<const std::uint8_t*>(poll.data()),poll.size(),output.data(),output.size())>0,"same real Rust handle remains usable");
  // Unknown Rust tuple genuinely returns -1: do not mask it with always-ok FFI.
  bool unknown_denied=false;try{(void)backend.call(handle,"{\"schema\":2,\"op\":\"close\",\"binding\":"+binding_json(sibling)+"}");}catch(...){unknown_denied=true;}
  check(unknown_denied,"real Rust rejects an unknown tuple");
  // An ordinary Invalid close now needs exact, fresh absence confirmation;
  // it is not a fatal runtime error by itself. This runtime owns no helpers.
  auto keeper=sibling;keeper.sandbox="77777777-7777-4777-8777-777777777777";
  keeper.tunnel="88888888-8888-4888-8888-888888888888";
  backend.reserve(auth,keeper);
  const auto saved=state->active.at(keeper.tunnel);
  state->active.at(sibling.tunnel).submitted=true;
  backend.close(auth,sibling);
  check(!state->retired && state->runtime==handle && backend.realms_.contains(auth) &&
        state->active.size()==1 && state->active.at(keeper.tunnel).same_authority(saved),
        "real exact absent-close reply preserves shared runtime and sibling reservation");
  check(os_runtime_call(handle,reinterpret_cast<const std::uint8_t*>(poll.data()),poll.size(),output.data(),output.size())>0,
        "confirmed-absence cleanup leaves original real runtime handle usable");
  // A genuinely invalidated handle is still fatal; never blanket-ignore errors.
  os_runtime_free(handle);
  state->active.at(keeper.tunnel).submitted=true;
  backend.close(auth,keeper);
  check(state->retired && !state->runtime && !backend.realms_.contains(auth),"fatal Rust handle error must release realm");
  check(os_runtime_call(handle,reinterpret_cast<const std::uint8_t*>(poll.data()),poll.size(),output.data(),output.size())==OS_RUNTIME_ERROR_HANDLE,"fatal control retains invalid-handle rejection");
  std::cout<<"PASS Engine rollback and exact absence preserve original Rust no-helper handle/reservation; fatal handle still fails closed (not native/helper forwarding proof)\n";
}
