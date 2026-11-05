// Actual Engine/Response regression; injected backend/ledger, NOT Windows acceptance.
// Reuse the existing allocation and liveness seam, not a second Engine model.
#define SERVICE_STOP_MAIN supplied_stop_main
#include "service_stop_tests.cpp"
#include "orangespace/service_client.hpp"
#include <array>

struct LateSession : FakeSession {
  const Binding* expected{};
  int attempts{}, successes{}, refreshes{}, renewals{};
  bool reject=true, allocate_on_revoke=false, allow_other=false;
  int other_attempts{};
  std::function<void(const Binding&)> during_revoke;
  void refresh() override {++refreshes;}
  RenewResult renew(const Binding&) override {++renewals;return {130,timing()};}
  void revoke(const Binding& b) override {
    if(expected && b!=*expected){check(allow_other,"cleanup must retain the SAME complete tuple");++other_attempts;return;}
    check(expected || allow_other,"test must identify every cleanup tuple");
    ++attempts;
    if(during_revoke)during_revoke(b);
    if(allocate_on_revoke) {auto* p=::operator new(32);::operator delete(p);}
    if(reject)throw 7; // nonallocating remote fault, including persistent OOM
    ++successes;
  }
};
struct LateBackend : StopBackend {
  std::shared_ptr<LateSession> session=std::make_shared<LateSession>();
  std::shared_ptr<Session> restore(std::string_view,std::string_view) override {return session;}
};
static Binding reply_binding(const Response& response) {
  const auto root=orangespace::json::parse(response.body);
  return orangespace::service_client::validate_binding(nd::field(root,"binding"));
}
static const orangespace::service::Peer local_peer{"S-1-5-21-100",1,99};

static bool poisoned(bool ack,bool oom=false,bool sticky=false) {
  LateBackend backend;bool fail=false;
  auto ns=std::make_shared<Namespace>([]{return std::vector<Persisted>{};},[&](const auto&){if(fail)throw 9;});
  Engine e(local_peer,backend,[]{return 100;},ns);
  auto auth=e.authorize(local_peer,"receipt","{}");auto response=e.start_response(local_peer,auth);
  const auto binding=reply_binding(response);backend.session->expected=&binding;
  fail=true;bool stopped=false;
  try{(void)e.stop(local_peer,auth,{binding.sandbox,binding.generation});}catch(...){stopped=true;}
  check(stopped && backend.poisoned && !backend.live.contains(binding.tunnel),"durable writer failure closes locally and poisons");
  backend.session->allocate_on_revoke=oom;
  if(oom){allocation_budget=0;sticky_failure=sticky;}
  response.finish(ack); // production noexcept boundary, both ACK values
  allocation_budget=-1;sticky_failure=false;
  const auto after_callback=backend.session->attempts;
  const auto success_after_callback=backend.session->successes;
  const auto local_closes=backend.close_calls;
  for(int dimension=0;dimension<3;++dimension) {
    auto foreign=local_peer;
    if(dimension==0)foreign.sid+="0";
    if(dimension==1)++foreign.session;
    if(dimension==2)++foreign.logon;
    bool denied=false;try{e.retire(foreign,auth);}catch(...){denied=true;}
    check(denied && backend.session->attempts==after_callback && backend.close_calls==local_closes,"receipt is original SID/session/LUID only");
  }
  backend.session->allocate_on_revoke=false;
  // Retirement and callback cleanup require no allocation even when remote revoke fails.
  allocations=0;allocation_budget=0;sticky_failure=true;
  e.retire(local_peer,auth);
  const auto cleanup_allocations=allocations;
  allocation_budget=-1;sticky_failure=false;
  const auto after_retry=backend.session->attempts;
  backend.session->reject=false;e.retire(local_peer,auth);
  const auto attempts=backend.session->attempts,successes=backend.session->successes;
  for(int op=0;op<3;++op) {
    bool denied=false;try{if(op==0)(void)e.start(local_peer,auth);else if(op==1)(void)e.status(local_peer,auth);else(void)e.cursor(local_peer,auth,binding.sandbox);}catch(...){denied=true;}
    check(denied,"cleanup receipt has no start/status/cursor authority after close");
  }
  const auto refreshes=backend.session->refreshes;e.tick();
  check(backend.session->refreshes==refreshes && backend.session->renewals==0,"poisoned cleanup receipt cannot refresh or renew");
  check(backend.session->logouts==0,"retire must not revoke API login");
  const bool ok=after_callback==1 && success_after_callback==0 && after_retry==2 && attempts==3 && successes==1 && cleanup_allocations==0;
  std::cout<<(ok?"PASS":"FAIL")<<" poison ack="<<ack<<" oom="<<oom<<" sticky="<<sticky
    <<" callback="<<after_callback<<" retry="<<after_retry<<" attempts="<<attempts<<" successes="<<successes<<" local_cleanup_allocations="<<cleanup_allocations<<'\n';
  return ok;
}
static void retirement_oom() {
  for(bool sticky:{false,true}) {
    LateBackend backend;Engine e(local_peer,backend,[]{return 100;});auto auth=e.authorize(local_peer,"retire-oom","{}");
    auto response=e.start_response(local_peer,auth);const auto binding=reply_binding(response);backend.session->expected=&binding;
    response.finish(false);backend.session->allocate_on_revoke=true;
    allocations=0;allocation_budget=0;sticky_failure=sticky;e.retire(local_peer,auth);
    const auto count=allocations;allocation_budget=-1;sticky_failure=false;
    check(count==1 && backend.session->attempts==2 && backend.session->successes==0,"only the injected remote operation allocates; OOM reinserts receipt without allocation");
    backend.session->allocate_on_revoke=false;backend.session->reject=false;e.retire(local_peer,auth);e.retire(local_peer,auth);
    check(backend.session->attempts==3 && backend.session->successes==1,"retirement OOM preserves exact receipt until success");
  }
  std::cout<<"PASS retirement revoke transient/sticky OOM, allocation-free receipt return, exact success consumed\n";
}
static void lifecycle() {
  for(int delivery=0;delivery<4;++delivery) {
    LateBackend backend;Engine e(local_peer,backend,[]{return 100;});auto auth=e.authorize(local_peer,"healthy","{}");
    const auto sibling=e.start(local_peer,auth);
    std::optional<Response> response(e.start_response(local_peer,auth));const auto binding=reply_binding(*response);
    backend.session->expected=&binding;backend.session->allow_other=true;
    allocations=0;allocation_budget=0;sticky_failure=true;
    if(delivery==0)response->finish(false);
    if(delivery==1)response.reset(); // disconnect/unwind destructor
    if(delivery==2)check(!response->deliver([](const auto&){return false;},[]{return false;}),"failed write cannot ACK");
    if(delivery==3)*response=Response{}; // move assignment completes old owner
    const auto count=allocations;allocation_budget=-1;sticky_failure=false;
    check(count==0 && backend.session->attempts==1 && !backend.live.contains(binding.tunnel),"nothrow rollback closes locally and retains exact receipt without allocation");
    check(backend.live.contains(sibling.tunnel),"failed response A cannot close healthy B");
    const auto status=e.status(local_peer,auth);
    check(status.find(sibling.tunnel)!=std::string::npos && status.find(binding.tunnel)==std::string::npos,"cleanup-only A has no proof, B remains independent");
    const auto renewals=backend.session->renewals;e.tick();
    check(backend.session->renewals==renewals+1 && backend.session->attempts==1,"only healthy B renews; rollback receipt cannot renew");
    e.retire(local_peer,auth);check(backend.session->attempts==2,"first retirement retries failed rollback");
    backend.session->reject=false;e.retire(local_peer,auth);e.retire(local_peer,auth);
    check(backend.session->attempts==3 && backend.session->successes==1,"successful receipt consumed, no extra remote retry");
  }
  // Replacement can complete WHILE the old callback's revoke is outstanding.
  for(bool fail_remote:{false,true}) {
    LateBackend backend;Engine e(local_peer,backend,[]{return 100;});auto auth=e.authorize(local_peer,"replace","{}");
    auto response=e.start_response(local_peer,auth);const auto old=reply_binding(response);
    backend.session->expected=&old;backend.session->allow_other=true;backend.session->reject=fail_remote;
    Binding newer;bool visited=false;
    backend.session->during_revoke=[&](const Binding&){if(!visited){visited=true;newer=e.start(local_peer,auth,Cursor{old.sandbox,old.generation});}};
    response.finish(false);backend.session->during_revoke={};
    check(visited && backend.live.contains(newer.tunnel) && e.status(local_peer,auth).find(newer.tunnel)!=std::string::npos,"late callback cannot erase/obstruct newer exact tuple");
    check(e.cursor(local_peer,auth,old.sandbox).generation==newer.generation && newer.generation==old.generation+1,"callback never resurrects generation");
    // Alias replacement detaches old work but must not drop its cleanup Session.
    const auto replacement=e.authorize(local_peer,"replace","{}");
    const auto newest=e.start(local_peer,replacement,Cursor{newer.sandbox,newer.generation});
    backend.session->reject=false;e.retire(local_peer,auth);e.retire(local_peer,auth);
    check(backend.live.contains(newest.tunnel) && e.status(local_peer,replacement).find(newest.tunnel)!=std::string::npos,"old exact receipt cannot destroy newer authorization/tuple");
    check(backend.session->attempts==(fail_remote?3:1) && backend.session->successes==1,"supersede retains failed receipt and stops retry after success");
  }
  // Callback owns its extracted node while retirement runs; late failure returns
  // cleanup authority, never local work. No engine lock is held across HTTPS.
  {
    LateBackend backend;Engine e(local_peer,backend,[]{return 100;});auto auth=e.authorize(local_peer,"concurrent","{}");
    auto response=e.start_response(local_peer,auth);const auto old=reply_binding(response);backend.session->expected=&old;
    std::promise<void> entered,release;auto barrier=release.get_future().share();
    backend.session->during_revoke=[&](const Binding&){entered.set_value();barrier.wait();};
    auto completing=std::async(std::launch::async,[&]{response.finish(false);});entered.get_future().wait();
    auto retiring=std::async(std::launch::async,[&]{e.retire(local_peer,auth);});
    const bool timely=retiring.wait_for(std::chrono::milliseconds(500))==std::future_status::ready;
    release.set_value();retiring.get();completing.get();backend.session->during_revoke={};
    check(timely && backend.live.empty(),"retire remains local and nonblocking during callback HTTPS");
    backend.session->reject=false;e.retire(local_peer,auth);e.retire(local_peer,auth);
    check(backend.session->attempts==2 && backend.session->successes==1,"late failure after retirement retains exact receipt");
  }
  // Production transport destroys its Response before Engine teardown. Teardown
  // is the documented in-memory receipt boundary, not a durable retry promise.
  {
    LateBackend backend;auto e=std::make_unique<Engine>(local_peer,backend,[]{return 100;});auto auth=e->authorize(local_peer,"destroy","{}");
    auto response=e->start_response(local_peer,auth);const auto binding=reply_binding(response);backend.session->expected=&binding;
    response.finish(false);allocations=0;allocation_budget=0;sticky_failure=true;e.reset();
    const auto count=allocations;allocation_budget=-1;sticky_failure=false;
    check(count==0 && backend.live.empty() && backend.session->attempts==1,"Engine teardown is allocation-free and retains no local work");
  }
  for(bool ack:{false,true}) {
    LateBackend backend;Engine e(local_peer,backend,[]{return 100;});auto auth=e.authorize(local_peer,"shutdown","{}");
    auto response=e.start_response(local_peer,auth);const auto binding=reply_binding(response);backend.session->expected=&binding;
    allocations=0;allocation_budget=0;sticky_failure=true;e.shutdown();const auto closes=backend.close_calls;response.finish(ack);
    const auto count=allocations;allocation_budget=-1;sticky_failure=false;
    check(count==0 && backend.live.empty() && backend.close_calls==closes && backend.session->attempts==0,"shutdown invalidates outstanding completion without resurrection or duplicate close");
  }
  {
    LateBackend backend;Engine e(local_peer,backend,[]{return 100;});auto auth=e.authorize(local_peer,"logout","{}");
    auto response=e.start_response(local_peer,auth);const auto binding=reply_binding(response);backend.session->expected=&binding;response.finish(false);
    backend.session->fail_logout=true;bool failed=false;try{e.logout(local_peer,auth);}catch(...){failed=true;}
    check(failed && backend.live.empty() && backend.session->attempts==2,"failed logout retains callback cleanup receipt");
    backend.session->reject=false;backend.session->fail_logout=false;e.logout(local_peer,auth);e.logout(local_peer,auth);e.retire(local_peer,auth);
    check(backend.session->attempts==3 && backend.session->successes==1 && backend.session->logouts==2,"logout retry drains callback receipt exactly once");
  }
  std::cout<<"PASS lifecycle: disconnect/write/move/destruction/shutdown, healthy B, replacement during callback, supersede, logout and threaded retire\n";
}
static void capacity() {
  LateBackend backend;Engine e(local_peer,backend,[]{return 100;});auto auth=e.authorize(local_peer,"bound","{}");
  std::array<Binding,64> bindings;std::array<int,64> retries{};
  std::optional<Cursor> prior;bool full_in_callback=false;
  for(auto& b:bindings) {
    auto response=e.start_response(local_peer,auth,prior);b=reply_binding(response);backend.session->expected=&b;
    prior=Cursor{b.sandbox,b.generation};
    if(&b==&bindings.back())backend.session->during_revoke=[&](const Binding&){
      const auto reserves=backend.reserve_calls;bool denied=false;
      try{(void)e.start(local_peer,auth,prior);}catch(...){denied=true;}
      full_in_callback=denied && backend.reserve_calls==reserves;
    };
    response.finish(false);backend.session->during_revoke={};
  }
  check(full_in_callback,"in-flight callback receipt also consumes the 64-tuple budget");
  const auto reserves=backend.reserve_calls;bool denied=false;
  try{(void)e.start(local_peer,auth,prior);}catch(...){denied=true;}
  check(denied && backend.reserve_calls==reserves && backend.live.empty(),"64 cleanup receipts deny new work before any mutation or eviction");
  backend.session->expected=nullptr;backend.session->allow_other=true;
  backend.session->during_revoke=[&](const Binding& b){
    auto it=std::find(bindings.begin(),bindings.end(),b);check(it!=bindings.end(),"capacity retry must be an exact original tuple");++retries[static_cast<std::size_t>(it-bindings.begin())];
  };
  backend.session->reject=false;allocations=0;allocation_budget=0;sticky_failure=true;e.retire(local_peer,auth);e.retire(local_peer,auth);
  const auto count=allocations;allocation_budget=-1;sticky_failure=false;
  for(auto n:retries)check(n==1,"every original receipt succeeds exactly once");
  check(count==0 && backend.session->attempts==128 && backend.session->successes==64,"bounded exact receipts retry with no allocations and are consumed on success");
  std::cout<<"PASS capacity=64 exact tuples retained/retried once, zero-allocation retirement\n";
}
static void stop_sweep() {
  long seams;
  {StopBackend backend;Engine e(local_peer,backend,[]{return 100;},stop_space());auto auth=e.authorize(local_peer,"count","{}");auto b=e.start(local_peer,auth);Cursor c{b.sandbox,b.generation};allocations=0;(void)e.stop(local_peer,auth,c);seams=allocations;}
  int pre=0,post=0;
  for(bool ack:{false,true})for(bool sticky:{false,true})for(long seam=0;seam<seams;++seam) {
    LateBackend backend;bool fail=false;
    auto ns=std::make_shared<Namespace>([]{return std::vector<Persisted>{};},[&](const auto& state){if(fail)throw 9;(void)state_json(state);});
    Engine e(local_peer,backend,[]{return 100;},ns);auto auth=e.authorize(local_peer,"sweep","{}");auto response=e.start_response(local_peer,auth);
    const auto binding=reply_binding(response);backend.session->expected=&binding;Cursor c{binding.sandbox,binding.generation};
    bool failed=false;allocation_budget=seam;sticky_failure=sticky;
    try{(void)e.stop(local_peer,auth,c);}catch(const std::bad_alloc&){failed=true;}
    allocation_budget=-1;sticky_failure=false;check(failed,"every counted stop allocation seam must fail");
    if(backend.live.contains(binding.tunnel)) {
      ++pre;check(e.cursor(local_peer,auth,binding.sandbox).generation==binding.generation,"pre-mutation OOM retains exact CAS");
      fail=true;try{(void)e.stop(local_peer,auth,c);}catch(...){}
    }else ++post;
    check(backend.poisoned && backend.live.empty(),"post-close fault poisons without generation resurrection");
    allocations=0;allocation_budget=0;sticky_failure=true;response.finish(ack);e.retire(local_peer,auth);
    const auto count=allocations;allocation_budget=-1;sticky_failure=false;
    backend.session->reject=false;e.retire(local_peer,auth);e.retire(local_peer,auth);
    check(count==0 && backend.session->attempts==3 && backend.session->successes==1,"all stop seams retain same callback/retire receipt through sticky OOM");
  }
  check(pre>0 && post>0,"stop sweep covers both sides of local mutation");
  std::cout<<"PASS late-response stop seams="<<seams<<" ACK both, transient/sticky pre="<<pre<<" post="<<post<<'\n';
}
int main(int argc,char** argv) {
  try {
    const std::string_view mode=argc>1?argv[1]:"poison";
    bool ok=true;
    if(mode=="poison")for(bool ack:{false,true})ok=poisoned(ack)&&ok;
    else if(mode=="oom")for(bool ack:{false,true})for(bool sticky:{false,true})ok=poisoned(ack,true,sticky)&&ok;
    else if(mode=="retirement-oom")retirement_oom();
    else if(mode=="lifecycle")lifecycle();
    else if(mode=="capacity")capacity();
    else if(mode=="stop-sweep")stop_sweep();
    else return 2;
    return ok?0:1;
  }catch(const std::exception& error){std::cerr<<"FAIL: "<<error.what()<<'\n';return 1;}
}
