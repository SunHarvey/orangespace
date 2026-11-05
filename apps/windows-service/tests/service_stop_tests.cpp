// Actual Engine stop fault sweep; backend is a liveness model, NOT native Windows.
#include <cstdlib>
#include <new>
static thread_local long allocation_budget=-1;
static thread_local bool sticky_failure=false;
static thread_local long allocations=0;
void* operator new(std::size_t n) {
  ++allocations;
  if(allocation_budget==0){if(!sticky_failure)allocation_budget=-1;throw std::bad_alloc();}
  if(allocation_budget>0)--allocation_budget;
  if(auto p=std::malloc(n?n:1))return p;
  throw std::bad_alloc();
}
void operator delete(void* p) noexcept {std::free(p);}
void operator delete(void* p,std::size_t) noexcept {std::free(p);}
#define main supplied_policy_main
#include "chain_tests.cpp"
#undef main
#include <set>
struct StopBackend : FakeBackend {
  std::set<std::string,std::less<>> live;
  bool poisoned{};
  int poison_calls{},close_calls{},reserve_calls{};
  void reserve(std::string_view,const Binding&) override {
    ++reserve_calls;check(!poisoned,"poison denies future backend reservation");
  }
  std::function<void(const Binding&)> during_start;
  Proof start(std::string_view,const Binding& b,const LeaseResult&) override {
    check(!poisoned,"poison denies backend start");live.insert(b.tunnel);
    if(during_start)during_start(b);
    return {true,true,true};
  }
  void close(std::string_view,const Binding& b) noexcept override {
    ++close_calls;auto it=live.find(b.tunnel);if(it!=live.end())live.erase(it);
  }
  bool alive(std::string_view,const Binding& b) override {return !poisoned && live.contains(b.tunnel);}
  void fail_closed() noexcept override {++poison_calls;poisoned=true;live.clear();}
};
static std::shared_ptr<Namespace> stop_space() {
  // Exact ledger serialization, injected persistence sink (no disk/ACL claim).
  return std::make_shared<Namespace>([]{return std::vector<Persisted>{};},[](const auto& state){(void)state_json(state);});
}
#ifndef SERVICE_STOP_MAIN
#define SERVICE_STOP_MAIN main
#endif
int SERVICE_STOP_MAIN() {
  orangespace::service::Peer p{"S-1-5-21-100",1,99};
  long seam_count=0;int pre=0,post=0;
  // Discover allocations from the complete real success path, not a guessed cap.
  {StopBackend backend;Engine e(p,backend,[]{return 100;},stop_space());auto a=e.authorize(p,"count","{}");auto b=e.start(p,a);(void)e.start(p,a);Cursor c{b.sandbox,b.generation};
   allocations=0;(void)e.stop(p,a,c);seam_count=allocations;}
  for(bool provisional:{false,true})for(bool sticky:{false,true})for(long seam=0;seam<seam_count;++seam) {
    StopBackend backend;Engine e(p,backend,[]{return 100;},stop_space());auto a=e.authorize(p,"stop","{}");
    auto b=e.start(p,a,{},provisional);auto sibling=e.start(p,a);Cursor c{b.sandbox,b.generation};
    bool failed=false;allocation_budget=seam;sticky_failure=sticky;
    try{(void)e.stop(p,a,c);}catch(const std::bad_alloc&){failed=true;}
    allocation_budget=-1;sticky_failure=false;
    check(failed,"every enumerated allocation seam must actually fail");
    if(backend.live.contains(b.tunnel)) {
      ++pre;check(failed,"live helper only after honest pre-mutation failure");
      auto current=e.cursor(p,a,b.sandbox);
      check(current.generation==c.generation,"OOM must not discard live owner or advance its CAS");
      check((e.status(p,a).find(b.tunnel)!=std::string::npos)==!provisional,"pre-mutation failure retains honest adopted/provisional proof");
      auto next=e.stop(p,a,current);check(next.generation==c.generation+1,"retained exact owner retries");
      check(!backend.live.contains(b.tunnel),"retry closes retained helper");
    } else if(failed) {
      ++post;check(backend.poisoned && backend.poison_calls==1,"fallible persistence after close poisons once");
      bool denied=false;try{(void)e.cursor(p,a,b.sandbox);}catch(...){denied=true;}
      check(denied,"post-close serialization failure latches namespace denial");
      denied=false;try{(void)e.status(p,a);}catch(...){denied=true;}
      check(denied,"post-close poison never reports active proof");
      denied=false;try{(void)e.start(p,a);}catch(...){denied=true;}check(denied,"poison denies new work");
      e.retire(p,a);e.retire(p,a); // cleanup receipt survives durable poison
    }
    if(!backend.poisoned)check(backend.live.contains(sibling.tunnel),"ordinary stop/prevalidation failure isolates sibling");
  }
  int pending_pre=0,pending_post=0;
  for(bool sticky:{false,true})for(long seam=0;seam<seam_count;++seam) {
    StopBackend backend;Engine e(p,backend,[]{return 100;},stop_space());auto a=e.authorize(p,"pending","{}");
    auto sibling=e.start(p,a);bool visited=false,callback_done=false;
    backend.during_start=[&](const Binding& b){
      visited=true;Cursor c{b.sandbox,b.generation};bool failed=false;
      allocation_budget=seam;sticky_failure=sticky;
      try{(void)e.stop(p,a,c);}catch(const std::bad_alloc&){failed=true;}
      allocation_budget=-1;sticky_failure=false;check(failed,"pending allocation seam exercised");
      if(backend.live.contains(b.tunnel)){
        ++pending_pre;auto current=e.cursor(p,a,b.sandbox);
        check(current.generation==c.generation,"pending live owner retains original CAS");
        check(e.status(p,a).find(b.tunnel)==std::string::npos,"pending helper never exposes proof");
        (void)e.stop(p,a,current);
      }else{++pending_post;check(backend.poisoned,"pending post-close fault poisons");}
      check(!backend.live.contains(b.tunnel),"pending stop always closes or retains retryable exact owner");
      if(!backend.poisoned)check(backend.live.contains(sibling.tunnel),"pending stop isolates established sibling");
      callback_done=true;
    };
    bool cancelled=false;try{(void)e.start(p,a);}catch(...){cancelled=true;}
    check(visited && callback_done && cancelled,"late start completion cannot resurrect stopped pending tuple");
    if(backend.poisoned)e.retire(p,a);
  }
  // Rejection before exact authenticated mutation is NOT permission to kill.
  {StopBackend backend;Engine e(p,backend,[]{return 100;});auto a=e.authorize(p,"authority","{}");auto b=e.start(p,a);
   for(int dimension=0;dimension<6;++dimension){auto foreign=p;auto id=a;Cursor c{b.sandbox,b.generation};
     if(dimension==0)foreign.sid+="0";
     if(dimension==1)++foreign.session;
     if(dimension==2)++foreign.logon;
     if(dimension==3)id="99999999-9999-4999-8999-999999999999";
     if(dimension==4)++c.generation;
     if(dimension==5)c.sandbox="99999999-9999-4999-8999-999999999999";
     bool denied=false;try{(void)e.stop(foreign,id,c);}catch(...){denied=true;}
     check(denied && backend.live.contains(b.tunnel) && backend.close_calls==0,"unauthenticated/stale stop cannot terminate live work");
   }
  }
  check(pre>0 && post>0 && pending_pre>0 && pending_post>0,"sweep covers pre-mutation and post-local-close allocations");
  std::cout<<"PASS actual stop allocation seams="<<seam_count<<" transient+persistent adopted/provisional pre="<<pre<<" post="<<post<<" pending_pre="<<pending_pre<<" pending_post="<<pending_post<<" (modeled liveness, not native)\n";
  return 0;
}
