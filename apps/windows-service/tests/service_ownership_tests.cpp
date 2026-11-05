// Standalone fault tests: compile with -fno-elide-constructors.
#include <cstdlib>
#include <new>
#include <cstring>
static thread_local long allocation_budget=-1;
static thread_local bool sticky_failure=false;
void* operator new(std::size_t n) {
  if(allocation_budget==0) {if(!sticky_failure)allocation_budget=-1;throw std::bad_alloc();}
  if(allocation_budget>0)--allocation_budget;
  if(auto p=std::malloc(n?n:1))return p;
  throw std::bad_alloc();
}
void operator delete(void* p) noexcept {std::free(p);}
void operator delete(void* p,std::size_t) noexcept {std::free(p);}
#define main supplied_policy_main
#include "chain_tests.cpp"
#undef main
#include "orangespace/service_client.hpp"
#include <set>
struct OwnershipBackend : FakeBackend {
  std::set<std::string,std::less<>> live;
  int releases{};
  Proof start(std::string_view,const Binding& b,const LeaseResult&) override {live.insert(b.tunnel);return {true,true,true};}
  void close(std::string_view,const Binding& b) noexcept override {auto it=live.find(b.tunnel);if(it!=live.end())live.erase(it);}
  void release(std::string_view) noexcept override {++releases;}
};
int main(int argc,char** argv) {
  const std::string_view mode=argc>1?argv[1]:"preowner";
  orangespace::service::Peer p{"S-1-5-21-100",1,99};
  if(mode=="preowner") {
    int failures=0;
    for(bool sticky:{false,true})for(long n=0;n<130;++n) {
      OwnershipBackend b;Engine e(p,b,[]{return 100;});bool failed=false;
      sticky_failure=sticky;allocation_budget=n;
      try {auto response=e.authorize_response(p,"alloc","{}");}catch(...){failed=true;}
      allocation_budget=-1;sticky_failure=false;
      if(failed){++failures;check(!b.last || b.last.use_count()==1,"PREOWNER: failed undisclosed auth retains Session without response owner");}
    }
    check(failures>0,"fault sweep exercised allocation failures");
    std::cout<<"PASS preowner transient + persistent allocation sweep\n";
  } else if(mode=="receipts") {
    OwnershipBackend b;Engine e(p,b,[]{return 100;});
    auto first=e.authorize(p,"same","{}");auto original=b.last;
    auto binding=e.start(p,first);e.retire(p,first);
    bool retry=true;try{e.retire(p,first);}catch(...){retry=false;}
    check(retry && b.live.empty() && original->logouts==0,"RECEIPT: exact peer can retry lost op6 reply without API logout");
    auto second=e.authorize(p,"same","{}");
    auto third=e.authorize(p,"same","{}");
    e.retire(p,second);check(!e.status(p,third).empty(),"superseded retry preserves newer authorization");
    original->fail_logout=true;bool failed=false;
    try{e.logout(p,first);}catch(...){failed=true;}
    original->fail_logout=false;e.logout(p,first);e.logout(p,first);
    check(failed && original->logouts==2,"op4 failure retries original remote Session and success is idempotent");
    for(int dimension=0;dimension<3;++dimension){auto foreign=p;if(dimension==0)foreign.sid+="0";if(dimension==1)++foreign.session;if(dimension==2)++foreign.logon;
      bool denied=false;try{e.retire(foreign,first);}catch(...){denied=true;}check(denied,"receipt bound to original SID/session/logon");}
    bool unknown=false;try{e.retire(p,"99999999-9999-4999-8999-999999999999");}catch(...){unknown=true;}check(unknown,"unknown receipt rejected");
    for(int operation=0;operation<3;++operation) {
      bool denied=false;try{if(operation==0)(void)e.start(p,first);else if(operation==1)(void)e.status(p,first);else(void)e.cursor(p,first,binding.sandbox);}catch(...){denied=true;}
      check(denied,"retirement receipt grants no start/status/cursor authority");
    }
    int refreshes=0;original->on_refresh=[&]{++refreshes;};e.tick();
    check(refreshes==0,"retirement receipt cannot refresh or renew work");
    // Retry of an old receipt must not cancel a newer in-flight alias restore.
    b.on_restore=[&]{e.retire(p,first);};auto fourth=e.authorize(p,"same","{}");b.on_restore={};
    check(!e.status(p,fourth).empty(),"old receipt does not advance newer alias ticket");
    auto latest=fourth;for(int i=4;i<64;++i)latest=e.authorize(p,"same","{}");
    bool full=false;try{(void)e.authorize(p,"same","{}");}catch(...){full=true;}
    check(full && !e.status(p,latest).empty(),"bounded receipts reject new authorization before superseding current grant");
    e.retire(p,first);check(original->logouts==2,"capacity never evicts original receipt");
    std::cout<<"PASS peer-bound cleanup-only receipts, op4 retry, lifetime cap 64\n";
  } else if(mode=="cleanup-oom") {
    OwnershipBackend b;Engine e(p,b,[]{return 100;});auto grant=e.authorize(p,"oom-retire","{}");auto session=b.last;
    auto binding=e.start(p,grant);bool completed=true;
    allocation_budget=0;sticky_failure=true;
    try{e.retire(p,grant);e.retire(p,grant);}catch(...){completed=false;}
    allocation_budget=-1;sticky_failure=false;
    check(completed && b.live.empty() && session->logouts==0,"exact authenticated local retirement needs no allocations and preserves API token");
    std::cout<<"PASS local retirement + exact retry under persistent allocation failure\n";
  } else if(mode=="start-rollback") {
    int failures=0;
    for(bool sticky:{false,true})for(long n=0;n<200;++n) {
      OwnershipBackend b;Engine e(p,b,[]{return 100;});auto grant=e.authorize(p,"start-alloc","{}");bool failed=false;
      sticky_failure=sticky;allocation_budget=n;
      try{auto response=e.start_response(p,grant);}catch(...){failed=true;}
      allocation_budget=-1;sticky_failure=false;
      if(failed)++failures;
      check(b.live.empty(),"failed/undelivered start response retains no helper under allocation failure");
    }
    check(failures>0,"start allocation faults exercised");
    std::cout<<"PASS start response transient + persistent allocation rollback sweep\n";
  } else return 2;
}
