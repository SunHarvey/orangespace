// Actual Engine start cleanup with sticky allocation faults; injected Session/backend.
#define SERVICE_STOP_MAIN supplied_stop_main
#include "service_stop_tests.cpp"
#include <array>
struct ReceiptSession : FakeSession {
  bool fail_revoke=true, fail_create=false;
  int attempts{}, creates{};
  std::array<Binding,64> exact{};
  std::function<void()> on_revoke;
  LeaseResult create(const Binding& b) override {
    exact.at(creates++)=b;
    auto budget=timing();
    if(on_create)on_create();
    if(fail_create)throw std::bad_alloc();
    return LeaseResult("{}",budget,expiry);
  }
  void revoke(const Binding& b) override {
    bool found=false;for(int i=0;i<creates;++i)if(exact[i]==b)found=true;
    check(found,"cleanup must retry exact created tuple");++attempts;
    if(on_revoke)on_revoke();
    if(fail_revoke)throw std::bad_alloc();
  }
};
struct ReceiptBackend : FakeBackend {
  std::shared_ptr<ReceiptSession> session=std::make_shared<ReceiptSession>();
  std::shared_ptr<Session> restore(std::string_view,std::string_view) override{return session;}
};
int main(){
  orangespace::service::Peer p{"S-1-5-21-100",1,99};
  for(bool typed_failure:{false,true}) {
    std::int64_t mono=100000;ReceiptBackend b;
    Engine e(p,b,[]{return 100;},std::make_shared<Namespace>(),[&]{return mono;});
    auto id=e.authorize(p,"receipt","{}");b.session->clock=[&]{return mono;};
    b.session->fail_create=typed_failure;
    b.session->on_create=[&]{mono+=30000;if(typed_failure){sticky_failure=true;allocation_budget=0;}};
    bool denied=false;try{(void)e.start(p,id);}catch(...){denied=true;}
    allocation_budget=-1;sticky_failure=false;
    check(denied && b.started==0 && b.session->attempts==1,"prebackend rollback initial revoke attempted");
    e.retire(p,id);check(b.session->attempts==2,"first retire retries retained exact start receipt");
    b.session->fail_revoke=false;e.retire(p,id);check(b.session->attempts==3,"second retire retries exact receipt");
    e.retire(p,id);check(b.session->attempts==3,"successful revoke consumes receipt");
  }
  {
    std::int64_t mono=100000;ReceiptBackend b;Engine e(p,b,[]{return 100;},std::make_shared<Namespace>(),[&]{return mono;});
    auto id=e.authorize(p,"capacity","{}");b.session->clock=[&]{return mono;};b.session->on_create=[&]{mono+=30000;};
    bool inflight_denied=false;
    b.session->on_revoke=[&]{if(b.session->attempts==64){try{(void)e.start(p,id);}catch(...){inflight_denied=true;}}};
    for(int i=0;i<65;++i){try{(void)e.start(p,id);}catch(...){}}
    b.session->on_revoke={};
    check(inflight_denied,"in-flight revoke still counts toward the 64 tuple cap");
    check(b.session->creates==64 && b.session->attempts==64,"cleanup receipts count against 64 tuple capacity before remote create");
    auto foreign=p;foreign.logon++;
    bool denied=false;try{e.retire(foreign,id);}catch(...){denied=true;}
    check(denied && b.session->attempts==64,"lost-auth receipt remains exact OS-peer bound");
    e.retire(p,id);check(b.session->attempts==128,"retire retries all bounded receipts");
    b.session->fail_revoke=false;e.logout(p,id);check(b.session->attempts==192,"logout consumes successful exact receipts");
    e.retire(p,id);check(b.session->attempts==192,"no successful receipt retry");
  }
  {
    std::int64_t mono=100000;ReceiptBackend b;Engine e(p,b,[]{return 100;},std::make_shared<Namespace>(),[&]{return mono;});
    auto id=e.authorize(p,"late-logout","{}");b.session->clock=[&]{return mono;};b.session->on_create=[&]{mono+=30000;};
    bool fired=false;b.session->on_revoke=[&]{if(!fired){fired=true;e.logout(p,id);}};
    try{(void)e.start(p,id);}catch(...){}
    check(fired && b.session->attempts==1,"logout completes while start rollback revoke is in flight");
    b.session->fail_revoke=false;e.logout(p,id);
    check(b.session->attempts==2,"already-logged-out auth still retries late exact cleanup receipt");
    e.logout(p,id);check(b.session->attempts==2,"late receipt consumed on successful retry");
  }
  // Fault every post-create allocation boundary in actual Engine publication.
  // Each failed sticky allocation must keep one exact receipt for retirement.
  for(long seam=0;seam<32;++seam) {
    std::int64_t mono=100000;ReceiptBackend b;
    Engine e(p,b,[]{return 100;},std::make_shared<Namespace>(),[&]{return mono;});
    auto id=e.authorize(p,"sweep","{}");b.session->clock=[&]{return mono;};
    b.session->on_create=[&]{sticky_failure=true;allocation_budget=seam;};
    bool denied=false;try{(void)e.start(p,id);}catch(...){denied=true;}
    allocation_budget=-1;sticky_failure=false;
    const auto attempts=b.session->attempts;
    b.session->fail_revoke=false;e.retire(p,id);
    check(b.session->attempts==attempts+1,"post-create sticky allocation keeps exact cleanup ownership");
    if(denied){e.retire(p,id);check(b.session->attempts==attempts+1,"swept receipt consumed on success");}
  }
  std::cout<<"PASS start-budget/typed-constructor receipts: sticky OOM, repeated retire/logout, exact peer and 64-cap (injected policy only)\n";
}
