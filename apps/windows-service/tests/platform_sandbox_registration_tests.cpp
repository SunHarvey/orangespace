#include "orangespace/service_chain.hpp"
#include <iostream>
#include <stdexcept>
using namespace orangespace::service;
using namespace orangespace::service::chain;
namespace {
void check(bool ok,const char* why){if(!ok)throw std::runtime_error(why);}
template<class F> void denied(F f,const char* why){bool rejected=false;try{f();}catch(const std::exception&){rejected=true;}check(rejected,why);}
constexpr auto sandbox_a="44444444-4444-4444-8444-444444444444";
constexpr auto sandbox_b="55555555-5555-4555-8555-555555555555";
const Peer peer{"S-1-5-21-100",1,99};
template<class I> void central(I& i,std::string value){if constexpr(requires{ i.central_user; })i.central_user=std::move(value);}
struct TestSession final:Session {
  Identity value{"11111111-1111-4111-8111-111111111111","22222222-2222-4222-8222-222222222222",1000};
  Identity identity()const override{return value;}
  void refresh()override{}
  LeaseResult create(const Binding&)override{return LeaseResult("{}",{std::string(nd::lease_clock),100000,30000,130000},130);}
  RenewResult renew(const Binding&)override{return {130,{std::string(nd::lease_clock),100000,30000,130000}};}
  void revoke(const Binding&)override{}
  void logout()override{}
};
struct TestBackend final:Backend {
  std::string owner="central-A";
  std::shared_ptr<TestSession> last;
  int next{},starts{},poisons{};
  void release(std::string_view)noexcept override{}
  void fail_closed()noexcept override{++poisons;}
  std::shared_ptr<Session> restore(std::string_view,std::string_view)override{last=std::make_shared<TestSession>();central(last->value,owner);return last;}
  std::string id()override{auto s=std::string("33333333-3333-4333-8333-333333330000");int n=++next;for(int i=35;i>=32;--i){s[i]="0123456789abcdef"[n&15];n>>=4;}return s;}
  void reserve(std::string_view,const Binding&)override{}
  Proof start(std::string_view,const Binding&,const LeaseResult&)override{++starts;return {true,true,true};}
  void close(std::string_view,const Binding&)noexcept override{}
  bool alive(std::string_view,const Binding&)override{return true;}
  void renew(std::string_view,const Binding&,const RenewResult&)override{}
};
template<class E> Cursor registration(E& e,const Peer& p,std::string_view auth,std::string_view sandbox){
  if constexpr(requires{e.register_sandbox(p,auth,sandbox);})return e.register_sandbox(p,auth,sandbox);
  else throw std::runtime_error("MISSING Engine.register_sandbox");
}
void persistent_registration(){
  std::string ledger="{\"schema\":1,\"sandboxes\":[]}";
  TestBackend backend;
  {
    auto ns=std::make_shared<Namespace>([&]{return parse_state(ledger);},[&](const auto& entries){ledger=state_json(entries);});
    Engine e(peer,backend,[]{return 100;},ns,[]{return 100000;});
    auto auth=e.authorize(peer,"node-a","{}");
    auto c=registration(e,peer,auth,sandbox_a);
    check(c.sandbox==sandbox_a && c.generation==0,"registration preserves local UUID with service generation zero");
    check(ledger.find("\"schema\":2")!=std::string::npos && ledger.find("\"central_user\":\"central-A\"")!=std::string::npos,"central owner persisted as explicit schema2");
    auto live=e.start(peer,auth,c);
    check(live.sandbox==sandbox_a && live.generation==1,"registered cursor starts exact sandbox");
  }
  {
    auto ns=std::make_shared<Namespace>([&]{return parse_state(ledger);},[&](const auto& entries){ledger=state_json(entries);});
    Engine e(peer,backend,[]{return 100;},ns,[]{return 100000;});
    auto auth=e.authorize(peer,"node-a","{}");
    auto c=registration(e,peer,auth,sandbox_a);
    check(c.generation==1,"reload ledger restores registration and generation");
    auto live=e.start(peer,auth,c);check(live.generation==2,"reload continues durable generation");
  }
}
void central_start_isolation(){
  TestBackend backend;auto ns=std::make_shared<Namespace>();
  Engine e(peer,backend,[]{return 100;},ns,[]{return 100000;});
  auto a=e.authorize(peer,"a","{}");auto c=registration(e,peer,a,sandbox_a);
  backend.owner="central-B";auto b=e.authorize(peer,"b","{}");
  denied([&]{(void)registration(e,peer,b,sandbox_a);},"different central identity cannot re-register");
  denied([&]{(void)e.start(peer,b,c);},"wrong central identity must not start another owner's cursor");
  denied([&]{(void)e.cursor(peer,b,sandbox_a);},"wrong central identity cannot retrieve cursor");
  backend.owner.clear();auto old=e.authorize(peer,"legacy","{}");
  denied([&]{(void)e.start(peer,old,c);},"legacy OSP2 identity cannot claim central cursor");
  denied([&]{(void)e.cursor(peer,old,sandbox_a);},"legacy identity cannot retrieve central cursor");
  denied([&]{(void)registration(e,peer,old,sandbox_b);},"legacy identity cannot register central workspace");
  auto other=peer;other.sid="S-1-5-21-200";
  backend.owner="central-A";Engine other_engine(other,backend,[]{return 100;},ns,[]{return 100000;});
  auto other_auth=other_engine.authorize(other,"a","{}");
  denied([&]{(void)registration(other_engine,other,other_auth,sandbox_a);},"same central identity wrong SID cannot register");
  denied([&]{(void)other_engine.start(other,other_auth,c);},"same central identity wrong SID cannot start");
  auto forged=peer;++forged.logon;
  denied([&]{(void)registration(e,forged,a,sandbox_b);},"wrong OS logon rejected");
  auto forged_generation=c;++forged_generation.generation;
  denied([&]{(void)e.start(peer,a,forged_generation);},"client cannot inject generation");
  auto live=e.start(peer,a,c);check(live.generation==1,"denied claims leave generation untouched");
}
void no_implicit_migration(){
  const std::string legacy="{\"schema\":1,\"sandboxes\":[{\"sandbox_id\":\"44444444-4444-4444-8444-444444444444\",\"sid\":\"S-1-5-21-100\",\"generation\":77}]}";
  auto old=parse_state(legacy);check(state_json(old)==legacy,"schema1 output remains byte compatible");
  std::string ledger=legacy;
  TestBackend backend;
  auto ns=std::make_shared<Namespace>([&]{return parse_state(ledger);},[&](const auto& entries){ledger=state_json(entries);});
  Engine e(peer,backend,[]{return 100;},ns,[]{return 100000;});
  auto a=e.authorize(peer,"central","{}");
  denied([&]{(void)e.start(peer,a);},"central workspace must use explicit registration, not random legacy UUID");
  denied([&]{(void)registration(e,peer,a,sandbox_a);},"legacy workspace cannot be silently claimed");
  denied([&]{(void)e.start(peer,a,Cursor{sandbox_a,77});},"central identity cannot silently migrate legacy cursor");
  check(ledger==legacy,"denied migration does not mutate ledger");
  auto b=registration(e,peer,a,sandbox_b);check(b.generation==0,"new workspace can coexist with legacy");
  auto mixed=parse_state(ledger);check(mixed.size()==2 && mixed[0].central_user.empty() && mixed[0].generation==77,"schema2 retains legacy owner and generation");
  backend.owner.clear();auto legacy_auth=e.authorize(peer,"legacy","{}");
  auto live=e.start(peer,legacy_auth,Cursor{sandbox_a,77});check(live.generation==78,"legacy auth continues legacy workspace");
  auto new_legacy=e.start(peer,legacy_auth);check(new_legacy.sandbox!=sandbox_a && new_legacy.sandbox!=sandbox_b,"legacy no-prior behavior retained");
}
void refreshed_identity_fence(){
  for(bool maintenance:{false,true}){
    TestBackend backend;Engine e(peer,backend,[]{return 100;},std::make_shared<Namespace>(),[]{return 100000;});
    auto a=e.authorize(peer,"a","{}");auto c=registration(e,peer,a,sandbox_a);
    if(maintenance){(void)e.start(peer,a,c);central(backend.last->value,"central-B");e.tick();denied([&]{(void)e.status(peer,a);},"maintenance must retire changed central identity");}
    else{central(backend.last->value,"central-B");denied([&]{(void)e.start(peer,a,c);},"refresh cannot replace central identity");check(backend.starts==0,"changed identity never reaches helper");}
  }
}
void independent_sandboxes(){
  TestBackend backend;std::string ledger="{\"schema\":1,\"sandboxes\":[]}";int saves=0;
  auto ns=std::make_shared<Namespace>([&]{return parse_state(ledger);},[&](const auto& state){ledger=state_json(state);++saves;});
  Engine e(peer,backend,[]{return 100;},ns,[]{return 100000;});
  auto a=e.authorize(peer,"node-a","{}");auto ca=registration(e,peer,a,sandbox_a),cb=registration(e,peer,a,sandbox_b);
  const auto before=saves;auto again=registration(e,peer,a,sandbox_a);
  check(again.generation==0 && saves==before,"lost registration reply retries without generation advance or rewrite");
  auto live_a=e.start(peer,a,ca),live_b=e.start(peer,a,cb);
  auto next_a=e.stop(peer,a,Cursor{live_a.sandbox,live_a.generation});
  check(next_a.generation==2 && e.status(peer,a).find(live_b.tunnel)!=std::string::npos,"stop A preserves live B");
  check(registration(e,peer,a,sandbox_b).generation==1,"A stop does not advance B generation");
  auto switched=e.authorize(peer,"other-node","{}");
  auto c=registration(e,peer,switched,sandbox_a);check(c.generation==2,"same central owner can reacquire across auths");
  auto response=e.start_response(peer,switched,c);response.finish(false);
  check(registration(e,peer,switched,sandbox_a).generation==3,"failed start ACK retains durable owner and spent generation");
  check(e.status(peer,a).find(live_b.tunnel)!=std::string::npos,"A failed ACK keeps independent B");
  auto restored=e.start(peer,switched,registration(e,peer,switched,sandbox_a));check(restored.generation==4,"retry uses service cursor after failed ACK");
}
void admission_and_poison(){
  {
    TestBackend backend;std::int64_t now=100;int saves=0;
    auto ns=std::make_shared<Namespace>([]{return std::vector<Persisted>{};},[&](const auto&){++saves;});
    Engine e(peer,backend,[&]{return now;},ns,[]{return 100000;});
    auto a=e.authorize(peer,"a","{}");
    denied([&]{(void)registration(e,peer,a,"bad-uuid");},"malformed local UUID rejected");
    auto response=e.authorize_response(peer,"pending","{}");
    const auto body=orangespace::json::parse(response.body);const auto provisional=nd::text(nd::field(body,"auth_id"));
    denied([&]{(void)registration(e,peer,provisional,sandbox_b);},"unacknowledged auth cannot register");response.finish(false);
    now=1000;denied([&]{(void)registration(e,peer,a,sandbox_a);},"expired auth cannot register");
    now=100;e.retire(peer,a);denied([&]{(void)registration(e,peer,a,sandbox_a);},"retired auth cannot register");
    check(saves==0,"invalid admissions do not write ledger");
  }
  {
    TestBackend backend;auto ns=std::make_shared<Namespace>([]{return std::vector<Persisted>{};},[](const auto&){throw std::runtime_error("durable write failed");});
    Engine e(peer,backend,[]{return 100;},ns,[]{return 100000;});auto a=e.authorize(peer,"a","{}");
    denied([&]{(void)registration(e,peer,a,sandbox_a);},"failed registration persistence returns no cursor");
    check(backend.poisons==1 && backend.starts==0,"write failure invokes existing fail-closed latch");
    denied([&]{(void)registration(e,peer,a,sandbox_a);},"poisoned registration cannot recover in memory");
    denied([&]{(void)e.start(peer,a,Cursor{sandbox_a,0});},"poisoned registration denies starts");
    e.retire(peer,a);e.logout(peer,a);
  }
}
void strict_ledger(){
  const std::string prefix="{\"schema\":2,\"sandboxes\":[{\"sandbox_id\":\"44444444-4444-4444-8444-444444444444\",\"sid\":\"S-1-5-21-100\",\"generation\":0";
  for(const auto& suffix:{"}]}",",\"central_user\":1}]}",",\"central_user\":\"central-A\",\"extra\":0}]}",",\"owner\":\"central-A\"}]}"})
    denied([&]{(void)parse_state(prefix+suffix);},"schema2 requires exactly typed central_user field");
  denied([&]{(void)parse_state("{\"schema\":1,\"sandboxes\":[{\"sandbox_id\":\"44444444-4444-4444-8444-444444444444\",\"sid\":\"S-1-5-21-100\",\"generation\":0,\"central_user\":\"central-A\"}]}");},"schema1 cannot hide central ownership");
  auto data=parse_state(prefix+",\"central_user\":\"central-A\"}]}");check(data.size()==1,"strict schema2 positive control");
  data.push_back(data.front());denied([&]{(void)parse_state(state_json(data));},"duplicate UUID ownership rejected");
}
}
int main(){try{persistent_registration();central_start_isolation();no_implicit_migration();refreshed_identity_fence();independent_sandboxes();admission_and_poison();strict_ledger();std::cout<<"platform sandbox registration tests passed (7 groups; portable policy, not native Windows)\n";}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
