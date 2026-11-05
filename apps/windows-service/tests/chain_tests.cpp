// Preload dependencies so the Windows-style min macro tests this header,
// not unrelated standard-library declarations.
#include "orangespace/service_policy.hpp"
#include "orangespace/chain_response.hpp"
#include "orangespace/node_session.hpp"
#include <algorithm>
#include <memory>
#include <mutex>
#include <map>
#include <functional>
#include <atomic>
#include <type_traits>
#ifdef min
#undef min
#endif
#define min(a, b) (((a) < (b)) ? (a) : (b))
#include "orangespace/service_chain.hpp"
#undef min
#include "orangespace/platform_protocol.hpp"
#include <iostream>
#include <stdexcept>
#include <future>
#include <thread>
using namespace orangespace::service::chain;
void check(bool b, const char* s) { if (!b) throw std::runtime_error(s); }
struct FakeSession : Session {
  Identity identity() const override { return {"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", 1000}; }
  std::function<void()> on_create;
  bool fail_logout{}, fail_revoke{};
  int revokes{}, logouts{};
  std::function<void()> on_refresh;
  void refresh() override {if(on_refresh)on_refresh();}
  std::function<std::int64_t()> clock=nd::monotonic_ms;
  std::int64_t ttl=30000, expiry=130;
  LeaseBudget timing() const {const auto start=clock();return {std::string(nd::lease_clock),start,ttl,start+ttl};}
  LeaseResult create(const Binding&) override { const auto budget=timing(); if(on_create) on_create(); return LeaseResult("{}",budget,expiry); }
  std::function<void()> on_renew;
  RenewResult renew(const Binding&) override {const auto budget=timing();auto callback=on_renew;if(callback)callback();return {expiry,budget};}
  void revoke(const Binding&) override { ++revokes;if(fail_revoke)throw std::runtime_error("revoke unavailable"); }
  void logout() override { ++logouts; if(fail_logout) throw std::runtime_error("network failed"); }
};
struct FakeBackend : Backend {
  void release(std::string_view) noexcept override {}
  void fail_closed() noexcept override {}
  int next{}, started{}, closed{}, renewed{};
  bool living=true;
  Proof proof{true,true,true};
  std::shared_ptr<FakeSession> last;
  std::function<void()> on_restore;
  std::shared_ptr<Session> restore(std::string_view, std::string_view) override {
    auto callback=on_restore; if(callback) callback();
    last=std::make_shared<FakeSession>(); return last;
  }
  std::string id() override {
    auto s=std::string("33333333-3333-4333-8333-333333330000"); auto n=++next;
    for(int i=35;i>=32;--i) {s[i]="0123456789abcdef"[n&15];n>>=4;}
    return s;
  }
  std::function<void()> on_start;
  std::function<void()> on_reserve;
  void reserve(std::string_view,const Binding&) override {if(on_reserve)on_reserve();}
  Proof start(std::string_view,const Binding&, const LeaseResult&) override { ++started; if(on_start)on_start();return proof; }
  void close(std::string_view,const Binding&) noexcept override { ++closed; }
  std::function<bool(const Binding&)> on_alive;
  bool alive(std::string_view,const Binding& b) override { return on_alive ? on_alive(b) : living; }
  void renew(std::string_view,const Binding&,const RenewResult& renewal) override {check(renewal.expires_at>0,"server expiry passed to runtime");++renewed;}
};
void lease_v2_engine_tests() {
  orangespace::service::Peer p{"S-1-5-21-100",1,99};
  for (bool after_proof : {false,true}) {
    std::int64_t mono=100000;
    FakeBackend b; Engine e(p,b,[]{return 100;},std::make_shared<Namespace>(),[&]{return mono;});
    auto a=e.authorize(p,"budget","{}");b.last->clock=[&]{return mono;};b.last->ttl=10;
    if(after_proof)b.on_start=[&]{mono=100010;};else b.last->on_create=[&]{mono=100010;};
    bool denied=false;try{(void)e.start(p,a);}catch(...){denied=true;}
    check(denied && b.started==(after_proof?1:0) && b.last->revokes==1,"original budget expires in HTTP/queue/proof; no re-anchor");
  }
  for(bool switching:{false,true}) {
    std::int64_t mono=100000;
    FakeBackend b;Engine e(p,b,[]{return 100;},std::make_shared<Namespace>(),[&]{return mono;});
    auto a=e.authorize(p,"late-renew","{}");b.last->clock=[&]{return mono;};
    auto session=b.last;auto live=e.start(p,a),sibling=e.start(p,a);
    session->on_renew=[&]{
      session->on_renew={};
      if(switching)(void)e.start(p,a,Cursor{live.sandbox,live.generation});
      else (void)e.stop(p,a,Cursor{live.sandbox,live.generation});
    };
    e.tick();
    check(e.status(p,a).find(sibling.tunnel)!=std::string::npos,"late renewal of closed/switched A must preserve sibling B");
  }
  {
    std::int64_t mono=100000;
    FakeBackend b;Engine e(p,b,[]{return 100;},std::make_shared<Namespace>(),[&]{return mono;});
    auto a=e.authorize(p,"late-ack","{}");b.last->clock=[&]{return mono;};b.last->ttl=10;
    auto response=e.start_response(p,a);mono+=10;response.finish(true);
    check(b.closed==1 && e.status(p,a).find("forwarding_verified")==std::string::npos,"late ACK never adopts expired proof");
  }
  for (int scenario=0;scenario<4;++scenario) {
    std::int64_t mono=100000;
    FakeBackend b; Engine e(p,b,[]{return 100;},std::make_shared<Namespace>(),[&]{return mono;});
    auto a=e.authorize(p,"renew-budget","{}");b.last->clock=[&]{return mono;};b.last->expiry=131;
    auto live=e.start(p,a); // 31 wall seconds is not an upper-bound failure.
    mono+=1000;
    if(scenario==0)b.last->expiry=130; // regression
    if(scenario==1)b.last->on_renew=[&]{mono=130000;}; // old expiry reached during HTTP
    if(scenario==2)b.last->ttl=1,b.last->on_renew=[&]{++mono;}; // new budget exhaustion
    if(scenario==3) { // equal expiry cannot extend original deadline
      e.tick();check(b.renewed==1,"equal expiry accepted without extending lifetime");
      mono=130000;bool denied=false;try{(void)e.status(p,a);}catch(...){denied=true;}
      check(denied,"equal-expiry renewal must retain original deadline");continue;
    }
    e.tick();check(b.renewed==0 && b.closed>0,"renewal expiry regression/old/new exhaustion rejected before backend");
  }
}
void sibling_failure_tests() {
  orangespace::service::Peer p{"S-1-5-21-100",1,99};
  for(bool renewal_failure:{false,true}) {
    std::int64_t mono=100000;
    FakeBackend b;Engine e(p,b,[]{return 100;},std::make_shared<Namespace>(),[&]{return mono;});
    auto auth=e.authorize(p,"isolated","{}");auto session=b.last;session->clock=[&]{return mono;};
    const auto a=e.start(p,auth), sibling=e.start(p,auth);
    if(renewal_failure)session->on_renew=[&]{session->on_renew={};throw std::runtime_error("A renew failed");};
    else b.on_alive=[&](const Binding& binding){return binding!=a;};
    std::string reply;
    try {if(renewal_failure)e.tick();else reply=e.status(p,auth);}catch(...){}
    if(renewal_failure)session->on_renew={};
    try{reply=e.status(p,auth);}catch(...){}
    check(reply.find(sibling.tunnel)!=std::string::npos && reply.find(a.tunnel)==std::string::npos,
      "same-node failed A must preserve healthy B and authorization");
    check(b.closed==1 && session->logouts==0,"only failed binding closes; shared login survives");
    if(!renewal_failure)check(session->revokes==0,"local status never waits for HTTPS revoke");
    if(!renewal_failure)session->fail_revoke=true;
    e.tick();check(session->revokes==1,"tick drains exact failed-binding cleanup receipt");
    if(!renewal_failure) {
      session->fail_revoke=false;e.tick();
      check(session->revokes==2 && e.status(p,auth).find(sibling.tunnel)!=std::string::npos,
        "uncertain revoke receipt survives retry without touching healthy sibling");
    }
    auto replacement=e.start(p,auth,Cursor{a.sandbox,a.generation});
    check(replacement.generation>a.generation,"failed binding cursor permits fresh fenced generation");
    session->on_refresh=[]{throw std::runtime_error("shared authority failed");};e.tick();
    bool denied=false;try{(void)e.status(p,auth);}catch(...){denied=true;}
    check(denied,"shared refresh failure still retires whole authorization");
  }
}
void diagnostic_tests() {
  orangespace::service::Peer p{"S-1-5-21-100",1,99};
  struct ProbeBackend : FakeBackend {
    int probes{}; std::function<void()> during; bool fresh=true;
    bool diagnose(std::string_view,const Binding&,const LeaseBudget& budget) override {
      ++probes;check(budget.remaining_ttl_ms<=5000,"diagnostic budget capped");
      if(during)during();
      return fresh;
    }
  };
  for(int scenario=0;scenario<7;++scenario) {
    std::int64_t mono=100000;ProbeBackend b;
    Engine e(p,b,[]{return 100;},std::make_shared<Namespace>(),[&]{return mono;});
    auto auth=e.authorize(p,"diagnostic","{}");b.last->clock=[&]{return mono;};
    auto a=e.start(p,auth), sibling=e.start(p,auth);const int before=b.closed;
    auto wrong=p;++wrong.logon;bool denied=false;
    try{(void)e.diagnose(wrong,auth,a);}catch(...){denied=true;}
    auto tuple=a;tuple.tunnel=sibling.tunnel;bool tuple_denied=false;
    try{(void)e.diagnose(p,auth,tuple);}catch(...){tuple_denied=true;}
    check(denied&&tuple_denied&&b.probes==0,"wrong OS peer/full tuple denied before backend");
    if(scenario==1)b.fresh=false;
    if(scenario==2)b.during=[&]{mono+=5000;};
    if(scenario==3)b.during=[&]{(void)e.start(p,auth,Cursor{a.sandbox,a.generation});};
    if(scenario==4)b.during=[&]{b.last->expiry=140;e.tick();};
    if(scenario==5)b.during=[] {throw std::runtime_error("secret must not escape");};
    if(scenario==6)mono=a.deadline_ms;
    std::string reply;try{reply=e.diagnose(p,auth,a);}catch(...){check(scenario==6,"only expired preflight rejects");}
    if(scenario!=6) {
      check(reply.find("\"fresh_proof\":true")!=std::string::npos ? scenario==0 : scenario!=0,"fresh positive requires current authority and budget");
      check(reply.find("\"browser_allowed\":false")!=std::string::npos&&reply.find("secret")==std::string::npos&&reply.find("ready")==std::string::npos,"nonsecret diagnostic never readiness");
      check(b.closed==before+(scenario==3?1:0),"diagnostic failure never closes sibling or renewed authority");
    } else check(b.probes==0,"expired authority denied before runtime");
  }
}
void diagnostic_protocol_tests() {
  const std::string id="11111111-1111-4111-8111-111111111111";
  Binding b{id,id,id,id,1};
  const auto body="{\"auth_id\":"+quote(id)+",\"binding\":"+binding_json(b)+"}";
  check(static_cast<int>(parse_request(request_frame(static_cast<Op>(8),body)).op)==8,"op8 full binding accepted");
  namespace pp=orangespace::service::platform;
  check(pp::parse_request(pp::request_frame(8,body)).op==8,"OSP3 op8 full binding accepted");
  for(const auto& bad:{body.substr(0,body.size()-1)+",\"url\":\"https://invalid\"}",
      "{\"auth_id\":"+quote(id)+",\"binding\":{}}"}) {
    bool denied=false;try{(void)parse_request(request_frame(static_cast<Op>(8),bad));}catch(...){denied=true;}
    check(denied,"op8 unknown/incomplete fields denied");
    denied=false;try{(void)pp::parse_request(pp::request_frame(8,bad));}catch(...){denied=true;}
    check(denied,"OSP3 op8 unknown/incomplete fields denied");
  }
}
int main() {
  diagnostic_protocol_tests();
  diagnostic_tests();
  sibling_failure_tests();
  lease_v2_engine_tests();
  FakeBackend backend;
  orangespace::service::Peer peer{"S-1-5-21-100",1,99};
  auto space=std::make_shared<Namespace>();
  Engine engine(peer, backend, []{return 100;},space);
  // Op6 is local retirement, not API logout; exact strict request shape.
  const auto retire_bytes=request_frame(static_cast<Op>(6),R"({"auth_id":"33333333-3333-4333-8333-333333333333"})");
  check(static_cast<int>(parse_request(retire_bytes).op)==6,"op6 retire accepted");
  const auto auth=engine.authorize(peer,"node","{}");
  const auto binding=engine.start(peer,auth);
  check(binding.user=="11111111-1111-4111-8111-111111111111", "server identity owns binding");
  check(engine.diagnose(peer,auth,binding).find("\"fresh_proof\":false")!=std::string::npos,"cached start proof never substitutes unsupported live diagnostic");
  check(engine.status(peer,auth).find("\"forwarding_verified\":true")!=std::string::npos,"proof states exposed independently, never ready");
  engine.logout(peer,auth);
  bool stale=false;
  try { (void)engine.start(peer,auth); } catch (...) { stale=true; }
  check(stale,"logged out auth never revives");
  // Deterministic forced interleaving: create(A) returns after logout(A).
  const auto late_auth=engine.authorize(peer,"late","{}");
  auto late_session=backend.last;
  late_session->on_create=[&]{engine.logout(peer,late_auth);};
  const int starts_before=backend.started;
  bool late=false;
  try { (void)engine.start(peer,late_auth); } catch (...) {late=true;}
  check(late && backend.started==starts_before && late_session->revokes==1,"late lease revoked, never passed to runtime");
  const auto failure_auth=engine.authorize(peer,"failure","{}");
  auto failed_session=backend.last; failed_session->fail_logout=true;
  bool remote_failed=false;
  try {engine.logout(peer,failure_auth);} catch (...) {remote_failed=true;}
  bool locally_gone=false;
  try {(void)engine.status(peer,failure_auth);} catch (...) {locally_gone=true;}
  check(remote_failed && locally_gone,"remote logout failure cannot retain local grant");
  auto a=engine.authorize(peer,"node-a","{}");
  auto ta=engine.start(peer,a),tb=engine.start(peer,a);
  engine.tick(); check(backend.renewed==2,"lease renewal extends both exact runtime deadlines");
  engine.stop(peer,a,Cursor{ta.sandbox,ta.generation});
  check(engine.status(peer,a).find(tb.tunnel)!=std::string::npos,"stop A keeps independent B");
  bool stale_stop=false;
  try {engine.stop(peer,a,Cursor{ta.sandbox,ta.generation});} catch (...) {stale_stop=true;}
  check(stale_stop,"exact closed tuple cannot be reused");
  auto attacker=peer; ++attacker.logon;
  bool rejected_peer=false;
  try {(void)engine.start(attacker,a);} catch (...) {rejected_peer=true;}
  check(rejected_peer,"same SID new logon LUID rejected");
  backend.living=false; engine.tick(); backend.living=true;
  check(engine.status(peer,a).find(tb.tunnel)==std::string::npos,"helper death removes only binding proof, preserving auth");
  auto cap_auth=engine.authorize(peer,"capacity","{}");
  auto cap_session=backend.last; int depth=0; bool bounded=false;
  cap_session->on_create=[&]{
    if(++depth<=64) try {(void)engine.start(peer,cap_auth);} catch (...) {bounded=true;}
  };
  (void)engine.start(peer,cap_auth);
  check(bounded,"in-flight starts count against resource bound");
  const auto switch_a=engine.authorize(peer,"switch-a","{}");
  const auto switch_b=engine.authorize(peer,"switch-b","{}");
  auto owned=engine.start(peer,switch_a);
  auto sibling=engine.start(peer,switch_a);
  auto switched=engine.start(peer,switch_b,Cursor{owned.sandbox,owned.generation});
  check(switched.sandbox==owned.sandbox && switched.generation>owned.generation,"switch advances service-owned CAS");
  bool old_start=false;
  try {(void)engine.start(peer,switch_a,Cursor{owned.sandbox,owned.generation});} catch (...) {old_start=true;}
  check(old_start && engine.status(peer,switch_a).find(sibling.tunnel)!=std::string::npos,"captured old start cannot reclaim switched sandbox or close sibling");
  auto maintenance_auth=engine.authorize(peer,"maintenance","{}");
  auto maintenance_a=engine.start(peer,maintenance_auth),maintenance_b=engine.start(peer,maintenance_auth);
  backend.on_alive=[&](const Binding& b) {
    if(b==maintenance_a) {engine.stop(peer,maintenance_auth,Cursor{b.sandbox,b.generation});return false;}
    return true;
  };
  engine.tick(); backend.on_alive={};
  check(engine.status(peer,maintenance_auth).find(maintenance_b.tunnel)!=std::string::npos,"late maintenance result for closed A cannot invalidate sibling B auth");
  auto concurrent_auth=engine.authorize(peer,"concurrent","{}");
  auto concurrent_session=backend.last;
  std::promise<void> entered,release;
  auto barrier=release.get_future().share();
  concurrent_session->on_create=[&]{entered.set_value();barrier.wait();};
  const auto before_concurrent=backend.started;
  auto concurrent=std::async(std::launch::async,[&]{
    try {(void)engine.start(peer,concurrent_auth);return false;} catch (...) {return true;}
  });
  entered.get_future().wait(); engine.logout(peer,concurrent_auth); release.set_value();
  check(concurrent.get() && backend.started==before_concurrent,"real threaded logout/create race cannot publish a late runtime");
  std::string newer;
  backend.on_restore=[&]{backend.on_restore={};newer=engine.authorize(peer,"replace","{}");};
  bool superseded=false;
  try {(void)engine.authorize(peer,"replace","{}");} catch (...) {superseded=true;}
  check(superseded && !engine.status(peer,newer).empty(),"late authorize never replaces newer session epoch");
  auto other_peer=peer; other_peer.sid="S-1-5-21-200";
  Engine other(other_peer,backend,[]{return 100;},space);
  auto same_remote=other.authorize(other_peer,"node","{}");
  bool cross_sid=false;
  try {(void)other.start(other_peer,same_remote,Cursor{switched.sandbox,switched.generation});} catch (...) {cross_sid=true;}
  check(cross_sid,"same remote account cannot steal another OS SID sandbox namespace");
  const auto proof_auth=engine.authorize(peer,"proof","{}"); backend.proof={true,false,false};
  bool no_proof=false;
  try {(void)engine.start(peer,proof_auth);} catch (...) {no_proof=true;}
  check(no_proof && engine.status(peer,proof_auth).find("forwarding_verified")==std::string::npos,"stdin delivery/process existence is never forwarding proof");
  backend.proof={true,true,true};
  const auto state=parse_state(R"({"schema":1,"sandboxes":[{"sandbox_id":"44444444-4444-4444-8444-444444444444","sid":"S-1-5-21-100","generation":77}]})");
  check(state.size()==1 && state.front().generation==77,"durable service generation codec");
  auto restarted_space=std::make_shared<Namespace>([state]{return state;},[](const auto&){});
  Engine restarted(peer,backend,[]{return 100;},restarted_space);
  auto restarted_auth=restarted.authorize(peer,"node","{}");
  auto recovered=restarted.start(peer,restarted_auth,Cursor{state.front().sandbox,77});
  check(recovered.generation==78,"restart continues durable max generation, never resets");
  std::vector<Persisted> disk=state;
  auto durable=std::make_shared<Namespace>([&]{return disk;},[&](const auto& next){disk=next;});
  Engine reserve(peer,backend,[]{return 100;},durable);
  const auto reserve_auth=reserve.authorize(peer,"reserve","{}");
  backend.last->on_create=[] {throw std::runtime_error("node unavailable");};
  bool api_failed=false;
  try {(void)reserve.start(peer,reserve_auth,Cursor{state.front().sandbox,77});}catch(...){api_failed=true;}
  check(api_failed && disk.front().generation==78,"failed API attempt retains durable reservation");
  check(state_json(disk).find(reserve_auth)==std::string::npos,"state never serializes random auth IDs");
  bool disk_unwritable=true;
  auto broken=std::make_shared<Namespace>([state]{return state;},[&](const auto&){if(disk_unwritable)throw std::runtime_error("disk full");});
  Engine broken_engine(peer,backend,[]{return 100;},broken);
  auto broken_auth=broken_engine.authorize(peer,"broken","{}");
  const auto before_disk_failure=backend.started;
  bool write_failed=false;
  try {(void)broken_engine.start(peer,broken_auth,Cursor{state.front().sandbox,77});}catch(...){write_failed=true;}
  disk_unwritable=false;
  bool permanent_failure=false;
  try {(void)broken_engine.status(peer,broken_auth);}catch(...){permanent_failure=true;}
  check(write_failed && permanent_failure && backend.started==before_disk_failure,"unwritable state permanently fails closed before runtime/API create");
  // Reserve local backend intent before releasing commit locks for network/proof.
  {
    FakeBackend local;Engine e(peer,local,[]{return 100;});auto grant=e.authorize(peer,"reserved","{}");
    bool reserved=false;local.on_reserve=[&]{reserved=true;};
    local.last->on_create=[&]{check(reserved,"pending backend intent exists before remote allocation");};
    (void)e.start(peer,grant);check(reserved,"backend reservation is mandatory");
  }
  // A forwarding proof must not monopolize the auth/namespace commit locks.
  {
    FakeBackend local; Engine e(peer,local,[]{return 100;});
    auto grant=e.authorize(peer,"pending-proof","{}");
    std::promise<void> entered,release;auto barrier=release.get_future().share();
    local.on_start=[&]{entered.set_value();barrier.wait();};
    auto starting=std::async(std::launch::async,[&]{try{(void)e.start(peer,grant);return false;}catch(...){return true;}});
    entered.get_future().wait();
    auto retiring=std::async(std::launch::async,[&]{e.retire(peer,grant);});
    const bool invalidated=retiring.wait_for(std::chrono::milliseconds(200))==std::future_status::ready;
    release.set_value();retiring.get();const bool late=starting.get();
    check(invalidated && late,"pending proof cannot block local retirement or publish after invalidation");
  }
  // An exact service cursor can cancel a start already proving forwarding.
  {
    FakeBackend local;Engine e(peer,local,[]{return 100;});auto grant=e.authorize(peer,"stop-proof","{}");
    auto previous=e.start(peer,grant);
    std::promise<void> entered,release;auto barrier=release.get_future().share();
    local.on_start=[&]{entered.set_value();barrier.wait();};
    auto starting=std::async(std::launch::async,[&]{try{(void)e.start(peer,grant,Cursor{previous.sandbox,previous.generation});return false;}catch(...){return true;}});
    entered.get_future().wait();bool stopped=true;
    try{(void)e.stop(peer,grant,e.cursor(peer,grant,previous.sandbox));}catch(...){stopped=false;}
    release.set_value();const bool late=starting.get();
    check(stopped && late,"exact pending generation stop invalidates late proof commit");
  }
  // L1: provisional delivery owns only its newly created exact tuple.
  {
    FakeBackend local; Engine e(peer,local,[]{return 100;});
    auto grant=e.authorize(peer,"delivery","{}");
    {auto response=e.start_response(peer,grant);}
    check(local.closed==1 && e.status(peer,grant).find("forwarding_verified")==std::string::npos,"L1 disconnected initial response retires unadopted tuple");
    auto original=e.start(peer,grant);
    {auto response=e.start_response(peer,grant,Cursor{original.sandbox,original.generation});response.finish(false);}
    check(e.status(peer,grant).find("forwarding_verified")==std::string::npos,"L1 lost switch ACK never revives old generation");
    auto response=e.start_response(peer,grant); response.finish(true);
    check(e.status(peer,grant).find("forwarding_verified")!=std::string::npos,"L1 validated ACK adopts new tuple");
    {auto lost=e.authorize_response(peer,"lost-auth","{}");}
    check(local.last->logouts==0,"L1 authorize rollback preserves API token");
    // A stale response callback cannot close a newer committed tuple/auth.
    auto stale=e.start_response(peer,grant);
    const auto root=orangespace::json::parse(stale.body);
    const auto& value=orangespace::node_session::detail::field(root,"binding");
    const auto sbx=orangespace::node_session::detail::text(orangespace::node_session::detail::field(value,"sandbox_id"));
    const auto gen=static_cast<std::uint64_t>(orangespace::node_session::detail::integer(orangespace::node_session::detail::field(value,"generation")));
    auto newer=e.start(peer,grant,Cursor{sbx,gen});const int closes=local.closed;
    stale.finish(false);
    check(local.closed==closes && e.status(peer,grant).find(newer.tunnel)!=std::string::npos,"L1 stale completion cannot retire newer committed tuple");
    auto stopped_response=e.start_response(peer,grant,Cursor{newer.sandbox,newer.generation});
    e.stop(peer,grant,e.cursor(peer,grant,newer.sandbox));const auto stopped_closes=local.closed;
    stopped_response.finish(false);
    check(local.closed==stopped_closes,"L1 stop invalidates pending delivery callback exactly once");
    auto auth_response=e.authorize_response(peer,"replace-response","{}");
    auto newer_auth=e.authorize(peer,"replace-response","{}");auth_response.finish(false);
    check(!e.status(peer,newer_auth).empty(),"L1 stale authorization callback cannot retire newer auth");
    for(int failure=0;failure<3;++failure) {
      auto pending=e.start_response(peer,grant);
      const int before=local.closed;
      check(!pending.deliver([&](std::string_view){return failure!=0;},[&]{return false;}),"L1 failed write / lost or malformed ACK rejected");
      check(local.closed==before+1,"L1 transport failure rolls back immediately");
    }
    auto retiring_response=e.start_response(peer,grant);
    e.retire(peer,grant);const auto retired_closes=local.closed;
    retiring_response.finish(false);
    check(local.closed==retired_closes,"L1 retirement invalidates pending response ownership exactly once");
  }
  // Op6/S2: local retirement revokes leases but never the API login.
  {
    FakeBackend local; Engine e(peer,local,[]{return 100;});
    auto grant=e.authorize(peer,"retire","{}"); auto session=local.last;
    (void)e.start(peer,grant); e.retire(peer,grant);
    check(local.closed>0 && session->revokes==1 && session->logouts==0,"op6 preserves API login and retires local work");
    bool stale=false;try{(void)e.start(peer,grant);}catch(...){stale=true;}
    check(stale,"op6 grant never revives");
  }
  // L2: status polls local runtime before reporting any cached proof, even without tick.
  {
    FakeBackend local; Engine e(peer,local,[]{return 100;});
    auto grant=e.authorize(peer,"dead-status","{}"); (void)e.start(peer,grant);
    local.living=false;bool denied=false;try{(void)e.status(peer,grant);}catch(...){denied=true;}
    check(denied && local.closed>0,"L2 root death before tick cannot return cached active proof");
    check(e.status(peer,grant).find("forwarding_verified")==std::string::npos,"failed helper does not retire reusable auth");
  }
  // Status may report only exact bindings actually polled in this snapshot.
  {
    FakeBackend local;Engine e(peer,local,[]{return 100;});auto grant=e.authorize(peer,"poll-snapshot","{}");
    auto first=e.start(peer,grant);Binding unpolled;
    local.on_alive=[&](const Binding& b){if(b==first){unpolled=e.start(peer,grant);return true;}return false;};
    const auto reply=e.status(peer,grant);local.on_alive={};
    check(reply.find(unpolled.tunnel)==std::string::npos,"L2 status cannot attach unpolled concurrent cached proof");
  }
  // L2: blocked HTTPS maintenance cannot delay independent local-root reconciliation.
  {
    FakeBackend local; Engine e(peer,local,[]{return 100;});
    auto grant=e.authorize(peer,"blocked-refresh","{}"); (void)e.start(peer,grant);
    std::promise<void> entered,release;auto barrier=release.get_future().share();
    local.last->on_refresh=[&]{entered.set_value();barrier.wait();};
    auto remote=std::async(std::launch::async,[&]{e.tick();});entered.get_future().wait();
    local.living=false;e.poll();
    const bool absent=e.status(peer,grant).find("forwarding_verified")==std::string::npos;
    release.set_value();remote.get();
    check(absent && local.closed>0,"L2 independent local poll retires death while HTTPS is blocked");
  }
  // S1: persist failure with an already-running helper, not first allocation.
  for(bool stopping:{false,true}) for(bool logging_out:{false,true}) {
    FakeBackend local; bool fail_save=false;
    auto ledger=std::make_shared<Namespace>([]{return std::vector<Persisted>{};},[&](const auto&){if(fail_save)throw std::runtime_error("disk full");});
    Engine e(peer,local,[]{return 100;},ledger);
    auto grant=e.authorize(peer,"poison","{}"); auto live=e.start(peer,grant);
    fail_save=true; bool failed=false;
    try {if(stopping)(void)e.stop(peer,grant,{live.sandbox,live.generation});else(void)e.start(peer,grant,Cursor{live.sandbox,live.generation});}catch(...){failed=true;}
    check(failed && local.closed>0,"S1 persist failure synchronously closes already-running helper");
    const auto starts=local.started;
    try{(void)e.start(peer,grant);}catch(...){}
    check(local.started==starts,"S1 poison never allocates new work");
    e.poll(); // watchdog must not erase the authenticated remote-cleanup handle on poison
    bool cleanup=true;try{if(logging_out)e.logout(peer,grant);else e.retire(peer,grant);}catch(...){cleanup=false;}
    check(cleanup,"S1 authenticated logout/retire remains usable after poison");
    check(local.last->revokes==1 && local.last->logouts==(logging_out?1:0),"S1 poison retains exact old lease for authenticated cleanup; retire preserves API token");
  }
  auto bytes = request_frame(Op::authorize, R"({"alias":"node","envelope":{"schema":1,"node_id":"11111111-1111-4111-8111-111111111111","api_origin":"https://example.invalid","access_token":"not-a-real-secret","expires_at":9000}})");
  auto parsed = parse_request(bytes);
  check(parsed.op == Op::authorize, "OSP2 authorize decoded");
  bytes[6] = 1;
  bool rejected = false;
  try { (void)parse_request(bytes); } catch (...) { rejected = true; }
  check(rejected, "OSP2 reserved flags rejected");
  auto reject=[](Op op,std::string_view text) {
    try {(void)parse_request(request_frame(op,text));return false;}catch (...) {return true;}
  };
  const auto auth_text=quote(auth);
  check(reject(Op::start,"{\"auth_id\":"+auth_text+",\"user_id\":"+auth_text+"}"),"caller identity claims rejected");
  check(reject(Op::start,"{\"auth_id\":"+auth_text+",\"path\":\"evil.exe\"}"),"arbitrary helper selection rejected");
  check(reject(Op::start,"{\"auth_id\":"+auth_text+",\"auth_id\":"+auth_text+"}"),"duplicate IDs rejected");
  check(reject(Op::stop,"{\"auth_id\":"+auth_text+",\"sandbox_id\":"+auth_text+"}"),"stop without generation CAS rejected");
  check(reject(Op::start,"{\"auth_id\":"+auth_text+",\"sandbox_id\":"+auth_text+",\"expected_generation\":-1}"),"negative generation rejected");
  auto valid=request_frame(Op::status,"{\"auth_id\":"+auth_text+"}");
  for(std::size_t n=0;n<valid.size();++n) {auto truncated=valid;truncated.resize(n);bool fail=false;try{(void)parse_request(truncated);}catch(...){fail=true;}check(fail,"every truncated request rejected");}
  valid.push_back(0); bool extra=false;try{(void)parse_request(valid);}catch(...){extra=true;}check(extra,"trailing frame byte rejected");
  std::cout << "PASS: S1 live switch/stop ledger-poison cleanup + logout/retire; L1 provisional reply/ACK exact rollback + stale callback guards; L2 dead-root/snapshot/HTTP-independent poll; pending proof retirement/stop; OS namespace/CAS/renewal policy (injected backend; NOT native/HTTPS acceptance)\n";
  return 0;
}
