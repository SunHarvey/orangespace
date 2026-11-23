#include "orangespace/platform_session.hpp"
#include "orangespace/sandbox_engine.hpp"
#include <atomic>
#include <chrono>
#include <thread>
#include <iostream>
#include <cassert>
using namespace orangespace::platform_session;
namespace orangespace::platform_session::detail {
struct TestAccess { static PlatformConfig config() { return PlatformConfig(validate_bootstrap(R"({"schema":1,"api_origin":"https://centre.example.test"})")); } };
}
const std::string uid="11111111-1111-4111-8111-111111111111", sid="22222222-2222-4222-8222-222222222222", nid="33333333-3333-4333-8333-333333333333", legacy="44444444-4444-4444-8444-444444444444";
std::string user() { return "{\"central_user_id\":\""+uid+"\",\"username\":\"alice\",\"role\":\"user\",\"enabled\":true,\"user_epoch\":3,\"created_at\":1}"; }
std::string metadata(int expiry=5000) { return "\"schema\":1,\"central_session_id\":\""+sid+"\",\"expires_at\":"+std::to_string(expiry)+",\"user\":"+user(); }
std::string node(std::string id) { return "{\"node_id\":\""+id+"\",\"alias\":\"node.a\",\"display_name\":\"Node A\",\"api_origin\":\"https://node.example.test\",\"tls_server_name\":\"node.example.test\",\"node_epoch\":2,\"config_revision\":4,\"key_fingerprint\":\""+std::string(64,'a')+"\",\"grant_id\":\""+uid+"\",\"grant_epoch\":5,\"scopes\":[\"files.read\",\"tunnel\"],\"mapping_id\":\""+sid+"\",\"mapping_epoch\":6,\"legacy_user_id\":\""+legacy+"\"}"; }
struct Fake final : Transport {
  int pages=0, deletes=0, refreshes=0; bool repeat=false, change=false, large=false, bad_logout=false, offline=false, past_deadline=false; unsigned status=200, refresh_status=200;
  // The Centre rotates both credentials on each refresh: access 'A'+n, refresh 'R'+n.
  char access='A', renewal='R'; int expiry=5000;
  char stale=0;  // the Centre's clock is ahead: this access credential has already expired there
  std::int64_t date=0;  // the Centre's clock as its replies' Date header gives it (0: no header)
  Response request(const Bootstrap& b, std::string_view method, std::string_view path, std::string_view body, std::string_view bearer) override {
    auto r=answer(b,method,path,body,bearer); r.date=date; return r;
  }
  Response answer(const Bootstrap& b, std::string_view method, std::string_view path, std::string_view body, std::string_view bearer) {
    assert(b.api_origin=="https://centre.example.test");
    if(path=="/control/v1/auth/refresh") {
      assert(method=="POST" && bearer.empty() && body.find("\"refresh_token\":\""+std::string(43,renewal)+"\"")!=body.npos);
      if(offline) throw std::runtime_error("connection reset");
      if(refresh_status!=200) return {refresh_status,SerializedSecret("{}")};
      ++refreshes; ++access; ++renewal; expiry+=1800;
      return {200,SerializedSecret("{"+metadata(expiry)+",\"access_token\":\""+std::string(43,access)+"\",\"token_type\":\"bearer\",\"session_deadline\":"+(past_deadline?"90001":"90000")+",\"refresh_token\":\""+std::string(43,renewal)+"\",\"refresh_expires_at\":80000}")};
    }
    if(status!=200) return {status,SerializedSecret("secret backend failure")};
    if(path=="/control/v1/auth/login") { assert(body.find("\"schema\":1")!=body.npos && body.find("\"renewable\":true")!=body.npos); return {200,SerializedSecret("{"+metadata(expiry)+",\"access_token\":\""+std::string(43,access)+"\",\"token_type\":\"bearer\",\"nodes\":[],\"nodes_next_cursor\":null,\"session_deadline\":90000,\"refresh_token\":\""+std::string(43,renewal)+"\",\"refresh_expires_at\":60000}")}; }
    if(stale && bearer==std::string(43,stale)) return {401,SerializedSecret("{}")};
    assert(bearer==std::string(43,access));
    if(path=="/control/v1/session") { auto data="{"+metadata(expiry)+"}"; if(change) data.replace(data.find(uid),uid.size(),legacy); return {200,SerializedSecret(data)}; }
    if(large && path.starts_with("/control/v1/me/nodes")) {
      std::string items;
      for(unsigned i=1;i<=100;++i) {auto id=nid; char suffix[9];std::snprintf(suffix,sizeof(suffix),"%08x",i);id.replace(0,8,suffix);if(!items.empty()) items+=',';items+=node(id);}
      return {200,SerializedSecret("{\"schema\":1,\"items\":["+items+"],\"next_cursor\":null}")};
    }
    if(path.starts_with("/control/v1/me/nodes")) { ++pages; bool first=path.find("cursor=")==path.npos; return {200,SerializedSecret("{\"schema\":1,\"items\":["+node(first?nid:legacy)+"],\"next_cursor\":"+((first||repeat)?"\""+nid+"\"":"null")+"}")}; }
    if(path=="/control/v1/node-exchanges") { assert(body.find("\"user_epoch\":3")!=body.npos && body.find("\"mapping_epoch\":6")!=body.npos); return {201,SerializedSecret("{\"schema\":1,\"exchange_id\":\""+uid+"\",\"exchange_token\":\""+std::string(43,'B')+"\",\"node_id\":\""+nid+"\",\"expires_at\":1020}")}; }
    assert(method=="DELETE" && path=="/control/v1/sessions/"+sid); ++deletes;
    return {202,SerializedSecret(bad_logout ? "{}" : "{\"schema\":1,\"revocation_id\":\""+uid+"\",\"committed_at\":1000,\"enforcement_deadline\":1030,\"cleanup_state\":\"pending\"}")};
  }
};
void session_flow() {
  auto config=detail::TestAccess::config(); Fake fake; auto clock=[] {return std::int64_t(1000);};
  bool oversized=false;try{(void)Session::login(config,"alice",std::string(4096,'\n'),fake,clock);}catch(const std::runtime_error&){oversized=true;}assert(oversized);
  auto s=Session::login(config,"alice","password-for-test",fake,clock);
  assert(s.identity().central_user_id==uid && s.identity().central_session_id==sid);
  const auto all=s.nodes(); assert(all.size()==2 && fake.pages==2 && all[0].remote_legacy_user_id==legacy && uid!=legacy);
  fake.large=true;assert(s.nodes().size()==100);fake.large=false;
  auto ticket=s.issue(nid); assert(ticket.node_id==nid && ticket.expires_at==1020); auto token=ticket.take_token(); assert(token.view()==std::string(43,'B') && ticket.exchange_token.view().empty());
  auto envelope=s.export_envelope(); assert(envelope.view().find("orangespace.platform.session")!=envelope.view().npos);
  auto restored=Session::restore(config,envelope.view(),fake,clock); restored.revalidate();
  auto reject_restore=[&](std::string_view from,std::string_view to) {
    std::string modified(envelope.view());auto pos=modified.find(from);assert(pos!=modified.npos);modified.replace(pos,from.size(),to);
    bool denied=false;try{(void)Session::restore(config,modified,fake,clock);}catch(const std::runtime_error&){denied=true;}assert(denied);
  };
  reject_restore("\"schema\":1","\"schema\":1.0");
  reject_restore("\"schema\":1","\"schema\":2");
  reject_restore("\"user_epoch\":3","\"user_epoch\":0");
  reject_restore("\"user_epoch\":3","\"user_epoch\":3.00000000000000001");
  reject_restore("\"user_epoch\":3","\"user_epoch\":4");
  reject_restore("\"expires_at\":5000","\"expires_at\":1000");
  reject_restore("\"expires_at\":5000","\"expires_at\":4999");
  reject_restore(uid,"00000000-0000-0000-0000-000000000000");
  reject_restore(sid,legacy);
  reject_restore("https://centre.example.test","https://centre.example.test:443");
  reject_restore("orangespace.platform.session","orangespace.node.session");
  bool expired=false;try{(void)Session::restore(config,envelope.view(),fake,[]{return std::int64_t(5000);});}catch(const std::runtime_error&){expired=true;}assert(expired);
  for(unsigned status:{403u,409u,410u,422u,429u,503u}) {fake.status=status;bool denied=false;try{restored.revalidate();}catch(const HttpStatusError& e){denied=e.status_code()==status && std::string(e.what())=="platform HTTPS response rejected";}assert(denied);}fake.status=200;
  fake.change=true; bool denied=false; try { restored.revalidate(); } catch(const std::runtime_error&) {denied=true;} assert(denied); fake.change=false;
  fake.repeat=true; denied=false; try {(void)s.nodes();} catch(const std::runtime_error&) {denied=true;} assert(denied); fake.repeat=false;
  fake.status=401; denied=false; try {s.revalidate();} catch(const HttpStatusError& e) {denied=e.status_code()==401 && std::string(e.what())=="platform HTTPS response rejected";} assert(denied); fake.status=200;
  fake.bad_logout=true;denied=false;try{s.logout();}catch(const std::runtime_error&){denied=true;}assert(denied);fake.bad_logout=false;
  s.logout(); assert(fake.deletes==2); denied=false; try {(void)s.export_envelope();} catch(const std::runtime_error&) {denied=true;} assert(denied);
  assert(!s.renewable());
}
void refresh_flow() {
  auto config=detail::TestAccess::config(); Fake fake; std::int64_t now=1000; auto clock=[&now] {return now;};
  auto s=Session::login(config,"alice","password-for-test",fake,clock);
  assert(s.renewable() && s.identity().expires_at==5000 && s.identity().deadline==90000 && s.renew_at()==3000);
  // A restored copy is not renewable and its deadline is its own expiry.
  auto copy=Session::restore(config,s.export_envelope().view(),fake,clock);
  assert(!copy.renewable() && copy.identity().deadline==5000);
  now=3000; s.refresh();
  assert(fake.refreshes==1 && s.identity().expires_at==6800 && s.renew_at()==4900);
  s.revalidate();  // the rotated access credential is in use
  // A lost response keeps the credentials, so the same refresh can be retried.
  fake.offline=true; bool failed=false; try{s.refresh();}catch(const std::runtime_error&){failed=true;} assert(failed && s.renewable());
  fake.offline=false; s.refresh(); assert(fake.refreshes==2 && s.identity().expires_at==8600);
  // The Centre never moves the hard deadline.
  fake.past_deadline=true; failed=false; try{s.refresh();}catch(const std::runtime_error&){failed=true;} assert(failed); fake.past_deadline=false;
  --fake.access; --fake.renewal; fake.expiry-=1800;  // that rotation was refused here
  fake.refresh_status=503; failed=false; try{s.refresh();}catch(const HttpStatusError& e){failed=e.status_code()==503;} assert(failed && s.renewable());
  // 401: the session has ended (revoked, or the refresh credential was reused).
  fake.refresh_status=401; failed=false; try{s.refresh();}catch(const HttpStatusError& e){failed=e.status_code()==401;} assert(failed && !s.renewable());
}
// The Centre was unreachable past the access expiry: calls say a renewal is
// awaited, and work again once a refresh gets through. A session that can no
// longer be renewed does not claim that.
void expired_awaiting_renewal() {
  auto config=detail::TestAccess::config(); Fake fake; std::int64_t now=1000; auto clock=[&now] {return now;};
  auto s=Session::login(config,"alice","password-for-test",fake,clock);
  now=5000; fake.offline=true;
  bool awaited=false; try{(void)s.nodes();}catch(const AccessExpired&){awaited=true;} assert(awaited && fake.pages==0);
  awaited=false; try{(void)s.issue(nid);}catch(const AccessExpired&){awaited=true;} assert(awaited);
  bool failed=false; try{s.refresh();}catch(const std::runtime_error&){failed=true;} assert(failed && s.renewable());
  fake.offline=false; s.refresh(); assert(s.identity().expires_at==6800 && s.nodes().size()==2);
  now=6800; fake.refresh_status=401; failed=false; try{s.refresh();}catch(const HttpStatusError&){failed=true;} assert(failed && !s.renewable());
  bool other=false; try{(void)s.nodes();}catch(const AccessExpired&){}catch(const std::runtime_error&){other=true;} assert(other);
}
// The Centre's clock is ahead: once it refuses a credential that is still
// valid here, renewals follow its clock; once this clock is corrected, its own.
void centre_lead() {
  auto config=detail::TestAccess::config(); Fake fake; std::int64_t now=1000; auto clock=[&now] {return now;};
  auto s=Session::login(config,"alice","password-for-test",fake,clock);
  s.expired_at_centre();  // refused at 1000 here, expiry 5000: the Centre is at least 4000 s ahead
  s.refresh(); assert(s.identity().expires_at==6800 && s.renew_at()==1900);
  now=5000;  // this clock was corrected: the lead no longer fits a fresh credential
  s.refresh(); assert(s.identity().expires_at==8600 && s.renew_at()==6800);
}
// The window's Centre renews on the session's clock, not on how long it has
// waited: after a sleep (Windows timeouts do not count time asleep) or a clock
// jump past renew_at it refreshes within one check, not after the old wait.
void centre_follows_clock() {
  using namespace std::chrono_literals;
  auto config=detail::TestAccess::config(); Fake fake; std::atomic<std::int64_t> now{1000}; auto clock=[&now] {return now.load();};
  auto s=Session::login(config,"alice","password-for-test",fake,clock);
  assert(s.renew_at()==3000 && s.renew_in()==2000);
  orangespace::sandbox::Centre centre(std::move(s),{},{},50ms);
  std::this_thread::sleep_for(300ms);
  assert(centre.identity().expires_at==5000);  // not due yet: nothing sent
  now=4000;  // the machine slept past renew_at (access expires at 5000)
  const auto give_up=std::chrono::steady_clock::now()+3s;
  while(centre.identity().expires_at==5000 && std::chrono::steady_clock::now()<give_up) std::this_thread::sleep_for(20ms);
  assert(centre.identity().expires_at==6800);
}
// This machine's clock is behind the Centre's: a call is refused (401) while
// the access credential still looks valid here. The Centre renews at once and
// the call succeeds; if the refresh is refused too, the 401 stands.
void centre_renews_on_refusal() {
  using namespace std::chrono_literals;
  auto config=detail::TestAccess::config(); Fake fake; std::atomic<std::int64_t> now{1000}; auto clock=[&now] {return now.load();};
  orangespace::sandbox::Centre centre(Session::login(config,"alice","password-for-test",fake,clock),{},{},50ms);
  fake.stale='A';
  const auto refs=centre.nodes();
  assert(refs.size()==2 && fake.refreshes==1 && centre.identity().expires_at==6800);
  (void)centre.issue(nid);  // the renewed credential is in use
  // The next renewal follows the Centre's clock (lead 4000 s): due at 1900 here, not 3900.
  now=1950;
  const auto give_up=std::chrono::steady_clock::now()+3s;
  while(centre.identity().expires_at==6800 && std::chrono::steady_clock::now()<give_up) std::this_thread::sleep_for(20ms);
  assert(centre.identity().expires_at==8600);
  fake.stale='C'; fake.refresh_status=401;
  bool refused=false; try{(void)centre.nodes();}catch(const HttpStatusError& e){refused=e.status_code()==401;}
  assert(refused && fake.refreshes==2);
}
// This machine's clock runs ahead of the Centre's (here by 5000 s, more than an
// access lifetime): from the replies' Date the session knows the Centre's
// clock, so it signs in, keeps its exchange tickets (30 s at the Centre) and
// renews by the Centre's clock. Without a Date it cannot, as before.
void clock_ahead_of_centre() {
  auto config=detail::TestAccess::config(); Fake fake; std::int64_t now=6000; auto clock=[&now] {return now;};
  bool refused=false; try{(void)Session::login(config,"alice","password-for-test",fake,clock);}catch(const std::runtime_error&){refused=true;} assert(refused);
  fake.date=1000;
  auto s=Session::login(config,"alice","password-for-test",fake,clock);
  assert(s.centre_offset()==-5000 && s.identity().expires_at==5000 && s.renew_at()==8000);
  auto ticket=s.issue(nid); assert(ticket.expires_at==1020);
  now=7000; fake.date=2000; assert(s.nodes().size()==2);  // 5000 is past here, not at the Centre
  now=8000; fake.date=3000; s.refresh(); assert(s.identity().expires_at==6800 && s.renew_at()==9900);
  // A reply without Date keeps what the last one showed.
  fake.date=0; now=8100; s.revalidate(); assert(s.centre_offset()==-5000);
  // A short lead (a ticket's 30 s) was already enough to refuse every ticket.
  Fake plain; now=1100;
  auto t=Session::login(config,"alice","password-for-test",plain,clock);
  refused=false; try{(void)t.issue(nid);}catch(const std::runtime_error&){refused=true;} assert(refused);
  plain.date=1000; t.revalidate(); assert(t.centre_offset()==-100 && t.issue(nid).expires_at==1020);
}
// A reply's Date also shows a Centre clock that is ahead, before any refusal,
// and replaces a lead learnt from a refusal.
void centre_ahead_by_date() {
  auto config=detail::TestAccess::config(); Fake fake; std::int64_t now=1000; auto clock=[&now] {return now;};
  fake.date=4000;
  auto s=Session::login(config,"alice","password-for-test",fake,clock);
  assert(s.centre_offset()==3000 && s.renew_at()==1500);
  s.expired_at_centre(); assert(s.centre_offset()==4000);
  s.refresh(); assert(s.centre_offset()==3000 && s.identity().expires_at==6800 && s.renew_at()==1000+(6800-4000)/2);
}
// Tunnel generations follow the Centre's clock and still only rise.
void generations() {
  using orangespace::sandbox::next_generation;
  assert(next_generation(0, 7000000, -5000)==2000000);  // this clock ahead: the Centre's time
  assert(next_generation(0, 1000000, 600)==1600000);
  assert(next_generation(2000500, 7000000, -5000)==2000501);  // never below the last one
  // The window's Centre reports the offset its session learnt.
  auto config=detail::TestAccess::config(); Fake fake; fake.date=1000; std::atomic<std::int64_t> now{1600}; auto clock=[&now] {return now.load();};
  orangespace::sandbox::Centre centre(Session::login(config,"alice","password-for-test",fake,clock),{},{},std::chrono::milliseconds(50));
  assert(centre.clock_offset()==-600);
}
int main() {
  try {
    auto b = detail::validate_bootstrap(R"({"schema":1,"api_origin":"https://centre.example.test"})");
    assert(b.api_origin == "https://centre.example.test" && b.host == "centre.example.test" && b.port == 443);
    for (const auto input : {R"({"schema":1.0,"api_origin":"https://centre.example.test"})", R"({"schema":2,"api_origin":"https://centre.example.test"})", R"({"schema":1,"api_origin":"http://centre.example.test"})", R"({"schema":1,"api_origin":"https://centre.example.test/"})", R"({"schema":1,"api_origin":"https://user@centre.example.test"})"}) {
      bool denied=false; try { (void)detail::validate_bootstrap(input); } catch (const std::runtime_error&) { denied=true; } assert(denied);
    }
    session_flow();
    refresh_flow();
    expired_awaiting_renewal();
    centre_lead();
    centre_follows_clock();
    centre_renews_on_refusal();
    clock_ahead_of_centre();
    centre_ahead_by_date();
    generations();
    std::cout << "platform bootstrap/session/pagination/identity tests passed\n";
  } catch (const std::exception&) { std::cerr << "platform bootstrap test failed\n"; return 1; }
}
