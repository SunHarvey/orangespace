#include "orangespace/platform_session.hpp"
#include <iostream>
#include <cassert>
using namespace orangespace::platform_session;
namespace orangespace::platform_session::detail {
struct TestAccess { static PlatformConfig config() { return PlatformConfig(validate_bootstrap(R"({"schema":1,"api_origin":"https://centre.example.test"})")); } };
}
const std::string uid="11111111-1111-4111-8111-111111111111", sid="22222222-2222-4222-8222-222222222222", nid="33333333-3333-4333-8333-333333333333", legacy="44444444-4444-4444-8444-444444444444";
std::string user() { return "{\"central_user_id\":\""+uid+"\",\"username\":\"alice\",\"role\":\"user\",\"enabled\":true,\"user_epoch\":3,\"created_at\":1}"; }
std::string metadata() { return "\"schema\":1,\"central_session_id\":\""+sid+"\",\"expires_at\":5000,\"user\":"+user(); }
std::string node(std::string id) { return "{\"node_id\":\""+id+"\",\"alias\":\"node.a\",\"display_name\":\"Node A\",\"api_origin\":\"https://node.example.test\",\"tls_server_name\":\"node.example.test\",\"node_epoch\":2,\"config_revision\":4,\"key_fingerprint\":\""+std::string(64,'a')+"\",\"grant_id\":\""+uid+"\",\"grant_epoch\":5,\"scopes\":[\"files.read\",\"tunnel\"],\"mapping_id\":\""+sid+"\",\"mapping_epoch\":6,\"legacy_user_id\":\""+legacy+"\"}"; }
struct Fake final : Transport {
  int pages=0, deletes=0; bool repeat=false, change=false, large=false, bad_logout=false; unsigned status=200;
  Response request(const Bootstrap& b, std::string_view method, std::string_view path, std::string_view body, std::string_view bearer) override {
    assert(b.api_origin=="https://centre.example.test");
    if(status!=200) return {status,SerializedSecret("secret backend failure")};
    if(path=="/control/v1/auth/login") { assert(body.find("\"schema\":1")!=body.npos); return {200,SerializedSecret("{"+metadata()+",\"access_token\":\""+std::string(43,'A')+"\",\"token_type\":\"bearer\",\"nodes\":[],\"nodes_next_cursor\":null}")}; }
    assert(bearer==std::string(43,'A'));
    if(path=="/control/v1/session") { auto data="{"+metadata()+"}"; if(change) data.replace(data.find(uid),uid.size(),legacy); return {200,SerializedSecret(data)}; }
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
}
int main() {
  try {
    auto b = detail::validate_bootstrap(R"({"schema":1,"api_origin":"https://centre.example.test"})");
    assert(b.api_origin == "https://centre.example.test" && b.host == "centre.example.test" && b.port == 443);
    for (const auto input : {R"({"schema":1.0,"api_origin":"https://centre.example.test"})", R"({"schema":2,"api_origin":"https://centre.example.test"})", R"({"schema":1,"api_origin":"http://centre.example.test"})", R"({"schema":1,"api_origin":"https://centre.example.test/"})", R"({"schema":1,"api_origin":"https://user@centre.example.test"})"}) {
      bool denied=false; try { (void)detail::validate_bootstrap(input); } catch (const std::runtime_error&) { denied=true; } assert(denied);
    }
    session_flow();
    std::cout << "platform bootstrap/session/pagination/identity tests passed\n";
  } catch (const std::exception&) { std::cerr << "platform bootstrap test failed\n"; return 1; }
}
