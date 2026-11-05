// Actual PlatformNode/receipt bodies + actual portable Centre SDK; Node HTTPS
// and protected file observations are explicit mock seams, NOT native evidence.
#include "orangespace/platform_protocol.hpp"
#include <cassert>
#include <array>
#include <iostream>
using namespace orangespace;
const std::string uid="11111111-1111-4111-8111-111111111111",sid="22222222-2222-4222-8222-222222222222",nid="33333333-3333-4333-8333-333333333333",legacy="44444444-4444-4444-8444-444444444444";
int exchanged=0,cleaned=0,restored=0;bool cleanup_fail=false,wrong_uid=false,wrong_expiry=false,wrong_mapping=false;
namespace orangespace::platform_session::detail {struct TestAccess {static PlatformConfig config(){return PlatformConfig(validate_bootstrap(R"({"schema":1,"api_origin":"https://centre.test"})"));}};}
platform_session::NodeRef selected(){platform_session::NodeRef n;n.node_id=nid;n.alias="node.a";n.display_name="A";n.api_origin="https://node.test";n.tls_server_name="node.test";n.key_fingerprint=std::string(64,'a');n.grant_id=uid;n.mapping_id=sid;n.remote_legacy_user_id=legacy;n.node_epoch=n.config_revision=n.grant_epoch=n.mapping_epoch=1;n.scopes={"tunnel"};return n;}
std::string metadata(){return "\"schema\":1,\"central_session_id\":\""+sid+"\",\"expires_at\":5000,\"user\":{\"central_user_id\":\""+uid+"\",\"username\":\"a\",\"role\":\"user\",\"enabled\":true,\"user_epoch\":1,\"created_at\":1}";}
struct Centre final:platform_session::Transport {
 bool denied=false,changed=false;int deletes=0;
 platform_session::Response request(const platform_session::Bootstrap&,std::string_view method,std::string_view path,std::string_view,std::string_view)override {
  using platform_session::SerializedSecret;
  if(denied)return {403,SerializedSecret("{}")} ;
  if(method=="DELETE"){++deletes;throw std::runtime_error("central logout forbidden");}
  if(path=="/control/v1/auth/login")return {200,SerializedSecret("{"+metadata()+",\"access_token\":\""+std::string(43,'A')+"\",\"token_type\":\"bearer\",\"nodes\":[],\"nodes_next_cursor\":null}")};
  if(path=="/control/v1/session")return {200,SerializedSecret("{"+metadata()+"}")};
  if(path.starts_with("/control/v1/me/nodes")){auto n=selected();if(changed)n.mapping_epoch++;return {200,SerializedSecret("{\"schema\":1,\"items\":["+service::platform::node_json(n)+"],\"next_cursor\":null}")};}
  assert(path=="/control/v1/node-exchanges");return {201,SerializedSecret("{\"schema\":1,\"exchange_id\":\""+uid+"\",\"exchange_token\":\""+std::string(43,'B')+"\",\"node_id\":\""+nid+"\",\"expires_at\":1020}")};
 }
};
namespace orangespace::node_session {
TrustedCatalog TrustedCatalog::load(const std::wstring&){return TrustedCatalog({detail::NodeEntry{"local_alias",nid,"node.test",443,{}}});}
const detail::NodeEntry& TrustedCatalog::federation_node(std::string_view id)const{assert(id==nid);return nodes_[0];}
void TrustedCatalog::federation_exchange(std::string_view id,std::string_view body,bool cleanup,const std::function<void(std::string_view)>& receive)const{
 assert(id==nid&&body.find(std::string(43,'B'))!=body.npos);
 if(cleanup){if(cleanup_fail)throw std::runtime_error("mock cleanup unavailable");++cleaned;receive(R"({"schema":1,"local_session_state":"revoked"})");return;}
 ++exchanged;
 const auto f="{\"federation_session_id\":\""+uid+"\",\"central_user_id\":\""+uid+"\",\"central_session_id\":\""+sid+"\",\"node_id\":\""+nid+"\",\"legacy_user_id\":\""+legacy+"\",\"mapping_id\":\""+(wrong_mapping?uid:sid)+"\",\"grant_id\":\""+uid+"\",\"epochs\":{\"user_epoch\":1,\"node_epoch\":1,\"mapping_epoch\":1,\"grant_epoch\":1},\"expires_at\":4000}";
 receive("{\"schema\":1,\"federation\":"+f+",\"node_credential\":{\"schema\":1,\"node_id\":\""+nid+"\",\"api_origin\":\"https://node.test\",\"access_token\":\""+std::string(43,'C')+"\",\"expires_at\":4000}}");
}
NodeSession NodeSession::restore(const TrustedCatalog& c,std::string_view alias,std::string_view token){assert(alias=="local_alias"&&token==std::string(43,'C'));++restored;detail::LoginReply r(std::string(token),wrong_expiry?3999:4000);return NodeSession(c.nodes_[0],{wrong_uid?uid:legacy,"a",nid},r);}
NodeSession NodeSession::restore_envelope(const TrustedCatalog& c,std::string_view alias,std::string_view){return restore(c,alias,std::string(43,'C'));}
std::string NodeSession::credential_envelope()const{return "{}";}
LeaseResult NodeSession::create_tunnel(std::string_view)const{throw std::runtime_error("not exercised");}
RenewResult NodeSession::renew_tunnel(std::string_view)const{throw std::runtime_error("not exercised");}
void NodeSession::revoke_tunnel(std::string_view)const{}
}
namespace orangespace::service::win {
using namespace chain;namespace detail=node_session::detail;
std::int64_t chain_now(){return 1000;}
#include "../src/platform_chain_windows.inc"
}
template<class F>void denied(F f){bool bad=false;try{f();}catch(...){bad=true;}assert(bad);}
int main(){
 using namespace service::win;auto catalog=std::make_shared<node_session::TrustedCatalog>(node_session::TrustedCatalog::load(L"mock"));PlatformReceipts pool;Centre centre;
 auto make=[&]{auto s=platform_session::Session::login(platform_session::detail::TestAccess::config(),"a","test-only",centre,[]{return std::int64_t(1000);});auto r=pool.reserve(catalog,nid);return std::make_shared<PlatformNode>(catalog,r,std::move(s),selected());};
 {auto p=make();p->initialize();assert(p->identity().user==legacy&&p->identity().central_user==uid);p->refresh();centre.changed=true;denied([&]{p->refresh();});centre.changed=false;p->logout();denied([&]{p->refresh();});assert(centre.deletes==0);}
 assert(exchanged==1&&cleaned==1&&restored==2);
 // Destroying an unadopted session is the same ownership edge as lost ACK.
 cleanup_fail=true;{auto p=make();p->initialize();}assert(cleaned==1);
 cleanup_fail=false;{auto r=pool.reserve(catalog,nid);assert(cleaned==2);r->abandon();}
 for(auto flag:{&wrong_uid,&wrong_expiry,&wrong_mapping}){*flag=true;{auto p=make();denied([&]{p->initialize();});}*flag=false;}
 assert(cleaned==5&&centre.deletes==0);
 std::cout<<"platform backend: independent restore, identity/expiry/mapping denial, refresh epoch denial, exact retained cleanup, no central logout passed (mockHTTP policy)\n";
}
