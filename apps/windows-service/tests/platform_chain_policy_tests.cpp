#include "orangespace/platform_protocol.hpp"
#include <cassert>
#include <iostream>
using namespace orangespace;
namespace pp=service::platform;
template<class F> void denied(F f){bool bad=false;try{f();}catch(...){bad=true;}assert(bad);}
int main(){
  platform_session::NodeRef n; n.node_id="11111111-1111-4111-8111-111111111111";n.alias="node.one";n.api_origin="https://node.test";n.tls_server_name="node.test";n.key_fingerprint=std::string(64,'a');n.grant_id="22222222-2222-4222-8222-222222222222";n.mapping_id="33333333-3333-4333-8333-333333333333";n.remote_legacy_user_id="44444444-4444-4444-8444-444444444444";n.scopes={"tunnel"};n.node_epoch=n.config_revision=n.grant_epoch=n.mapping_epoch=1;
  auto text=pp::node_json(n);auto saved=pp::parse_node(json::parse(text));pp::same_node(n,saved);
  auto changed=n;changed.mapping_epoch++;denied([&]{pp::same_node(n,changed);});
  changed=n;changed.remote_legacy_user_id=n.node_id;denied([&]{pp::same_node(n,changed);});
  node_session::detail::NodeEntry pin{"local-alias",n.node_id,"node.test",443,{}};
  pp::match_catalog(n,pin);pin.host="evil.test";denied([&]{pp::match_catalog(n,pin);});
  auto frame=pp::request_frame(7,"{\"auth_id\":\"22222222-2222-4222-8222-222222222222\",\"sandbox_id\":\"33333333-3333-4333-8333-333333333333\"}");
  assert(pp::parse_request(frame).op==7);frame[3]='2';denied([&]{pp::parse_request(frame);});
  frame=pp::request_frame(2,"{\"auth_id\":\"22222222-2222-4222-8222-222222222222\"}");denied([&]{pp::parse_request(frame);});
  std::cout<<"platform policy: passed (portable model, not native HTTPS/IPC)\n";
}
