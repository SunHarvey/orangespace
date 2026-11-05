#pragma once
#include "orangespace/service_chain.hpp"
#include "orangespace/platform_session.hpp"
namespace orangespace::service::platform {
namespace nd=node_session::detail;
namespace ch=chain;
using platform_session::NodeRef;
inline std::string node_json(const NodeRef& n) {
  std::string s="{";
  auto field=[&](std::string_view key,const std::string& value){if(s.size()>1)s+=',';s+=ch::quote(key)+":"+ch::quote(value);};
  field("node_id",n.node_id);field("alias",n.alias);field("display_name",n.display_name);field("api_origin",n.api_origin);field("tls_server_name",n.tls_server_name);field("key_fingerprint",n.key_fingerprint);field("grant_id",n.grant_id);field("mapping_id",n.mapping_id);field("legacy_user_id",n.remote_legacy_user_id);
  s+=",\"node_epoch\":"+std::to_string(n.node_epoch)+",\"config_revision\":"+std::to_string(n.config_revision)+",\"grant_epoch\":"+std::to_string(n.grant_epoch)+",\"mapping_epoch\":"+std::to_string(n.mapping_epoch)+",\"scopes\":[";
  for(const auto& v:n.scopes){if(s.back()!='[')s+=',';s+=ch::quote(v);}return s+"]}";
}
inline NodeRef parse_node(const json::Value& v) {
  nd::object(v,14);NodeRef n;
  n.node_id=nd::text(nd::field(v,"node_id"));n.alias=nd::text(nd::field(v,"alias"));n.display_name=nd::text(nd::field(v,"display_name"));n.api_origin=nd::text(nd::field(v,"api_origin"));n.tls_server_name=nd::text(nd::field(v,"tls_server_name"));n.key_fingerprint=nd::text(nd::field(v,"key_fingerprint"));n.grant_id=nd::text(nd::field(v,"grant_id"));n.mapping_id=nd::text(nd::field(v,"mapping_id"));n.remote_legacy_user_id=nd::text(nd::field(v,"legacy_user_id"));
  nd::require(nd::uuid(n.node_id)&&nd::uuid(n.grant_id)&&nd::uuid(n.mapping_id)&&nd::uuid(n.remote_legacy_user_id));
  n.node_epoch=nd::integer(nd::field(v,"node_epoch"));n.config_revision=nd::integer(nd::field(v,"config_revision"));n.grant_epoch=nd::integer(nd::field(v,"grant_epoch"));n.mapping_epoch=nd::integer(nd::field(v,"mapping_epoch"));
  const auto* scopes=std::get_if<json::Value::Array>(&nd::field(v,"scopes").data);nd::require(scopes&&scopes->size()<=3);
  for(const auto& s:*scopes){auto t=nd::text(s);nd::require(t=="tunnel"||t=="files.read"||t=="files.write");nd::require(std::find(n.scopes.begin(),n.scopes.end(),t)==n.scopes.end());n.scopes.push_back(t);}
  nd::require(std::find(n.scopes.begin(),n.scopes.end(),"tunnel")!=n.scopes.end());return n;
}
inline void same_node(const NodeRef& a,const NodeRef& b) {
  nd::require(a.node_id==b.node_id&&a.alias==b.alias&&a.api_origin==b.api_origin&&a.tls_server_name==b.tls_server_name&&a.key_fingerprint==b.key_fingerprint&&a.grant_id==b.grant_id&&a.mapping_id==b.mapping_id&&a.remote_legacy_user_id==b.remote_legacy_user_id&&a.node_epoch==b.node_epoch&&a.config_revision==b.config_revision&&a.grant_epoch==b.grant_epoch&&a.mapping_epoch==b.mapping_epoch);
  auto x=a.scopes,y=b.scopes;std::sort(x.begin(),x.end());std::sort(y.begin(),y.end());nd::require(x==y);
}
inline void match_catalog(const NodeRef& n,const nd::NodeEntry& pin) {
  nd::require(n.node_id==pin.node_id&&n.tls_server_name==pin.host);
  // Static schema1 catalog pins HTTPS host/port/node, not signing fingerprints.
  const auto explicit_origin=nd::api_origin(pin);
  const auto default_origin="https://"+pin.host+pin.api_prefix;
  nd::require(n.api_origin==explicit_origin||(pin.port==443&&n.api_origin==default_origin));
}
inline std::vector<std::uint8_t> request_frame(std::uint8_t op,std::string_view body) {
  nd::require(op>=1&&op<=9);auto result=ch::request_frame(static_cast<ch::Op>(op),body);result[3]='3';return result;
}
struct Request {std::uint8_t op;nd::JsonGuard body;Request(std::uint8_t op_,std::string_view text):op(op_),body(text){}};
inline Request parse_request(std::span<const std::uint8_t> bytes) {
  nd::require(bytes.size()>=12&&bytes.size()<=12+ch::max_payload&&bytes[0]=='O'&&bytes[1]=='S'&&bytes[2]=='P'&&bytes[3]=='3'&&bytes[4]>=1&&bytes[4]<=9&&bytes[5]==0&&bytes[6]==0&&bytes[7]==0);
  std::uint32_t size{};for(unsigned i=0;i<4;++i)size|=std::uint32_t(bytes[8+i])<<(8*i);nd::require(size==bytes.size()-12);
  std::string_view text(reinterpret_cast<const char*>(bytes.data()+12),size);nd::require(nd::safe_utf8(text));nd::exact_wire_integers(text);
  Request r(bytes[4],text);const auto& v=r.body.value;
  if(r.op==1){nd::object(v,2);nd::require(nd::text(nd::field(v,"envelope")).size()<=8192);(void)parse_node(nd::field(v,"node"));}
  else {
    nd::require(nd::uuid(nd::text(nd::field(v,"auth_id"))));
    const auto* obj=std::get_if<json::Value::Object>(&v.data);nd::require(obj);
    if(r.op==9){nd::object(v,4);ch::validate_binding_dto(nd::field(v,"binding"));const auto command=nd::integer(nd::field(v,"command"),0);nd::require(command<=6);const auto& url=nd::text(nd::field(v,"url"));nd::require(url.size()<=2048);if(command==1){nd::require(url.starts_with("https://")||url.starts_with("http://"));for(unsigned char c:url)nd::require(c>=32&&c!=127);}else nd::require(url.empty());}
    else if(r.op==8){nd::object(v,2);ch::validate_binding_dto(nd::field(v,"binding"));}
    else if(r.op==2||r.op==3){nd::object(v,3);nd::require(nd::uuid(nd::text(nd::field(v,"sandbox_id"))));(void)nd::integer(nd::field(v,"expected_generation"),0);}
    else if(r.op==7||(r.op==5&&obj->size()==2)){nd::object(v,2);nd::require(nd::uuid(nd::text(nd::field(v,"sandbox_id"))));}
    else nd::object(v,1);
  }return r;
}
inline std::int64_t validate_exchange(const json::Value& root,const platform_session::CentralIdentity& c,const NodeRef& n,std::int64_t now) {
  nd::object(root,3);nd::require(nd::integer(nd::field(root,"schema"))==1);
  const auto& f=nd::field(root,"federation");nd::object(f,9);
  nd::require(nd::uuid(nd::text(nd::field(f,"federation_session_id"))));
  nd::require(nd::text(nd::field(f,"central_user_id"))==c.central_user_id&&nd::text(nd::field(f,"central_session_id"))==c.central_session_id&&nd::text(nd::field(f,"node_id"))==n.node_id&&nd::text(nd::field(f,"legacy_user_id"))==n.remote_legacy_user_id&&nd::text(nd::field(f,"mapping_id"))==n.mapping_id&&nd::text(nd::field(f,"grant_id"))==n.grant_id);
  const auto& e=nd::field(f,"epochs");nd::object(e,4);
  nd::require(nd::integer(nd::field(e,"user_epoch"))==c.user_epoch&&nd::integer(nd::field(e,"node_epoch"))==n.node_epoch&&nd::integer(nd::field(e,"mapping_epoch"))==n.mapping_epoch&&nd::integer(nd::field(e,"grant_epoch"))==n.grant_epoch);
  const auto expiry=nd::integer(nd::field(f,"expires_at"));nd::require(expiry>now&&expiry<=c.expires_at);
  const auto& credential=nd::field(root,"node_credential");nd::object(credential,5);
  nd::require(nd::integer(nd::field(credential,"schema"))==1&&nd::text(nd::field(credential,"node_id"))==n.node_id&&nd::text(nd::field(credential,"api_origin"))==n.api_origin&&nd::integer(nd::field(credential,"expires_at"))==expiry);
  nd::validate_token(nd::text(nd::field(credential,"access_token")));return expiry;
}
}
