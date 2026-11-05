#include "orangespace/platform_session.hpp"
#include <algorithm>
#include <set>
#include <chrono>

namespace orangespace::platform_session {
namespace {
namespace nd = node_session::detail;
void require(bool ok) { if (!ok) throw std::runtime_error("invalid platform session data"); }
Bootstrap origin(std::string_view input) {
  require(input.starts_with("https://") && input.size() <= 300);
  Bootstrap b; b.api_origin = input;
  std::string_view authority = input.substr(8);
  const auto colon = authority.find(':');
  auto host = authority.substr(0, colon);
  require(!host.empty() && host.size() <= 253);
  std::size_t label=0; char previous='.';
  for (char c : host) {
    if(c=='.') { require(label>0 && previous!='-'); label=0; }
    else { require((c>='a' && c<='z') || (c>='0' && c<='9') || (c=='-' && label>0)); require(++label<=63); }
    previous=c;
  }
  require(label>0 && previous!='-');
  b.host=host;
  if(colon!=std::string_view::npos) {
    auto port=authority.substr(colon+1); unsigned n=0; require(!port.empty());
    for(char c:port) { require(c>='0' && c<='9'); n=n*10+static_cast<unsigned>(c-'0'); require(n<=65535); }
    require(n>0 && port==std::to_string(n)); b.port=static_cast<std::uint16_t>(n);
  }
  return b;
}
void wire(std::string_view input) {
  require(input.size()<=1024*1024 && nd::safe_utf8(input));
  nd::exact_wire_integers(input);
}
}
namespace detail {
Bootstrap validate_bootstrap(std::string_view input, const nd::ProtectedConfigReader& reader) {
  wire(input); nd::JsonGuard doc(input);
  const auto version=nd::integer(nd::field(doc.value,"schema"));
  require(version==1 || version==2);
  const auto* ca=doc.value.find("ca_file");
  nd::object(doc.value,version==2 ? 3 : 2);
  require(version==1 || ca!=nullptr);
  auto result=origin(nd::text(nd::field(doc.value,"api_origin")));
  if(version==2) result.ca_pem=nd::load_private_ca(nd::text(*ca),reader);
  return result;
}
}
Session::Session(Bootstrap b, CentralIdentity i, SerializedSecret t, Transport& transport, std::function<std::int64_t()> c)
  : bootstrap_(std::move(b)), identity_(std::move(i)), token_(std::move(t)), transport_(&transport), clock_(std::move(c)) {}
namespace {
struct SecretText { std::string text; ~SecretText() { nd::wipe(text.data(),text.size()); } };
void quote(std::string& out, std::string_view input) {
  out+='"'; constexpr char hex[]="0123456789abcdef";
  for(unsigned char c:input) {
    if(c=='"' || c=='\\') {out+='\\';out+=static_cast<char>(c);}
    else if(c<32) {out+="\\u00";out+=hex[c>>4];out+=hex[c&15];}
    else out+=static_cast<char>(c);
  }
  out+='"';
}
void schema(const json::Value& root, std::size_t size) { nd::object(root,size); require(nd::integer(nd::field(root,"schema"))==1); }
CentralIdentity parse_identity(const json::Value& root, std::int64_t now) {
  CentralIdentity i;
  i.central_session_id=nd::text(nd::field(root,"central_session_id"));
  i.expires_at=nd::integer(nd::field(root,"expires_at"));
  require(nd::uuid(i.central_session_id) && i.expires_at>now);
  const auto& user=nd::field(root,"user"); nd::object(user,6);
  i.central_user_id=nd::text(nd::field(user,"central_user_id"));
  i.username=nd::text(nd::field(user,"username")); i.role=nd::text(nd::field(user,"role"));
  i.user_epoch=nd::integer(nd::field(user,"user_epoch"));
  (void)nd::integer(nd::field(user,"created_at"),0);
  require(nd::uuid(i.central_user_id) && !i.username.empty() && i.username.size()<=256 && nd::safe_utf8(i.username,true));
  require(i.role=="user" || i.role=="admin");
  require(nd::field(user,"enabled").is_true()); return i;
}
void same(const CentralIdentity& a,const CentralIdentity& b) {
  require(a.central_user_id==b.central_user_id && a.central_session_id==b.central_session_id &&
    a.username==b.username && a.role==b.role && a.user_epoch==b.user_epoch && a.expires_at==b.expires_at);
}
NodeRef node_ref(const json::Value& root) {
  nd::object(root,14); NodeRef n;
  n.node_id=nd::text(nd::field(root,"node_id")); n.alias=nd::text(nd::field(root,"alias"));
  n.display_name=nd::text(nd::field(root,"display_name")); n.api_origin=nd::text(nd::field(root,"api_origin"));
  n.tls_server_name=nd::text(nd::field(root,"tls_server_name"));
  n.key_fingerprint=nd::text(nd::field(root,"key_fingerprint"));
  n.grant_id=nd::text(nd::field(root,"grant_id")); n.mapping_id=nd::text(nd::field(root,"mapping_id"));
  n.remote_legacy_user_id=nd::text(nd::field(root,"legacy_user_id"));
  require(nd::uuid(n.node_id) && nd::uuid(n.grant_id) && nd::uuid(n.mapping_id) && nd::uuid(n.remote_legacy_user_id));
  n.node_epoch=nd::integer(nd::field(root,"node_epoch")); n.config_revision=nd::integer(nd::field(root,"config_revision"));
  n.grant_epoch=nd::integer(nd::field(root,"grant_epoch")); n.mapping_epoch=nd::integer(nd::field(root,"mapping_epoch"));
  (void)origin(n.api_origin);
  require(!n.alias.empty() && n.alias.size()<=64);
  const auto alnum=[](char c){return (c>='a' && c<='z') || (c>='0' && c<='9');};
  require(alnum(n.alias.front()));
  for(char c:n.alias) require(alnum(c) || c=='_' || c=='.' || c=='-');
  const auto tls=origin("https://"+n.tls_server_name); require(tls.host==n.tls_server_name);
  require(!n.display_name.empty() && n.display_name.size()<=256 && nd::safe_utf8(n.display_name,true));
  require(n.key_fingerprint.size()==64);
  for(char c:n.key_fingerprint) require((c>='0'&&c<='9')||(c>='a'&&c<='f'));
  const auto* scopes=std::get_if<json::Value::Array>(&nd::field(root,"scopes").data); require(scopes && !scopes->empty() && scopes->size()<=3);
  for(const auto& value:*scopes) { const auto& s=nd::text(value); require(s=="files.read" || s=="files.write" || s=="tunnel"); require(std::find(n.scopes.begin(),n.scopes.end(),s)==n.scopes.end()); n.scopes.push_back(s); }
  return n;
}
std::string cursor(const json::Value& root,std::string_view key) {
  const auto& v=nd::field(root,key); if(std::holds_alternative<std::nullptr_t>(v.data)) return {};
  const auto& s=nd::text(v); require(nd::uuid(s)); return s;
}
void page_items(const json::Value& root,std::string_view key,std::vector<NodeRef>& out) {
  const auto* items=std::get_if<json::Value::Array>(&nd::field(root,key).data); require(items && items->size()<=100);
  for(const auto& item:*items) { auto n=node_ref(item); require(out.empty() || out.back().node_id<n.node_id); out.push_back(std::move(n)); }
}
Response checked_response(Response response,unsigned expected) {
  require(response.status>=100 && response.status<=599 && response.body.view().size()<=1024*1024);
  if(response.status!=expected) throw HttpStatusError(response.status);
  return response;
}
}
void Session::live() const { require(!token_.view().empty() && identity_.expires_at>clock_()); }
Response Session::request(std::string_view method,std::string_view path,std::string_view body,unsigned expected) {
  live(); return checked_response(transport_->request(bootstrap_,method,path,body,token_.view()),expected);
}
Session Session::login(const PlatformConfig& config, std::string_view username, std::string_view password, Transport& transport, std::function<std::int64_t()> clock) {
  require(!username.empty() && username.size()<=256 && nd::safe_utf8(username,true) && !password.empty() && password.size()<=4096 && nd::safe_utf8(password));
  SecretText body; body.text.reserve(32768); body.text="{\"schema\":1,\"username\":";quote(body.text,username);body.text+=",\"password\":";quote(body.text,password);body.text+='}';
  require(body.text.size()<=16384);
  auto response=checked_response(transport.request(config.bootstrap_,"POST","/control/v1/auth/login",body.text,{}),200);
  wire(response.body.view()); nd::JsonGuard doc(response.body.view()); schema(doc.value,8);
  require(nd::text(nd::field(doc.value,"token_type"))=="bearer");
  const auto& token=nd::text(nd::field(doc.value,"access_token")); nd::validate_token(token);
  auto i=parse_identity(doc.value,clock());
  std::vector<NodeRef> initial;page_items(doc.value,"nodes",initial); const auto next=cursor(doc.value,"nodes_next_cursor");
  require(next.empty() || (!initial.empty() && next==initial.back().node_id));
  Session result(config.bootstrap_,std::move(i),SerializedSecret(token),transport,std::move(clock));
  result.revalidate(); return result;
}
void Session::revalidate() {
  auto r=request("GET","/control/v1/session",{},200);wire(r.body.view());nd::JsonGuard doc(r.body.view());schema(doc.value,4);
  same(identity_,parse_identity(doc.value,clock_()));
}
SerializedSecret Session::export_envelope() const {
  live(); SecretText text; text.text.reserve(1024);
  text.text="{\"schema\":1,\"namespace\":\"orangespace.platform.session\",\"api_origin\":";quote(text.text,bootstrap_.api_origin);
  text.text+=",\"central_user_id\":";quote(text.text,identity_.central_user_id);
  text.text+=",\"central_session_id\":";quote(text.text,identity_.central_session_id);
  text.text+=",\"user_epoch\":"+std::to_string(identity_.user_epoch)+",\"expires_at\":"+std::to_string(identity_.expires_at)+",\"access_token\":";
  quote(text.text,token_.view());text.text+='}'; return SerializedSecret(text.text);
}
Session Session::restore(const PlatformConfig& config,std::string_view input,Transport& transport,std::function<std::int64_t()> clock) {
  wire(input);nd::JsonGuard doc(input);schema(doc.value,8);
  require(nd::text(nd::field(doc.value,"namespace"))=="orangespace.platform.session" && nd::text(nd::field(doc.value,"api_origin"))==config.api_origin());
  const auto& token=nd::text(nd::field(doc.value,"access_token"));nd::validate_token(token);
  const auto& uid=nd::text(nd::field(doc.value,"central_user_id"));const auto& sid=nd::text(nd::field(doc.value,"central_session_id"));
  require(nd::uuid(uid) && nd::uuid(sid));const auto epoch=nd::integer(nd::field(doc.value,"user_epoch"));const auto expiry=nd::integer(nd::field(doc.value,"expires_at"));require(expiry>clock());
  auto r=checked_response(transport.request(config.bootstrap_,"GET","/control/v1/session",{},token),200);
  wire(r.body.view());nd::JsonGuard live_doc(r.body.view());schema(live_doc.value,4);auto i=parse_identity(live_doc.value,clock());
  require(i.central_user_id==uid && i.central_session_id==sid && i.user_epoch==epoch && i.expires_at==expiry);
  return Session(config.bootstrap_,std::move(i),SerializedSecret(token),transport,std::move(clock));
}
std::vector<NodeRef> Session::nodes() {
  revalidate();std::vector<NodeRef> result;std::set<std::string> seen;std::string next;
  do {
    std::string path="/control/v1/me/nodes?limit=100";if(!next.empty()) path+="&cursor="+next;
    auto r=request("GET",path,{},200);wire(r.body.view());nd::JsonGuard doc(r.body.view());schema(doc.value,3);
    const auto before=result.size();page_items(doc.value,"items",result);next=cursor(doc.value,"next_cursor");
    if(!next.empty()) require(result.size()>before && next==result.back().node_id && seen.insert(next).second);
    require(result.size()<=100000 && seen.size()<=10000);
  } while(!next.empty());
  revalidate();return result;
}
ExchangeTicket Session::issue(std::string_view id) {
  require(nd::uuid(id));auto all=nodes();auto it=std::find_if(all.begin(),all.end(),[&](const auto& n){return n.node_id==id;});require(it!=all.end());
  SecretText body;body.text="{\"schema\":1,\"node_id\":";quote(body.text,id);
  body.text+=",\"expected_epochs\":{\"user_epoch\":"+std::to_string(identity_.user_epoch)+",\"node_epoch\":"+std::to_string(it->node_epoch)+",\"mapping_epoch\":"+std::to_string(it->mapping_epoch)+",\"grant_epoch\":"+std::to_string(it->grant_epoch)+"}}";
  auto r=request("POST","/control/v1/node-exchanges",body.text,201);wire(r.body.view());nd::JsonGuard doc(r.body.view());schema(doc.value,5);
  ExchangeTicket ticket;ticket.exchange_id=nd::text(nd::field(doc.value,"exchange_id"));ticket.node_id=nd::text(nd::field(doc.value,"node_id"));
  ticket.expires_at=nd::integer(nd::field(doc.value,"expires_at"));const auto& token=nd::text(nd::field(doc.value,"exchange_token"));nd::validate_token(token);
  require(nd::uuid(ticket.exchange_id) && ticket.node_id==id && ticket.expires_at>clock_() && ticket.expires_at<=identity_.expires_at);
  ticket.exchange_token=SerializedSecret(token);return ticket;
}
#ifdef _WIN32
namespace {
class SharedWindowsTransport final : public Transport {
 public:
  Response request(const Bootstrap& bootstrap,std::string_view method,std::string_view path,std::string_view body,std::string_view token) override {
    // Revalidate even this public seam: no caller-supplied host/origin mismatch.
    const auto checked=origin(bootstrap.api_origin);
    require(checked.host==bootstrap.host && checked.port==bootstrap.port);
    nd::NodeEntry node;node.host=checked.host;node.port=checked.port;node.ca_pem=bootstrap.ca_pem;
    Response response;
    nd::central_https_request(node,method,path,body,token,[&](unsigned status,std::string_view bytes) {
      response.status=status;response.body=SerializedSecret(bytes);
    });
    return response;
  }
};
Transport& windows_transport() { static SharedWindowsTransport transport; return transport; }
std::int64_t wall_seconds() { return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count(); }
}
PlatformConfig PlatformConfig::load(const std::wstring& path) {
  return PlatformConfig(detail::validate_bootstrap(nd::read_admin_protected_config(path),nd::read_admin_protected_config));
}
Session Session::login(const PlatformConfig& config,std::string_view user,std::string_view password) {
  return login(config,user,password,windows_transport(),wall_seconds);
}
Session Session::restore(const PlatformConfig& config,std::string_view envelope) {
  return restore(config,envelope,windows_transport(),wall_seconds);
}
#endif
void Session::logout() {
  auto r=request("DELETE","/control/v1/sessions/"+identity_.central_session_id,{},202);
  wire(r.body.view());nd::JsonGuard doc(r.body.view());schema(doc.value,5);
  require(nd::uuid(nd::text(nd::field(doc.value,"revocation_id"))) && nd::text(nd::field(doc.value,"cleanup_state"))=="pending");
  const auto committed=nd::integer(nd::field(doc.value,"committed_at"));
  const auto deadline=nd::integer(nd::field(doc.value,"enforcement_deadline"));require(deadline>=committed);
  token_.clear();identity_.expires_at=0;
}
}
