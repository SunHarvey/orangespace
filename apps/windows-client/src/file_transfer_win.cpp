#include "orangespace/file_transfer.hpp"
#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <mutex>

namespace orangespace::files {
namespace nd = node_session::detail;
namespace detail {
void cancellation_point(const std::atomic<bool>& c) { if(c.load(std::memory_order_relaxed)) throw Cancelled(); }
void DownloadOwnership::publish(const std::atomic<bool>& c,const std::function<void()>& commit) {
 nd::require(owned_);cancellation_point(c);commit();owned_=false;
}
std::vector<Entry> parse_listing(std::string_view body,const TaskScope& task){
 nd::require(body.size()<=1024*1024&&nd::safe_utf8(body));nd::JsonGuard d(body);nd::object(d.value,3);
 nd::require(nd::text(nd::field(d.value,"node_id"))==task.node_id&&nd::text(nd::field(d.value,"path"))==task.path);
 auto a=std::get_if<json::Value::Array>(&nd::field(d.value,"entries").data);nd::require(a);std::vector<Entry> result;
 for(const auto& v:*a){Entry e;e.name=nd::text(nd::field(v,"name"));nd::require(checked_path(e.name)==e.name&&e.name.find('/')==e.name.npos);e.path=task.path.empty()?e.name:task.path+"/"+e.name;checked_path(e.path);auto kind=nd::text(nd::field(v,"kind"));nd::require(kind=="directory"||kind=="file");e.is_directory=kind=="directory";if(!e.is_directory)e.size=static_cast<std::uint64_t>(nd::integer(nd::field(v,"size"),0));
 // Nanosecond metadata exceeds the shared DOM exact integer range. Omit it
 // explicitly rather than fabricate a rounded timestamp.
 result.push_back(std::move(e));}return result;
}
std::string checked_path(std::string_view p, bool root) {
  nd::require(p.size()<=4096 && nd::safe_utf8(p,true));
  if(p.empty()) {nd::require(root);return {};}
  unsigned count=0;
  for(std::size_t start=0;start<=p.size();) {
    auto end=p.find('/',start);if(end==p.npos)end=p.size();
    auto part=p.substr(start,end-start);
    nd::require(++count<=64 && !part.empty() && part.size()<=255 && part!="." && part!=".." && part.find('\\')==part.npos && !part.starts_with(".orangespace-upload-"));
    if(end==p.size())break;
    start=end+1;
  }
  return std::string(p);
}
std::string encode_path(std::string_view p) {
  constexpr char hex[]="0123456789ABCDEF";std::string s;
  for(unsigned char c:p) {
    if((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'||c=='_'||c=='.'||c=='~'||c=='/')s+=static_cast<char>(c);
    else {s+='%';s+=hex[c>>4];s+=hex[c&15];}
  }return s;
}
TaskScope::TaskScope(const FileContext& c,std::string_view p,bool root)
 :central_user_id(c.central_user_id),sandbox_id(c.sandbox_id),node_id(c.node_id),path(checked_path(p,root)) {
 nd::require(nd::uuid(central_user_id)&&nd::uuid(sandbox_id)&&nd::uuid(node_id));
}
}
}
#if defined(_WIN32) && !defined(ORANGESPACE_FILE_LOCAL_IO_ONLY)
#include "file_transfer_local_io_win.hpp"
#include <winhttp.h>
#include <bcrypt.h>
#include <chrono>
#include <system_error>
#include "orangespace/file_https_abi.h"
#include "orangespace/platform_protocol.hpp"
namespace orangespace::files {
namespace {
namespace pp=service::platform;
void check(BOOL b) {if(!b){auto e=GetLastError();throw std::system_error(static_cast<int>(e?e:ERROR_GEN_FAILURE),std::system_category(),"file API operation failed");}}
struct CloseInternet {void operator()(void* p)const noexcept {if(p)WinHttpCloseHandle(p);}};
using Internet=std::unique_ptr<void,CloseInternet>;
using local_io::File;using local_io::LocalPath;using local_io::Part;
struct Secret {std::string value;~Secret(){nd::wipe(value.data(),value.size());}};
struct WideSecret {std::wstring value;~WideSecret(){nd::wipe(value.data(),value.size()*sizeof(wchar_t));}};
std::wstring wide(std::string_view s){return {s.begin(),s.end()};}
std::string quote(std::string_view s){return service::chain::quote(s);}
std::int64_t now(){return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();}
void exchange_body(Secret& b,const ps::ExchangeTicket& t){nd::require(nd::uuid(t.exchange_id));nd::validate_token(t.exchange_token.view());b.value.reserve(256);b.value="{\"schema\":1,\"exchange_id\":\"";b.value+=t.exchange_id;b.value+="\",\"exchange_token\":\"";b.value.append(t.exchange_token.view());b.value+="\"}";}
std::wstring catalog_path(){std::array<wchar_t,32768> b{};auto n=GetModuleFileNameW(nullptr,b.data(),static_cast<DWORD>(b.size()));nd::require(n && n<b.size());std::wstring p(b.data(),n);return p.substr(0,p.find_last_of(L'\\')+1)+L"nodes.json";}
std::string header(HINTERNET r,DWORD type,const wchar_t* name) {
 std::array<wchar_t,256>b{};DWORD n=sizeof(b),i=0;check(WinHttpQueryHeaders(r,type,name,b.data(),&n,&i));std::string out;
 for(DWORD j=0;j<n/sizeof(wchar_t);++j){nd::require(b[j]>=32&&b[j]<=126);out+=static_cast<char>(b[j]);}
 n=sizeof(b);nd::require(!WinHttpQueryHeaders(r,type,name,b.data(),&n,&i)&&GetLastError()==ERROR_WINHTTP_HEADER_NOT_FOUND);return out;
}
std::uint64_t decimal(std::string_view s){std::uint64_t n{};auto [p,e]=std::from_chars(s.data(),s.data()+s.size(),n);nd::require(!s.empty()&&e==std::errc{}&&p==s.data()+s.size());return n;}
// Fixed pool retains uncertain exchange cleanup capabilities; never evict one
// merely because the foreground task was cancelled or its response was lost.
struct Receipt {
 std::shared_ptr<const node_session::TrustedCatalog> catalog;std::string node;
 std::optional<ps::ExchangeTicket> ticket;bool submitted{},pending{},complete{};
 void cleanup(){if(complete)return;if(submitted){nd::require(ticket.has_value());Secret b;exchange_body(b,*ticket);
 try{catalog->federation_exchange(node,b.value,true,[](auto bytes){nd::exact_wire_integers(bytes);nd::JsonGuard d(bytes);nd::object(d.value,2);nd::require(nd::integer(nd::field(d.value,"schema"))==1&&nd::text(nd::field(d.value,"local_session_state"))=="revoked");});}catch(const node_session::ExchangeCleanupAbsent&){}
 }complete=true;ticket.reset();}
};
std::mutex receipt_mutex;std::array<std::shared_ptr<Receipt>,64> receipts;
std::shared_ptr<Receipt> reserve_receipt(std::shared_ptr<const node_session::TrustedCatalog> cat,std::string_view node){std::lock_guard l(receipt_mutex);for(auto& r:receipts)if(r&&r->pending){try{r->cleanup();}catch(...){}if(r->complete)r.reset();break;}for(auto& r:receipts)if(!r){auto prepared=std::make_shared<Receipt>();prepared->catalog=std::move(cat);prepared->node=node;r=prepared;return prepared;}throw std::runtime_error("file exchange cleanup capacity exhausted");}
void abandon(const std::shared_ptr<Receipt>& r)noexcept{if(!r)return;std::lock_guard l(receipt_mutex);r->pending=true;try{r->cleanup();}catch(...){}}
struct Request {
 Internet session,connection,request;std::atomic<bool>& cancel;
 Request(const nd::NodeEntry& n,const wchar_t* method,std::string_view path,std::string_view token,std::atomic<bool>& c):cancel(c){
  detail::cancellation_point(c);
  if(n.ca_pem)throw std::runtime_error("app-private CA streaming is not available");
  session.reset(WinHttpOpen(L"OrangeSpace-Files/1",WINHTTP_ACCESS_TYPE_NO_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0));nd::require(bool(session));
  check(WinHttpSetTimeouts(session.get(),1000,1000,1000,1000));DWORD tls=WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;check(WinHttpSetOption(session.get(),WINHTTP_OPTION_SECURE_PROTOCOLS,&tls,sizeof(tls)));
  connection.reset(WinHttpConnect(session.get(),wide(n.host).c_str(),n.port,0));nd::require(bool(connection));
  request.reset(WinHttpOpenRequest(connection.get(),method,wide(nd::api_path(n,path)).c_str(),nullptr,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE));nd::require(bool(request));
  DWORD policy=WINHTTP_OPTION_REDIRECT_POLICY_NEVER;check(WinHttpSetOption(request.get(),WINHTTP_OPTION_REDIRECT_POLICY,&policy,sizeof(policy)));
  DWORD disable=WINHTTP_DISABLE_REDIRECTS|WINHTTP_DISABLE_COOKIES|WINHTTP_DISABLE_AUTHENTICATION;check(WinHttpSetOption(request.get(),WINHTTP_OPTION_DISABLE_FEATURE,&disable,sizeof(disable)));
  DWORD rev=WINHTTP_ENABLE_SSL_REVOCATION;check(WinHttpSetOption(request.get(),WINHTTP_OPTION_ENABLE_FEATURE,&rev,sizeof(rev)));
  DWORD limit=16384;check(WinHttpSetOption(request.get(),WINHTTP_OPTION_MAX_RESPONSE_HEADER_SIZE,&limit,sizeof(limit)));
  WideSecret auth;auth.value=L"Authorization: Bearer ";auth.value.append(token.begin(),token.end());auth.value+=L"\r\nCache-Control: no-store\r\n";check(WinHttpAddRequestHeaders(request.get(),auth.value.c_str(),static_cast<DWORD>(auth.value.size()),WINHTTP_ADDREQ_FLAG_ADD));
 }
 void send(std::uint64_t length,std::string_view type){detail::cancellation_point(cancel);auto h=L"Content-Type: "+wide(type)+L"\r\nContent-Length: "+std::to_wstring(length)+L"\r\n";check(WinHttpSendRequest(request.get(),h.c_str(),static_cast<DWORD>(h.size()),nullptr,0,length<=std::numeric_limits<DWORD>::max()?static_cast<DWORD>(length):WINHTTP_IGNORE_REQUEST_TOTAL_LENGTH,0));detail::cancellation_point(cancel);}
 void write(const void* p,DWORD n){detail::cancellation_point(cancel);DWORD done{};check(WinHttpWriteData(request.get(),p,n,&done));nd::require(done==n);detail::cancellation_point(cancel);}
 void receive(const nd::NodeEntry& node,unsigned expected){detail::cancellation_point(cancel);check(WinHttpReceiveResponse(request.get(),nullptr));DWORD status{},n=sizeof(status);check(WinHttpQueryHeaders(request.get(),WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,WINHTTP_HEADER_NAME_BY_INDEX,&status,&n,WINHTTP_NO_HEADER_INDEX));nd::require(header(request.get(),WINHTTP_QUERY_CUSTOM,L"X-OrangeSpace-Node")==node.node_id);if(status!=expected)throw node_session::HttpStatusError(status);detail::cancellation_point(cancel);}
 DWORD read(void* p,DWORD n){detail::cancellation_point(cancel);DWORD done{};check(WinHttpReadData(request.get(),p,n,&done));detail::cancellation_point(cancel);return done;}
 std::string json(){auto t=header(request.get(),WINHTTP_QUERY_CONTENT_TYPE,WINHTTP_HEADER_NAME_BY_INDEX);nd::require(t=="application/json"||t=="application/json; charset=utf-8");std::string s;std::array<char,4096>b{};while(auto n=read(b.data(),b.size())){nd::require(s.size()+n<=1024*1024);s.append(b.data(),n);}return s;}
};
// Shared bounded callback adapter. No callback exception crosses Rust/C ABI.
using Source=std::function<std::int64_t(std::uint8_t*,std::size_t)>;
using Sink=std::function<void(const std::uint8_t*,std::size_t)>;
void transfer(const nd::NodeEntry& node,std::string_view method,std::string_view path,std::string_view token,std::uint64_t upload_size,std::atomic<bool>& cancel,const Source& source,const Sink& sink,bool binary,std::uint64_t& total){
 detail::cancellation_point(cancel);
 if(node.ca_pem){
  struct State{const Source& source;const Sink& sink;std::atomic<bool>& cancel;std::exception_ptr exception;};State state{source,sink,cancel,{}};
  auto bytes=[](std::string_view s)->OsHttpsBytes{return {reinterpret_cast<const std::uint8_t*>(s.data()),s.size()};};
  const auto origin="https://"+node.host+":"+std::to_string(node.port),full=nd::api_path(node,path);
  OsHttpsTransferRequest r{};r.origin=bytes(origin);r.ca_pem=bytes(*node.ca_pem);r.method=bytes(method);r.path=bytes(full);r.bearer=bytes(token);r.expected_node=bytes(node.node_id);r.upload_size=upload_size;r.context=&state;
  if(method!="GET")r.read=[](void* p,std::uint8_t* b,std::size_t n)->std::int64_t{auto& s=*static_cast<State*>(p);try{detail::cancellation_point(s.cancel);nd::require(n<=65536);return s.source(b,n);}catch(...){s.exception=std::current_exception();return -1;}};
  r.write=[](void* p,const std::uint8_t* b,std::size_t n)->std::int32_t{auto& s=*static_cast<State*>(p);try{detail::cancellation_point(s.cancel);nd::require(n<=65536);s.sink(b,n);return 0;}catch(...){s.exception=std::current_exception();return -1;}};
  r.cancelled=[](void* p)->std::int32_t{auto& s=*static_cast<State*>(p);return s.exception||s.cancel.load(std::memory_order_relaxed)?1:0;};
  std::uint32_t status{};auto rc=os_https_transfer_v1(&r,&status,&total);if(state.exception)std::rethrow_exception(state.exception);detail::cancellation_point(cancel);if(rc!=0)throw std::runtime_error("file HTTPS transfer failed");return;
 }
 Request r(node,wide(method).c_str(),path,token,cancel);r.send(upload_size,method=="POST"?"application/json":"application/octet-stream");std::array<std::uint8_t,65536>b{};std::uint64_t sent{};
 if(method!="GET"){
  while(sent<upload_size){detail::cancellation_point(cancel);auto n=source(b.data(),static_cast<std::size_t>(std::min<std::uint64_t>(b.size(),upload_size-sent)));nd::require(n>0&&static_cast<std::uint64_t>(n)<=upload_size-sent&&static_cast<std::uint64_t>(n)<=b.size());r.write(b.data(),static_cast<DWORD>(n));sent+=static_cast<std::uint64_t>(n);}
  nd::require(source(b.data(),1)==0);
 }
 r.receive(node,method=="GET"?200:201);auto type=header(r.request.get(),WINHTTP_QUERY_CONTENT_TYPE,WINHTTP_HEADER_NAME_BY_INDEX);
 nd::require(binary?type=="application/octet-stream":type=="application/json"||type=="application/json; charset=utf-8");
 if(binary)total=decimal(header(r.request.get(),WINHTTP_QUERY_CONTENT_LENGTH,WINHTTP_HEADER_NAME_BY_INDEX));
 while(auto n=r.read(b.data(),b.size())) { sink(b.data(),n); }
 detail::cancellation_point(cancel);
}
std::string metadata(const nd::NodeEntry& node,std::string_view method,std::string_view path,std::string_view token,std::atomic<bool>& c,std::string_view input={}){
 std::size_t offset{};std::string response;std::uint64_t total=UINT64_MAX;
 transfer(node,method,path,token,input.size(),c,[&](std::uint8_t* b,std::size_t cap)->std::int64_t{auto n=std::min(cap,input.size()-offset);std::copy_n(input.data()+offset,n,b);offset+=n;return static_cast<std::int64_t>(n);},[&](const std::uint8_t* b,std::size_t n){nd::require(response.size()+n<=1024*1024);response.append(reinterpret_cast<const char*>(b),n);},false,total);return response;
}

}
struct FileClient::Impl {
 const FileContext context;std::mutex mutex;std::unique_ptr<ps::Session> central;
 std::shared_ptr<const node_session::TrustedCatalog> catalog;ps::NodeRef selected;nd::NodeEntry node;
 explicit Impl(const FileContext& c):context(c){detail::TaskScope scope(c,"",true);nd::require(c.platform&&c.central_envelope);central.reset(new ps::Session(ps::Session::restore(*c.platform,c.central_envelope->view())));nd::require(central->identity().central_user_id==c.central_user_id);catalog=std::make_shared<node_session::TrustedCatalog>(node_session::TrustedCatalog::load(catalog_path()));auto all=central->nodes();auto f=std::find_if(all.begin(),all.end(),[&](const auto& n){return n.node_id==c.node_id;});nd::require(f!=all.end());selected=*f;node=catalog->federation_node(c.node_id);pp::match_catalog(selected,node);
 }
 template<class F> void authenticated(std::string_view scope,std::atomic<bool>& cancel,F f){detail::cancellation_point(cancel);central->revalidate();detail::cancellation_point(cancel);auto nodes=central->nodes();detail::cancellation_point(cancel);auto n=std::find_if(nodes.begin(),nodes.end(),[&](const auto& v){return v.node_id==context.node_id;});nd::require(n!=nodes.end());pp::same_node(selected,*n);nd::require(std::find(n->scopes.begin(),n->scopes.end(),scope)!=n->scopes.end());auto receipt=reserve_receipt(catalog,node.node_id);
 struct Cleanup{std::shared_ptr<Receipt> r;~Cleanup(){abandon(r);}} cleanup{receipt};receipt->ticket.emplace(central->issue(node.node_id));detail::cancellation_point(cancel);Secret body;exchange_body(body,*receipt->ticket);receipt->submitted=true;
 catalog->federation_exchange(node.node_id,body.value,false,[&](auto bytes){nd::exact_wire_integers(bytes);nd::JsonGuard doc(bytes);auto expiry=pp::validate_exchange(doc.value,central->identity(),selected,now());auto& credential=nd::field(doc.value,"node_credential");auto& token=nd::text(nd::field(credential,"access_token"));auto verified=node_session::NodeSession::restore(*catalog,node.name,token);nd::require(verified.identity().user_id==selected.remote_legacy_user_id&&verified.identity().node_id==node.node_id&&verified.expires_at()==expiry);detail::cancellation_point(cancel);f(token);});}
};
FileClient::FileClient(const FileContext& c):impl_(std::make_unique<Impl>(c)){}
FileClient::~FileClient()=default;
std::vector<Entry> FileClient::list(std::string_view p,std::atomic<bool>& c){detail::TaskScope task(impl_->context,p,true);std::lock_guard l(impl_->mutex);std::vector<Entry> result;impl_->authenticated("files.read",c,[&](auto token){result=detail::parse_listing(metadata(impl_->node,"GET","/v1/files?path="+detail::encode_path(task.path),token,c),task);});detail::cancellation_point(c);return result;}
void FileClient::mkdir(std::string_view p,std::atomic<bool>& c){detail::TaskScope task(impl_->context,p);std::lock_guard l(impl_->mutex);impl_->authenticated("files.write",c,[&](auto token){auto b="{\"path\":"+quote(task.path)+"}";auto bytes=metadata(impl_->node,"POST","/v1/directories",token,c,b);nd::JsonGuard d(bytes);nd::require(nd::text(nd::field(d.value,"node_id"))==task.node_id&&nd::text(nd::field(d.value,"path"))==task.path);});}
void FileClient::upload(const std::filesystem::path& local,std::string_view remote,std::atomic<bool>& c,Progress progress){detail::TaskScope task(impl_->context,remote);std::lock_guard l(impl_->mutex);detail::cancellation_point(c);LocalPath path(local);File file=path.open_upload();nd::require(file.get()!=INVALID_HANDLE_VALUE);BY_HANDLE_FILE_INFORMATION info{};check(GetFileInformationByHandle(file.get(),&info));nd::require(!(info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))&&GetFileType(file.get())==FILE_TYPE_DISK);auto total=(std::uint64_t(info.nFileSizeHigh)<<32)|info.nFileSizeLow;
 impl_->authenticated("files.write",c,[&](auto token){std::uint64_t done{},response_total=UINT64_MAX;std::string bytes;
 transfer(impl_->node,"PUT","/v1/files/"+detail::encode_path(task.path)+"?overwrite=false",token,total,c,[&](std::uint8_t* b,std::size_t cap)->std::int64_t{detail::cancellation_point(c);DWORD count{};check(ReadFile(file.get(),b,static_cast<DWORD>(cap),&count,nullptr));done+=count;nd::require(done<=total);if(progress)progress(done,total);return count;},[&](const std::uint8_t* b,std::size_t n){nd::require(bytes.size()+n<=16384);bytes.append(reinterpret_cast<const char*>(b),n);},false,response_total);
 nd::require(done==total);nd::JsonGuard d(bytes);nd::require(nd::text(nd::field(d.value,"node_id"))==task.node_id&&nd::text(nd::field(d.value,"path"))==task.path&&static_cast<std::uint64_t>(nd::integer(nd::field(d.value,"size"),0))==total);});}
void FileClient::download(std::string_view remote,const std::filesystem::path& local,std::atomic<bool>& c,Progress progress){detail::TaskScope task(impl_->context,remote);std::lock_guard l(impl_->mutex);detail::cancellation_point(c);Part part(local);impl_->authenticated("files.read",c,[&](auto token){std::uint64_t total=UINT64_MAX,done{};
 transfer(impl_->node,"GET","/v1/files/"+detail::encode_path(task.path),token,0,c,{},[&](const std::uint8_t* b,std::size_t count){nd::require(done<=UINT64_MAX-count&&(total==UINT64_MAX||(done<=total&&count<=total-done)));DWORD written{};check(WriteFile(part.file.get(),b,static_cast<DWORD>(count),&written,nullptr));nd::require(written==count);done+=count;if(progress)progress(done,total==UINT64_MAX?0:total);},true,total);
 nd::require(total==UINT64_MAX||done==total);detail::cancellation_point(c);part.publish(c);});}
}
#endif
