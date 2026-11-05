// Exact extracted WindowsBackend methods with injected OS/FFI seams.
// No Windows, HTTPS, helper, SCM or kernel containment acceptance.
#include "orangespace/service_chain.hpp"
#include <array>
#include <set>
#include <iostream>
using namespace orangespace::service::chain;
static std::int64_t mono=100000;
namespace fixture_detail {
using namespace orangespace::node_session::detail;
std::int64_t monotonic_ms() {return mono;}
}
namespace detail=fixture_detail;
namespace json=orangespace::json;
static std::function<void()> on_verify,on_new;
static int calls{}, frees{};
static std::function<std::ptrdiff_t(std::string_view,std::uint8_t*,std::size_t)> ffi_reply;
static std::vector<std::string>* recorded;
static std::function<void()>* call_hook;
std::ptrdiff_t os_runtime_call(void*,const std::uint8_t* p,std::size_t n,std::uint8_t* out,std::size_t cap) {
  ++calls;const std::string_view request(reinterpret_cast<const char*>(p),n);
  if(recorded)recorded->emplace_back(request);
  if(call_hook && *call_hook)(*call_hook)();
  if(ffi_reply)return ffi_reply(request,out,cap);
  const std::string reply=R"({"ok":true,"process_started":true,"tunnel_authenticated":true,"forwarding_verified":true,"exited":[]})";
  std::copy(reply.begin(),reply.end(),out);return reply.size();
}
void* os_runtime_new(const std::uint8_t*,std::size_t,unsigned) {if(on_new)on_new();return reinterpret_cast<void*>(1);}
void* os_runtime_new_with_ca_v1(const std::uint8_t* p,std::size_t n,unsigned t,const std::uint8_t*,std::size_t) {return os_runtime_new(p,n,t);}
void os_runtime_free(void*) {++frees;}
struct PinnedFile {
  explicit PinnedFile(const std::wstring&) {}
  void hash() {}
  void verify() {if(on_verify)on_verify();}
};
std::wstring installation() {return L"fixture\\";}
std::string utf8(std::wstring_view) {return "fixture-helper";}
#define ORANGESPACE_TEST_ACTUAL_CALL
#include "lease_v2_backend_under_test.hpp"
void check(bool c,const char* message) {if(!c)throw std::runtime_error(message);}
template<class F> void denies(F run) {bool rejected=false;try{run();}catch(...){rejected=true;}check(rejected,"expected backend denial");}
int main() {
  const Binding binding{"11111111-1111-4111-8111-111111111111","22222222-2222-4222-8222-222222222222","33333333-3333-4333-8333-333333333333","44444444-4444-4444-8444-444444444444",1};
  const std::string realm="realm";
  for(int seam=0;seam<5;++seam) {
    mono=100000;calls=0;on_verify={};on_new={};ExtractedBackend b;recorded=&b.requests;call_hook=&b.on_call;
    b.reserve(realm,binding);
    LeaseResult lease("{\"lease_schema\":2,\"remaining_ttl_ms\":20}",{std::string(nd::lease_clock),100000,20,100020},131);
    if(seam==0)mono=100020;
    if(seam==1)on_verify=[]{mono=100020;};
    if(seam==2)on_new=[]{mono=100020;};
    if(seam==3)b.on_call=[]{mono=100020;};
    if(seam==4)b.on_call=[&]{std::lock_guard lock(b.mutex_);b.realms_.at(realm)->active.erase(binding.tunnel);};
    denies([&]{(void)b.start(realm,binding,lease);});
    check(calls==((seam>=3)?1:0),"expired queued/start budget must never enter FFI");
    on_verify={};on_new={};
  }
  mono=100000;calls=0;ExtractedBackend b;recorded=&b.requests;call_hook=&b.on_call;b.reserve(realm,binding);
  LeaseResult lease("{\"lease_schema\":2,\"remaining_ttl_ms\":20}",{std::string(nd::lease_clock),100000,20,100020},131);
  (void)b.start(realm,binding,lease);
  auto start=orangespace::json::parse(b.requests.back());nd::object(start,5);
  check(nd::integer(nd::field(start,"schema"))==2,"start schema2");
  const auto& sent=nd::field(start,"budget");nd::object(sent,4);
  check(nd::integer(nd::field(sent,"request_started_ms"))==100000 && nd::integer(nd::field(sent,"deadline_ms"))==100020,"FFI preserves original start anchor");
  mono=100001;
  RenewResult renewal{131,{std::string(nd::lease_clock),100001,30,100031}};
  Binding live=binding;live.server_expiry=131;live.deadline_ms=100020;
  const auto stale=live;
  b.renew(realm,live,renewal);
  check(b.realms_.at(realm)->active.at(binding.tunnel).deadline_ms==100020,"equal expiry doesn't extend backend deadline");
  auto renew=orangespace::json::parse(b.requests.back());nd::object(renew,5);
  check(nd::integer(nd::field(renew,"schema"))==2 && nd::integer(nd::field(nd::field(renew,"budget"),"deadline_ms"))==100031,"renew carries unchanged request budget, not effective re-anchor");
  const auto before=calls;renewal.expires_at=130;denies([&]{b.renew(realm,live,renewal);});check(calls==before,"regression never reaches FFI");
  renewal.expires_at=132;b.on_call=[]{mono=100020;};denies([&]{b.renew(realm,live,renewal);});
  check(b.realms_.at(realm)->active.at(binding.tunnel).deadline_ms==100020,"late renewal cannot resurrect expired old binding");
  b.on_call={};mono=100001;b.renew(realm,live,renewal);
  const auto before_stale=calls;
  denies([&]{b.renew(realm,stale,renewal);});
  check(calls==before_stale,"stale same-tuple renewal must not enter FFI or overwrite new authority");
  b.close(realm,binding);
  auto close=orangespace::json::parse(b.requests.back());nd::object(close,3);check(nd::integer(nd::field(close,"schema"))==2,"close schema2");
  mono=100000;ExtractedBackend poll;recorded=&poll.requests;call_hook=&poll.on_call;poll.reserve(realm,binding);(void)poll.start(realm,binding,lease);(void)poll.alive(realm,binding);
  auto polled=orangespace::json::parse(poll.requests.back());nd::object(polled,2);check(nd::integer(nd::field(polled,"schema"))==2,"poll schema2");
  // RAM ABI seams, exercising actual production start/call/close/parser.
  recorded=nullptr;call_hook=nullptr;
  for(int mode=0;mode<38;++mode) {
    mono=100000;ffi_reply={};ExtractedBackend backend;
    Binding a=binding, sibling=binding;sibling.tunnel="55555555-5555-4555-8555-555555555555";sibling.sandbox="66666666-6666-4666-8666-666666666666";
    backend.reserve(realm,sibling);(void)backend.start(realm,sibling,lease);
    backend.reserve(realm,a);
    ffi_reply=[](std::string_view,std::uint8_t* out,std::size_t){const std::string r="{\"ok\":false}";std::copy(r.begin(),r.end(),out);return r.size();};
    if(mode==24) {ffi_reply={};(void)backend.start(realm,a,lease);a.server_expiry=lease.expires_at;a.deadline_ms=lease.budget.deadline_ms;}
    else denies([&]{(void)backend.start(realm,a,lease);});
    if(mode==1)mono=100100; // expired A: cleanup budget must not be lease authority
    if(mode==2) { // old A after newer same-sandbox generation publication
      Binding replacement=a;replacement.generation=2;replacement.tunnel="77777777-7777-4777-8777-777777777777";
      backend.reserve(realm,replacement);
    }
    ffi_reply=[&](std::string_view req,std::uint8_t* out,std::size_t)->std::ptrdiff_t {
      if(req.find("\"op\":\"close\"")!=std::string_view::npos)return mode==3?-2:mode==4?-4:mode==5?0:mode==6?70000:-1;
      if(mode==25)return -2;
      if(mode==26)return -4;
      if(mode==27)return -1;
      auto request=json::parse(req);auto budget=nd::field(request,"budget");
      auto observed=nd::integer(nd::field(budget,"request_started_ms"));
      std::string r="{\"ok\":false,\"process_alive\":false,\"forwarding_verified\":false,\"binding\":"+binding_json(a)+",\"observed_at_ms\":"+std::to_string(observed)+",\"lease_deadline_ms\":0,\"expires_at\":0,\"reason\":\""+(mode==1?"expired":mode==2?"helper_stopped":"not_active")+"\"}";
      auto change=[&](std::string_view from,std::string_view to){r.replace(r.find(from),from.size(),to);};
      if(mode==7)change("\"ok\":false","\"ok\":true");
      if(mode==8)change("\"process_alive\":false","\"process_alive\":0");
      if(mode==9)change("\"forwarding_verified\":false","\"forwarding_verified\":null");
      if(mode==10)change("not_active","probe_failed");
      if(mode==11)change("\"lease_deadline_ms\":0","\"lease_deadline_ms\":1");
      if(mode==12)change("\"expires_at\":0","\"expires_at\":1");
      if(mode==13)change(std::to_string(observed),std::to_string(observed-1));
      if(mode==14)change(std::to_string(observed),std::to_string(observed+1));
      if(mode==15)change(a.tunnel,sibling.tunnel);
      if(mode==16)r.insert(1,"\"extra\":false,");
      if(mode==17)change("\"ok\":false,","");
      if(mode==18)change("\"ok\":false","\"ok\":\"false\"");
      if(mode==19)change("\"process_alive\":false","\"process_alive\":true");
      if(mode==20)change("\"forwarding_verified\":false","\"forwarding_verified\":true");
      if(mode==21)change("not_active","unknown");
      if(mode==22)change("\"lease_deadline_ms\":0","\"lease_deadline_ms\":0.0");
      if(mode==23)mono+=5000;
      if(mode==28)change(a.user,"88888888-8888-4888-8888-888888888888");
      if(mode==29)change(a.sandbox,sibling.sandbox);
      if(mode==30)change(a.node,"88888888-8888-4888-8888-888888888888");
      if(mode==31)change("\"generation\":1","\"generation\":2");
      if(mode==32)change("\"expires_at\":0","\"expires_at\":false");
      if(mode==33)change("\"observed_at_ms\":"+std::to_string(observed),"\"observed_at_ms\":\"100000\"");
      if(mode==34)change("not_active","stale_authority");
      if(mode==35)change("not_active","verified");
      if(mode==36)change("\"process_alive\":false","\"process_alive\":\"false\"");
      if(mode==37)change("\"forwarding_verified\":false","\"forwarding_verified\":0");
      std::copy(r.begin(),r.end(),out);return r.size();
    };
    if(mode==24)denies([&]{(void)backend.diagnose(realm,a,lease.budget);}); // private probe removed A before poll
    const auto freed=frees;backend.close(realm,a);
    if(mode<3 || mode==24) {
      check(frees==freed && backend.realms_.contains(realm),"routine Invalid exact absence must preserve healthy shared B");
      check(backend.realms_.at(realm)->active.contains(sibling.tunnel),"B reservation preserved");
      check(!backend.realms_.at(realm)->active.contains(a.tunnel),"only old A reservation erased");
      if(mode==2)check(backend.realms_.at(realm)->active.size()==2,"replacement A2 preserved");
    } else check(frees==freed+1 && !backend.realms_.contains(realm),"uncertain/fatal cleanup must release realm");
    ffi_reply={};
  }
  std::cout<<"PASS exact backend extracted methods: original budget through queue/new/FFI; post-FFI expiry/identity; equal/regressing/late renew; all-op schema2; 38 exact-close/negative/fatal controls (RAM ABI seams, NOT real Go/native)\n";
}
