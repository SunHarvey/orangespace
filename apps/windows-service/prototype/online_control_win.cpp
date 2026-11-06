#include "online_control_win.hpp"
#include "orangespace/chain_windows.hpp"
#include "orangespace/platform_protocol.hpp"
#include "orangespace/pipe_server.hpp"
#include <thread>
#include <mutex>
#ifndef ORANGESPACE_PROTOTYPE_NODE_UUID
#error Prototype requires the trusted build-selected SG node UUID
#endif
// CONTROL_POLICY_BEGIN
namespace orangespace::service::win::control_detail {
namespace ch=orangespace::service::chain;
namespace nd=ch::nd;
inline ch::Binding full_binding(std::string_view diagnostic,const ch::Binding& expected,
    std::int64_t now,std::int64_t wall) {
  nd::exact_wire_integers(diagnostic);nd::JsonGuard doc(diagnostic);const auto& r=doc.value;
  nd::object(r,9);
  nd::require(std::get<bool>(nd::field(r,"ok").data) && !std::get<bool>(nd::field(r,"browser_allowed").data));
  auto b=ch::parse_binding(nd::field(r,"binding"));nd::require(b==expected);
  b.server_expiry=nd::integer(nd::field(r,"server_expiry"));
  b.deadline_ms=nd::integer(nd::field(r,"deadline_ms"));
  const auto observed=nd::integer(nd::field(r,"observed_at_ms"),0);
  nd::require(nd::text(nd::field(r,"clock"))==nd::lease_clock &&
      b.server_expiry>wall && b.deadline_ms>now && observed<=now && now-observed<3000 &&
      std::get<bool>(nd::field(r,"fresh_proof").data) && nd::text(nd::field(r,"reason"))=="verified");
  return b;
}
inline void live_status(std::string_view status,std::string_view auth,const ch::Binding& expected) {
  nd::exact_wire_integers(status);nd::JsonGuard doc(status);const auto& r=doc.value;
  nd::object(r,6);
  nd::require(std::get<bool>(nd::field(r,"ok").data) && !std::get<bool>(nd::field(r,"browser_allowed").data));
  nd::require(nd::text(nd::field(r,"auth_id"))==auth && nd::text(nd::field(r,"user_id"))==expected.user &&
      nd::text(nd::field(r,"node_id"))==expected.node);
  const auto& tunnels=std::get<orangespace::json::Value::Array>(nd::field(r,"tunnels").data);
  nd::require(tunnels.size()==1);const auto& t=tunnels.front();nd::object(t,4);
  nd::require(ch::parse_binding(nd::field(t,"binding"))==expected);
  for(const auto key:{"process_started","tunnel_authenticated","forwarding_verified"})
    nd::require(std::get<bool>(nd::field(t,key).data));
}
}
// CONTROL_POLICY_END
namespace orangespace::service::win {
namespace nd=chain::nd;
namespace {
constexpr wchar_t control_prefix[]=L"\\\\.\\pipe\\OrangeSpace.SinglePrototype.SG.v25.Control.v1.session.";
// serve_owned_connection also supports legacy OSP1: exclude it before that
// helper's decoder, without consuming bytes or bypassing its OS peer check.
bool osp3_wait(HANDLE pipe,HANDLE stop) {
  const auto deadline=GetTickCount64()+1500;
  while(WaitForSingleObject(stop,0)==WAIT_TIMEOUT && GetTickCount64()<deadline) {
    std::array<BYTE,4> head{};DWORD copied{},available{};
    if(!PeekNamedPipe(pipe,head.data(),DWORD(head.size()),&copied,&available,nullptr))return false;
    if(copied==head.size())return head[0]=='O'&&head[1]=='S'&&head[2]=='P'&&head[3]=='3';
    if(WaitForSingleObject(stop,10)!=WAIT_TIMEOUT)return false;
  }
  return false;
}
}
struct PrototypeControl::Impl {
  struct Prepared {std::string auth;chain::Binding binding;chain::Cursor cursor;};
  struct Published {std::string auth;std::shared_ptr<const LocalChannel> channel;};
  const Peer peer;
  HANDLE service_stop; // parent owns; outlives stopAndJoin
  Handle stop,ready,pipe;
  std::unique_ptr<PrototypePlatformBackend> backend;
  chain::Engine engine;
  std::mutex mutex;
  std::shared_ptr<const Published> published;
  std::jthread listener,poller,maintenance;
  std::mutex lifecycle;
  std::shared_ptr<const Published> last;
  prototype::BrowserFrame browser, pending_command;
  std::string package_sid,profile_name;
  DWORD process_id{};std::uint64_t process_birth{},sequence{};
  bool desktop{},close_requested{},launch_reserved{},started{};
  chain::Response browser_request(const json::Value& r) {
    const auto auth=nd::text(nd::field(r,"auth_id"));auto binding=chain::parse_binding(nd::field(r,"binding"));
    const auto command=nd::integer(nd::field(r,"command"),0);const auto url=nd::text(nd::field(r,"url"));
    std::lock_guard serial(lifecycle);
    auto p=snapshot();std::shared_ptr<const Published> owner;bool closed_status_snapshot{};
    {
      std::lock_guard lock(mutex);owner=p?p:last;
      nd::require(owner&&owner->auth==auth&&owner->channel->binding==binding);
      // finish_run retains only a closed receipt. Reading that exact receipt
      // grants no work and must remain possible after Engine work authority expires.
      closed_status_snapshot=!p&&!published&&last.get()==owner.get()&&
          browser.phase==0&&process_id==0&&command==0;
    }
    if(!closed_status_snapshot){(void)engine.status(peer,auth);if(p)check(*p);}
    std::lock_guard lock(mutex);
    if(closed_status_snapshot)nd::require(!p&&!published&&last.get()==owner.get()&&
        owner->auth==auth&&owner->channel->binding==binding&&
        browser.phase==0&&process_id==0&&command==0);
    // The initial zeroed frame of a published launch is not a closed receipt.
    // Only finish_run can confirm an exact binding has no remaining browser.
    if(command==0 && p)nd::require(process_id!=0);
    if(command==6){nd::require(p&&browser.phase==1);desktop=true;browser.phase=2;}
    else if(command){
      nd::require(p&&pending_command.command==0);
      if(command==5)close_requested=true;
      else nd::require(browser.phase==3);
      pending_command=prototype::BrowserFrame{};pending_command.command=static_cast<std::uint32_t>(command);
      if(command==1){nd::require(prototype::OnlineNavigation(url));pending_command.url_size=static_cast<std::uint32_t>(url.size());std::memcpy(pending_command.url.data(),url.data(),url.size());}
    }
    auto q=[](std::string_view s){return chain::quote(s);};auto b=[](bool v){return v?"true":"false";};
    std::string out="{\"schema\":1,\"ok\":true,\"browser\":{\"phase\":"+std::to_string(browser.phase)+
      ",\"sandbox\":"+q(binding.sandbox)+",\"node\":"+q(binding.node)+",\"package_sid\":"+q(package_sid)+",\"profile_name\":"+q(profile_name)+
      ",\"url\":"+q({browser.url.data(),browser.url_size})+",\"title\":"+q({browser.title.data(),browser.title_size})+",\"error\":\"\",\"generation\":"+std::to_string(binding.generation)+
      ",\"process_birth\":"+std::to_string(process_birth)+",\"process_id\":"+std::to_string(process_id)+",\"loading\":"+b(browser.loading)+",\"can_go_back\":"+b(browser.back)+",\"can_go_forward\":"+b(browser.forward)+"}}";
    return chain::Response(std::move(out));
  }
  Impl(Peer p,HANDLE svc,std::string_view expected)
      :peer(std::move(p)),service_stop(svc),stop(CreateEventW(nullptr,TRUE,FALSE,nullptr)),
       ready(CreateEventW(nullptr,TRUE,FALSE,nullptr)),backend(make_prototype_platform_chain_backend()),
       engine(peer,*backend,chain_now,make_prototype_chain_namespace()) {
    nd::require(stop && ready && service_stop && peer.session && peer.logon &&
      pipe_sddl(peer.sid).has_value() && nd::uuid(expected) && expected==ORANGESPACE_PROTOTYPE_NODE_UUID);
    HANDLE raw{};
    if(OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&raw)) {CloseHandle(raw);nd::require(false);}
    nd::require(GetLastError()==ERROR_NO_TOKEN && current_peer().sid=="S-1-5-18");
  }
  std::shared_ptr<const Published> snapshot() {std::lock_guard lock(mutex);return published;}
  void revoke() noexcept {SetEvent(service_stop);SetEvent(stop.get());}
  void check(const Published& p) {
    nd::require(WaitForSingleObject(stop.get(),0)==WAIT_TIMEOUT && WaitForSingleObject(service_stop,0)==WAIT_TIMEOUT);
    // Engine.status independently polls the retained helper root and latest
    // authority under Engine's existing renewal-snapshot race fences.
    control_detail::live_status(engine.status(peer,p.auth),p.auth,p.channel->binding);
    nd::require(WaitForSingleObject(stop.get(),0)==WAIT_TIMEOUT && WaitForSingleObject(service_stop,0)==WAIT_TIMEOUT);
  }
  void rollback(const Prepared& p) noexcept {
    // Exact runtime close remains allocation-free if metadata/secret/shared
    // owner preparation failed after the frontend ACK committed Engine.start.
    backend->close(p.auth,p.binding);
    try{(void)engine.stop(peer,p.auth,p.cursor);}catch(...){
      try{engine.retire(peer,p.auth);}catch(...){}
    }
  }
  void accept() noexcept {
    try {
      const auto name=std::wstring(control_prefix)+std::to_wstring(peer.session);
      while(WaitForSingleObject(stop.get(),0)==WAIT_TIMEOUT) {
        if(!connect_pipe(pipe.get(),stop.get()))break;
        auto next=create_pipe(name,peer,false);
        std::optional<Prepared> prepared;
        bool delivered=false;
        if(osp3_wait(pipe.get(),stop.get())) delivered=serve_owned_connection(pipe.get(),peer,stop.get(),[&](auto bytes) {
          auto request=platform::parse_request(bytes);const auto& r=request.body.value;
          if(request.op==9)return browser_request(r);
          if(request.op==1) {
            nd::require(platform::parse_node(nd::field(r,"node")).node_id==ORANGESPACE_PROTOTYPE_NODE_UUID);
          }
          if(request.op==2 || request.op==7){std::lock_guard lock(mutex);nd::require(!launch_reserved&&!published); }
          // All capture/tuple allocations precede chain::Response.write. Its original
          // completion remains untouched, owning rollback on disconnect/ACK loss.
          auto response=dispatch_platform_chain(engine,peer,bytes);
          if(request.op==2) {
            Prepared p{nd::text(nd::field(r,"auth_id")),{}, {nd::text(nd::field(r,"sandbox_id")),0}};
            nd::JsonGuard result(response.body);
            nd::require(std::get<bool>(nd::field(result.value,"ok").data));
            p.binding=chain::parse_binding(nd::field(result.value,"binding"));
            nd::require(p.binding.node==ORANGESPACE_PROTOTYPE_NODE_UUID && p.binding.sandbox==p.cursor.sandbox);
            p.cursor.generation=p.binding.generation;
            prepared.emplace(std::move(p));{std::lock_guard lock(mutex);launch_reserved=true;}
          }
          return response;
        });
        DisconnectNamedPipe(pipe.get());pipe=std::move(next);
        if(!delivered&&prepared){std::lock_guard lock(mutex);launch_reserved=false;}
        if (delivered && prepared) {
          try {
            // No tick before this once-only handoff. The runtime retains the
            // original <=30s grant and its <3s proof fence; never re-anchor it.
            auto diagnostic=engine.diagnose(peer,prepared->auth,prepared->binding);
            const auto full=control_detail::full_binding(diagnostic,prepared->binding,nd::monotonic_ms(),chain_now());
            auto owner=std::make_shared<const LocalChannel>(backend->take_local_channel(prepared->auth,full));
            auto state=std::make_shared<const Published>(Published{prepared->auth,std::move(owner)});
            check(*state);
            {std::lock_guard lock(mutex);published=std::move(state);browser=prototype::BrowserFrame{};pending_command=prototype::BrowserFrame{};package_sid.clear();profile_name.clear();process_id=0;process_birth=0;desktop=false;close_requested=false;}
            SetEvent(ready.get()); // wakes wait_channel and delays first tick by 3s
          }catch(...) {rollback(*prepared);std::lock_guard lock(mutex);launch_reserved=false;}
        }
      }
      if(WaitForSingleObject(stop.get(),0)!=WAIT_OBJECT_0)revoke();
    } catch(...) {revoke();}
  }
  void launch() {
    nd::require(!started);started=true;
    const auto name=std::wstring(control_prefix)+std::to_wstring(peer.session);
    pipe=create_pipe(name,peer); // protected DACL, first instance, local-only
    try {
      poller=std::jthread([this] {
        while(WaitForSingleObject(stop.get(),200)==WAIT_TIMEOUT) {
          if(WaitForSingleObject(service_stop,0)!=WAIT_TIMEOUT){SetEvent(stop.get());break;}
          try {std::lock_guard serial(lifecycle);engine.poll();if(auto p=snapshot())check(*p);}catch(...) {revoke();break;}
        }
      });
      maintenance=std::jthread([this] {
        HANDLE waits[]{stop.get(),ready.get()};
        if(WaitForMultipleObjects(2,waits,FALSE,INFINITE)!=WAIT_OBJECT_0+1)return;
        while(WaitForSingleObject(stop.get(),3000)==WAIT_TIMEOUT) {
          try{
            // Engine fences slow renewal against the exact authority and runtime
            // owner. Keep HTTPS out of the lock needed by desktop ACK/status.
            engine.tick();
            std::lock_guard serial(lifecycle);
            if(auto p=snapshot())check(*p);
          }catch(...){revoke();break;}
        }
      });
      listener=std::jthread([this]{accept();});
    } catch(...) {join();throw;}
  }
  void join() noexcept {
    SetEvent(stop.get());
    // Invalidate/cancel first. No Engine/backend/pins/channel destruction until
    // every HTTP, poll and pipe worker has returned and been joined.
    try{engine.shutdown();}catch(...){}
    for(auto* t:{&listener,&poller,&maintenance})if(t->joinable())t->join();
    pipe=Handle();
  }
  ~Impl(){join();}
};
PrototypeControl::PrototypeControl(Peer peer,HANDLE stop,std::string_view expected)
    :impl_(std::make_unique<Impl>(std::move(peer),stop,expected)) {}
PrototypeControl::~PrototypeControl()=default;
void PrototypeControl::start(){impl_->launch();}
std::shared_ptr<const LocalChannel> PrototypeControl::wait_channel(DWORD timeout) {
  HANDLE waits[]{impl_->service_stop,impl_->stop.get(),impl_->ready.get()};
  if(WaitForMultipleObjects(3,waits,FALSE,timeout)!=WAIT_OBJECT_0+2)return {};
  auto p=impl_->snapshot();if(!p)return {};
  try {impl_->check(*p);}catch(...){impl_->revoke();throw;}
  return p->channel;
}
void PrototypeControl::verify_live(const LocalChannel& channel) {
  auto p=impl_->snapshot();
  // A foreign or stale caller owner is not a service-wide revocation request.
  nd::require(p && p->channel.get()==&channel && p->channel->binding==channel.binding);
  try{impl_->check(*p);}catch(...){impl_->revoke();throw;}
}
std::int64_t PrototypeControl::fresh_forwarding_proof(const LocalChannel& channel) {
  const auto p=impl_->snapshot();
  nd::require(p && p->channel.get()==&channel && p->channel->binding==channel.binding);
  const auto expected=channel.binding;
  // Only short local fences hold the publication lock. Never serialize a
  // network probe behind publication, lifecycle or the Root admission gate.
  const auto retained=[&](std::int64_t now) {
    nd::require(impl_->published.get()==p.get() && p->channel.get()==&channel &&
        channel.binding==expected && p->channel->binding==expected);
    nd::require(WaitForSingleObject(impl_->stop.get(),0)==WAIT_TIMEOUT &&
        WaitForSingleObject(impl_->service_stop,0)==WAIT_TIMEOUT);
    channel.budget.validate(now);
  };
  {std::lock_guard lock(impl_->mutex);retained(nd::monotonic_ms());}
  impl_->check(*p);
  // diagnose performs a new positive forwarding probe. Its start is a
  // conservative lower bound; stamping completion would hide a slow probe.
  const auto probe_started=nd::monotonic_ms();
  {std::lock_guard lock(impl_->mutex);retained(probe_started);}
  auto diagnostic=impl_->engine.diagnose(impl_->peer,p->auth,channel.binding);
  const auto full=control_detail::full_binding(diagnostic,expected,nd::monotonic_ms(),chain_now());
  impl_->check(*p);
  {
    std::lock_guard lock(impl_->mutex);
    const auto now=nd::monotonic_ms();retained(now);
    nd::require(probe_started>=channel.budget.request_started_ms && now>=probe_started &&
        now-probe_started<3000 && full.deadline_ms>now && full.server_expiry>chain_now());
  }
  return probe_started;
}
void PrototypeControl::publish_root(const LocalChannel& channel,std::string package,std::string profile,DWORD pid,std::uint64_t birth) {
 verify_live(channel);std::lock_guard lock(impl_->mutex);
 nd::require(pid&&birth&&!package.empty()&&!profile.empty());impl_->package_sid=std::move(package);impl_->profile_name=std::move(profile);impl_->process_id=pid;impl_->process_birth=birth;
 impl_->browser=prototype::BrowserFrame{};impl_->browser.phase=1;impl_->desktop=false;impl_->sequence=0;
}
bool PrototypeControl::desktop_configured(){std::lock_guard lock(impl_->mutex);return impl_->desktop;}
bool PrototypeControl::closing(){std::lock_guard lock(impl_->mutex);return impl_->close_requested;}
prototype::BrowserFrame PrototypeControl::next_command(){std::lock_guard lock(impl_->mutex);auto f=impl_->pending_command;impl_->pending_command=prototype::BrowserFrame{};f.sequence=++impl_->sequence;return f;}
void PrototypeControl::observe(const prototype::BrowserFrame& frame){nd::require(prototype::ValidBrowserFrame(frame)&&frame.command==0&&nd::safe_utf8({frame.url.data(),frame.url_size})&&nd::safe_utf8({frame.title.data(),frame.title_size}));std::lock_guard lock(impl_->mutex);nd::require(frame.sequence==impl_->sequence);impl_->browser=frame;}
void PrototypeControl::finish_run(const LocalChannel& channel){
 std::lock_guard serial(impl_->lifecycle);auto p=impl_->snapshot();nd::require(p&&p->channel.get()==&channel);
 {std::lock_guard lock(impl_->mutex);impl_->last=p;impl_->published.reset();impl_->browser.phase=0;impl_->process_id=0;impl_->process_birth=0;ResetEvent(impl_->ready.get());}
 (void)impl_->engine.stop(impl_->peer,p->auth,{channel.binding.sandbox,channel.binding.generation});
 {std::lock_guard lock(impl_->mutex);impl_->launch_reserved=false;}
}
void PrototypeControl::stopAndJoin() noexcept {impl_->join();}
}
