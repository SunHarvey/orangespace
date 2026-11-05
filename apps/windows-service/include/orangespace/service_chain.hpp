#pragma once
#include "orangespace/service_policy.hpp"
#include "orangespace/chain_response.hpp"
#include "orangespace/node_session.hpp"
#include <memory>
#include <mutex>
#include <map>
#include <functional>
#include <atomic>
#include <type_traits>
namespace orangespace::service::chain {
namespace nd = node_session::detail;
using node_session::LeaseBudget;
using node_session::LeaseResult;
using node_session::RenewResult;
inline constexpr std::size_t max_payload = 16384;
enum class Op : std::uint8_t { authorize=1, start=2, stop=3, logout=4, status=5, retire=6, diagnose=8 };
inline std::string quote(std::string_view input) {
  std::string out = "\"";
  constexpr char hex[] = "0123456789abcdef";
  for (unsigned char c : input) {
    if (c == '\"' || c == '\\') { out += '\\'; out += static_cast<char>(c); }
    else if (c < 32) { out += "\\u00"; out += hex[c >> 4]; out += hex[c & 15]; }
    else out += static_cast<char>(c);
  }
  return out + '\"';
}
// Wiped owner for transient credential-bearing strings, including error paths.
struct Text {
  std::string value;
  explicit Text(std::string s = {}) : value(std::move(s)) {}
  ~Text() { nd::wipe(value.data(), value.size()); }
  Text(const Text&) = delete;
  Text& operator=(const Text&) = delete;
};
inline void validate_binding_dto(const json::Value& v) {
  nd::object(v,5);
  for(const auto key:{"user_id","sandbox_id","node_id","tunnel_id"})nd::require(nd::uuid(nd::text(nd::field(v,key))));
  (void)nd::integer(nd::field(v,"generation"));
}
struct Request {
  Op op;
  nd::JsonGuard body;
  Request(Op code, std::string_view text) : op(code), body(text) {}
};
inline std::vector<std::uint8_t> request_frame(Op op, std::string_view body) {
  nd::require(body.size() <= max_payload);
  std::vector<std::uint8_t> out(12 + body.size());
  out[0]='O'; out[1]='S'; out[2]='P'; out[3]='2'; out[4]=static_cast<std::uint8_t>(op);
  for(unsigned i=0;i<4;++i) out[8+i]=static_cast<std::uint8_t>(body.size() >> (8*i));
  std::copy(body.begin(), body.end(), out.begin()+12);
  return out;
}
inline Request parse_request(std::span<const std::uint8_t> bytes) {
  nd::require(bytes.size() >= 12 && bytes.size() <= 12+max_payload);
  nd::require(bytes[0]=='O' && bytes[1]=='S' && bytes[2]=='P' && bytes[3]=='2' && bytes[4]>=1 && (bytes[4]<=6 || bytes[4]==8));
  nd::require(bytes[5]==0 && bytes[6]==0 && bytes[7]==0);
  std::uint32_t size=0;
  for(unsigned i=0;i<4;++i) size |= std::uint32_t(bytes[8+i]) << (8*i);
  nd::require(size==bytes.size()-12);
  std::string_view text(reinterpret_cast<const char*>(bytes.data()+12), size);
  nd::require(nd::safe_utf8(text));
  if(bytes[4]==8)nd::exact_wire_integers(text);
  Request request(static_cast<Op>(bytes[4]), text);
  const auto& root=request.body.value;
  const auto* obj=std::get_if<json::Value::Object>(&root.data); nd::require(obj!=nullptr);
  const auto fields=obj->size();
  if(request.op==Op::authorize) nd::require(fields==2);
  else if(request.op==Op::start) nd::require(fields==1 || fields==3);
  else if(request.op==Op::stop) nd::require(fields==3);
  else if(request.op==Op::diagnose) nd::require(fields==2);
  else if(request.op==Op::status) nd::require(fields==1 || fields==2);
  else nd::require(fields==1);
  if (request.op==Op::authorize) {
    const auto& alias=nd::text(nd::field(root,"alias"));
    nd::require(!alias.empty() && alias.size()<=64);
    for(char c:alias) nd::require((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-'||c=='_');
    nd::object(nd::field(root,"envelope"),5);
  } else {
    nd::require(nd::uuid(nd::text(nd::field(root,"auth_id"))));
    if(request.op==Op::diagnose)validate_binding_dto(nd::field(root,"binding"));
    if(request.op==Op::stop || (request.op==Op::start && fields==3) || (request.op==Op::status && fields==2))
      nd::require(nd::uuid(nd::text(nd::field(root,"sandbox_id"))));
    if(request.op==Op::stop || (request.op==Op::start && fields==3))
      (void)nd::integer(nd::field(root,"expected_generation"),0);
  }
  return request;
}
// central_user is supplied only by the independently verified central session.
// Appended for source compatibility with legacy three-field aggregates.
struct Identity { std::string user, node; std::int64_t expiry{}; std::string central_user{}; };
struct Binding {
  std::string user, sandbox, node, tunnel;
  std::uint64_t generation{};
  // Local authority metadata never enters the wire tuple. Equality is identity,
  // not a replacement for independently checking these monotonic fences.
  std::int64_t server_expiry{}, deadline_ms{};
  bool operator==(const Binding& b) const {
    return user==b.user && sandbox==b.sandbox && node==b.node && tunnel==b.tunnel && generation==b.generation;
  }
  bool same_authority(const Binding& b) const {
    return *this==b && server_expiry==b.server_expiry && deadline_ms==b.deadline_ms;
  }
};
inline Binding parse_binding(const json::Value& v) {
  validate_binding_dto(v);
  return {nd::text(nd::field(v,"user_id")),nd::text(nd::field(v,"sandbox_id")),nd::text(nd::field(v,"node_id")),nd::text(nd::field(v,"tunnel_id")),static_cast<std::uint64_t>(nd::integer(nd::field(v,"generation")))};
}
inline std::string binding_json(const Binding& b) {
  return "{\"user_id\":"+quote(b.user)+",\"sandbox_id\":"+quote(b.sandbox)+",\"node_id\":"+quote(b.node)+
    ",\"generation\":"+std::to_string(b.generation)+",\"tunnel_id\":"+quote(b.tunnel)+"}";
}
inline std::string budget_json(const LeaseBudget& b) {
  return "{\"clock\":"+quote(b.clock)+",\"request_started_ms\":"+std::to_string(b.request_started_ms)+
    ",\"remaining_ttl_ms\":"+std::to_string(b.remaining_ttl_ms)+",\"deadline_ms\":"+std::to_string(b.deadline_ms)+"}";
}
inline std::int64_t renewed_deadline(const Binding& old, const RenewResult& renewal, std::int64_t now) {
  renewal.budget.validate(now);
  nd::require(old.deadline_ms>now && old.server_expiry>0 && renewal.expires_at>=old.server_expiry && renewal.expires_at<=nd::max_exact_integer);
  const auto delta=renewal.expires_at-old.server_expiry;
  nd::require(old.deadline_ms<=nd::max_exact_integer && delta<=(nd::max_exact_integer-old.deadline_ms)/1000);
  const auto deadline=(std::min)(renewal.budget.deadline_ms,old.deadline_ms+delta*1000);
  nd::require(deadline>now);
  return deadline;
}
struct Proof { bool process_started{}, tunnel_authenticated{}, forwarding_verified{}; };
struct Session {
  virtual ~Session() = default;
  virtual Identity identity() const = 0;
  virtual void refresh() = 0;
  virtual LeaseResult create(const Binding&) = 0;
  virtual RenewResult renew(const Binding&) = 0;
  virtual void revoke(const Binding&) = 0;
  virtual void logout() = 0;
};
struct Backend {
  virtual ~Backend() = default;
  virtual void release(std::string_view realm) noexcept = 0;
  // Latch backend-wide allocation denial and synchronously kill all local realms.
  virtual void fail_closed() noexcept = 0;
  virtual std::shared_ptr<Session> restore(std::string_view alias, std::string_view envelope) = 0;
  virtual std::string id() = 0; // OS CSPRNG UUID; never caller controlled or persisted.
  virtual void reserve(std::string_view realm,const Binding&) = 0;
  virtual Proof start(std::string_view realm, const Binding&, const LeaseResult& lease) = 0;
  virtual void close(std::string_view realm, const Binding&) noexcept = 0;
  virtual bool alive(std::string_view realm, const Binding&) = 0;
  virtual bool diagnose(std::string_view, const Binding&, const LeaseBudget&) {return false;}
  virtual void renew(std::string_view realm, const Binding&,const RenewResult& renewal) = 0;
};
struct Cursor { std::string sandbox; std::uint64_t generation{}; };
struct Persisted {std::string sandbox,sid;std::uint64_t generation{};std::string central_user{};};
inline std::vector<Persisted> parse_state(std::string_view input) {
  nd::require(input.size()<=1024*1024 && nd::safe_utf8(input));
  const auto root=json::parse(input); nd::object(root,2);
  const auto schema=nd::integer(nd::field(root,"schema"));
  nd::require(schema==1 || schema==2);
  const auto* entries=std::get_if<json::Value::Array>(&nd::field(root,"sandboxes").data);
  nd::require(entries && entries->size()<=4096);
  std::vector<Persisted> result; std::map<std::string,bool> seen;
  for(const auto& item:*entries) {
    nd::object(item,schema==1 ? 3 : 4);
    Persisted entry{nd::text(nd::field(item,"sandbox_id")),nd::text(nd::field(item,"sid")),static_cast<std::uint64_t>(nd::integer(nd::field(item,"generation"),0))};
    if(schema==2)entry.central_user=nd::text(nd::field(item,"central_user"));
    nd::require(entry.central_user.size()<=256 && nd::safe_utf8(entry.central_user));
    nd::require(nd::uuid(entry.sandbox) && pipe_sddl(entry.sid).has_value() && seen.emplace(entry.sandbox,true).second);
    result.push_back(std::move(entry));
  }
  return result;
}
inline std::string state_json(const std::vector<Persisted>& entries) {
  const bool central=std::any_of(entries.begin(),entries.end(),[](const auto& e){return !e.central_user.empty();});
  std::string out=central ? "{\"schema\":2,\"sandboxes\":[" : "{\"schema\":1,\"sandboxes\":[";
  for(const auto& e:entries) {
    if(out.back()!='[')out+=',';
    out+="{\"sandbox_id\":"+quote(e.sandbox)+",\"sid\":"+quote(e.sid)+",\"generation\":"+std::to_string(e.generation);
    if(central)out+=",\"central_user\":"+quote(e.central_user);
    out+='}';
  }
  return out+"]}";
}
class Namespace {
  struct Record { Peer owner; std::uint64_t generation{}; std::string realm; std::optional<Binding> binding, pending; std::string central_user{}; };
  std::mutex mutex;
  std::map<std::string,Record> records;
  std::function<std::vector<Persisted>()> load_;
  std::function<void(const std::vector<Persisted>&)> save_;
  bool loaded_{};
  std::atomic_bool failed{false};
  void ensure() {
    std::lock_guard lock(mutex); nd::require(!failed);
    if(loaded_)return;
    try {
      const auto data=load_();
      // Round-trip validates injected/native loader output too; load never resets
      // missing/corrupt state or imports UI/broker generations.
      for(const auto& e:parse_state(state_json(data))) records.emplace(e.sandbox,Record{Peer{e.sid,0,0},e.generation,{},{},{},e.central_user});
      loaded_=true;
    } catch (...) {failed=true;throw;}
  }
  void commit() { // caller holds namespace mutex; durable BEFORE API create
    nd::require(!failed);
    std::vector<Persisted> state;
    for(const auto& [id,r]:records)state.push_back({id,r.owner.sid,r.generation,r.central_user});
    try {save_(state);} catch (...) {failed=true;throw;}
  }
  static bool owns(const Record& r,const Peer& p) {
    return r.owner.sid==p.sid && (r.realm.empty() || authorize_peer(r.owner,p));
  }
  friend class Engine;
public:
  // In-memory construction is a portable policy-test seam. Production always
  // provides the protected fixed-path loader/atomic writer below.
  Namespace():load_([]{return std::vector<Persisted>{};}),save_([](const auto&){}),loaded_(true){}
  Namespace(std::function<std::vector<Persisted>()> load,std::function<void(const std::vector<Persisted>&)> save):load_(std::move(load)),save_(std::move(save)){}
};
// Namespace is shared across all logons. Only exact OS peers may use a cursor;
// generation is CAS, never a caller-selected resulting generation or identity.
class Engine {
  struct Auth {
    std::string id, alias;
    Identity identity;
    std::shared_ptr<Session> session;
    std::map<std::string, Binding> tunnels;
    std::map<std::string, Binding> unadopted;
    // Failed response rollback owns only cleanup, never work. Reuse the existing
    // tunnel map node without allocation; multiple generations may share a key.
    std::multimap<std::string, Binding> cleanup;
    bool adopted{true}, usable{true}, locally_retired{}, remote_logged_out{};
    std::int64_t last_validation{};
    std::size_t pending{};
  };
  Peer peer_;
  std::shared_ptr<Namespace> namespace_;
  Backend& backend_;
  std::function<std::int64_t()> now_;
  std::function<std::int64_t()> monotonic_;
  std::mutex mutex_;
  bool closed_{};
  // Active grants + cleanup-only receipts share a lifetime budget of 64.
  // No expiry/eviction: failed remote logout still needs its original Session.
  // Scope: this OS-peer Engine only, not durable across service/logon teardown.
  // At capacity deny NEW authorization before superseding any valid grant.
  std::map<std::string,std::shared_ptr<Auth>,std::less<>> auths_;
  std::map<std::string,std::uint64_t> tickets_;
  std::shared_ptr<Auth> get(std::string_view id) {
    auto it=auths_.find(id);
    nd::require(!closed_ && !namespace_->failed && it!=auths_.end() && it->second->adopted && it->second->usable && it->second->identity.expiry>now_());
    return it->second;
  }
  std::shared_ptr<Auth> cleanup_get(std::string_view id) {
    auto it=auths_.find(id);
    nd::require(it!=auths_.end()); // peer already authenticated; expiry/ledger health are irrelevant to cleanup
    return it->second;
  }
  void persist() {
    try { namespace_->commit(); }
    // commit's state-vector preparation can throw before its writer catch.
    // Any failed durable mutation is poisoned; local cleanup remains available.
    catch (...) { namespace_->failed=true; backend_.fail_closed(); throw; }
  }
  bool current(const std::shared_ptr<Auth>& a) {
    auto it=auths_.find(a->id);
    return !closed_ && !namespace_->failed && a->usable && it!=auths_.end() && it->second==a && a->identity.expiry>now_();
  }
  void peer(const Peer& p) { nd::require(authorize_peer(peer_,p)); }
  void detach(const std::shared_ptr<Auth>& a,bool keep_cleanup=true) {
    if(!keep_cleanup)auths_.erase(a->id);
    a->usable=false;
    if(a->locally_retired)return;
    a->locally_retired=true;
    a->unadopted.clear(); // any late transport callback has lost ownership
    std::lock_guard lock(namespace_->mutex);
    for(auto& [_,r]:namespace_->records) if(r.realm==a->id) {
      r.binding.reset(); r.pending.reset(); r.realm.clear();
    }
    for(const auto& [_,b]:a->tunnels) backend_.close(a->id,b);
    backend_.release(a->id);
  }
  // Caller holds the Engine lock. Retire only this exact authority snapshot;
  // transfer its existing node to bounded cleanup without allocating or HTTPS.
  void detach_binding(const std::shared_ptr<Auth>& a,const Binding& b) {
    auto it=a->tunnels.find(b.sandbox);
    if(it==a->tunnels.end() || !it->second.same_authority(b))return;
    std::lock_guard space(namespace_->mutex);
    auto record=namespace_->records.find(b.sandbox);
    if(record!=namespace_->records.end()) {
      auto& r=record->second;
      if(Namespace::owns(r,peer_) && r.realm==a->id && r.generation==b.generation &&
         r.binding && r.binding->same_authority(b))r.binding.reset();
    }
    backend_.close(a->id,b);
    a->unadopted.erase(b.sandbox);
    a->cleanup.insert(a->tunnels.extract(it));
  }
  void remote_cleanup(const std::shared_ptr<Auth>& a) noexcept {
    // A callback may return failed cleanup while retirement is doing HTTPS.
    // Drain owned nodes outside the engine lock, counting in-flight receipts
    // against the same 64-tuple budget. Neither transfer allocates.
    std::multimap<std::string,Binding> receipts;
    std::size_t count;
    {std::lock_guard lock(mutex_);receipts.swap(a->cleanup);count=receipts.size();a->pending+=count;}
    for(auto it=receipts.begin();it!=receipts.end();) {
      try{a->session->revoke(it->second);it=receipts.erase(it);}catch(...){++it;}
    }
    {std::lock_guard lock(mutex_);a->pending-=count;a->cleanup.merge(receipts);}
  }
  void remote_revoke(const std::shared_ptr<Auth>& a) noexcept {
    for(const auto& [_,b]:a->tunnels) try { a->session->revoke(b); } catch (...) {}
    remote_cleanup(a);
  }
public:
  Engine(Peer p, Backend& b, std::function<std::int64_t()> clock, std::shared_ptr<Namespace> space=std::make_shared<Namespace>(), std::function<std::int64_t()> monotonic=nd::monotonic_ms) : peer_(std::move(p)),namespace_(std::move(space)),backend_(b),now_(std::move(clock)),monotonic_(std::move(monotonic)) {}
  ~Engine() {shutdown();}
  void shutdown() {
    std::lock_guard lock(mutex_); closed_=true;
    for(auto& [_,ticket]:tickets_) ++ticket;
    while(!auths_.empty()) {auto a=auths_.begin()->second;detach(a,false);}
  }
  std::string authorize(const Peer& p,std::string alias,std::string_view envelope,bool provisional=false) {
    peer(p); namespace_->ensure();
    std::uint64_t ticket;
    std::vector<std::shared_ptr<Auth>> old;
    {
      std::lock_guard lock(mutex_);
      nd::require(!closed_ && auths_.size()<64 && (tickets_.size()<64 || tickets_.contains(alias)));
      ticket=++tickets_[alias];
      for(auto it=auths_.begin();it!=auths_.end();) {
        if(it->second->usable && it->second->alias==alias) { old.push_back(it->second); ++it; detach(old.back()); }
        else ++it;
      }
    }
    for(const auto& a:old) remote_revoke(a);
    auto session=backend_.restore(alias,envelope);
    auto identity=session->identity();
    nd::require(nd::uuid(identity.user) && nd::uuid(identity.node) && identity.expiry>now_());
    std::lock_guard lock(mutex_);
    nd::require(!closed_ && !namespace_->failed && tickets_[alias]==ticket && auths_.size()<64 && identity.expiry>now_());
    auto id=backend_.id(); nd::require(nd::uuid(id) && !auths_.contains(id));
    auto a=std::make_shared<Auth>(); a->id=id; a->alias=std::move(alias); a->identity=std::move(identity);
    a->adopted=!provisional; a->session=std::move(session); a->last_validation=now_(); auths_.emplace(id,std::move(a));
    return id;
  }
  // New local workspaces only. No generation/owner supplied by the caller;
  // legacy records require a separate explicit migration, never auto-claim.
  Cursor register_sandbox(const Peer& p,std::string_view id,std::string_view localSandboxUUID) {
    peer(p);
    nd::require(nd::uuid(localSandboxUUID) && pipe_sddl(p.sid).has_value());
    std::lock_guard lock(mutex_); const auto a=get(id);
    nd::require(!a->identity.central_user.empty() && a->identity.central_user.size()<=256 && nd::safe_utf8(a->identity.central_user));
    std::lock_guard space(namespace_->mutex);
    auto found=namespace_->records.find(std::string(localSandboxUUID));
    if(found!=namespace_->records.end()) {
      const auto& r=found->second;
      nd::require(r.owner.sid==p.sid && r.central_user==a->identity.central_user);
      return {found->first,r.generation};
    }
    nd::require(namespace_->records.size()<4096);
    // Prepare the returned owner and all map allocations before publication.
    Cursor result{std::string(localSandboxUUID),0};
    Namespace::Record record{p,0,{},{},{},a->identity.central_user};
    namespace_->records.emplace(result.sandbox,std::move(record));
    persist(); // failed persistence permanently poisons work; no fake success
    return result;
  }
  Binding start(const Peer& p,std::string_view id,std::optional<Cursor> prior={},bool provisional=false) {
    peer(p); std::shared_ptr<Auth> a,old; std::optional<Binding> old_binding; Binding b;
    // Prepare ownership before any remote creation. These same map nodes become
    // live ownership or cleanup-only receipts without allocating during unwind.
    std::map<std::string,Binding> prepared, adoption;
    std::optional<Binding> pending;
    static_assert(std::is_nothrow_move_assignable_v<decltype(pending)>);
    {
      std::lock_guard lock(mutex_); a=get(id); nd::require(a->tunnels.size()+a->cleanup.size()+a->pending<64);
      std::lock_guard space(namespace_->mutex);
      std::string sandbox;
      if(prior) {
        auto it=namespace_->records.find(prior->sandbox);
        nd::require(it!=namespace_->records.end() && Namespace::owns(it->second,p) &&
          it->second.central_user==a->identity.central_user && it->second.generation==prior->generation);
        sandbox=prior->sandbox;
      } else {
        // Central workspaces must register their persistent local UUID first.
        nd::require(a->identity.central_user.empty());
        nd::require(namespace_->records.size()<4096);
        sandbox=backend_.id(); nd::require(nd::uuid(sandbox) && !namespace_->records.contains(sandbox));
        namespace_->records.emplace(sandbox,Namespace::Record{p,0,{}, {},{}});
      }
      auto& r=namespace_->records.at(sandbox); nd::require(r.generation<9007199254740991ULL);
      if(r.binding || r.pending) {
        old_binding=r.binding ? r.binding : r.pending;
        if(auto it=auths_.find(r.realm);it!=auths_.end()) old=it->second;
        // Kill before a fallible durable write; retain cleanup ownership if it fails.
      }
      b={a->identity.user,sandbox,a->identity.node,backend_.id(),r.generation+1};
      nd::require(nd::uuid(b.tunnel));
      prepared.emplace(b.sandbox,b);
      if(provisional)adoption.emplace(b.sandbox,b);
      // Finish the fallible pending owner before reserving backend capacity or
      // replacing namespace ownership. Publication below is a nothrow move.
      pending.emplace(b);
      const auto old_realm=r.realm;
      r.generation=b.generation; r.realm=a->id; r.owner=p; r.binding.reset(); r.pending.reset();
      if(old_binding)backend_.close(old_realm,*old_binding);
      persist();
      if(old){old->tunnels.erase(sandbox);old->unadopted.erase(sandbox);}
      backend_.reserve(a->id,b);r.pending=std::move(pending);
      ++a->pending;
    }
    if(old && old_binding) try {old->session->revoke(*old_binding);} catch (...) {}
    try {
      a->session->refresh();
      const auto verified=a->session->identity();
      if(verified.user!=a->identity.user || verified.node!=a->identity.node || verified.central_user!=a->identity.central_user || verified.expiry<=now_()) {
        std::lock_guard lock(mutex_); if(auths_.contains(a->id))detach(a);
        throw std::runtime_error("session identity changed");
      }
      const auto lease=a->session->create(b);
      lease.budget.validate(monotonic_());
      nd::require(lease.expires_at>0 && lease.expires_at<=verified.expiry && lease.expires_at<=a->identity.expiry);
      b.server_expiry=lease.expires_at; b.deadline_ms=lease.budget.deadline_ms;
      {
        std::lock_guard lock(mutex_); nd::require(current(a));
        std::lock_guard space(namespace_->mutex); const auto& r=namespace_->records.at(b.sandbox);
        nd::require(r.generation==b.generation && r.realm==a->id && !r.binding && r.pending==b);
      }
      // Proof may block on real forwarding; never hold the commit/auth locks.
      lease.budget.validate(monotonic_());
      const auto proof=backend_.start(a->id,b,lease);
      lease.budget.validate(monotonic_());
      std::lock_guard lock(mutex_); nd::require(current(a));
      lease.budget.validate(monotonic_());
      std::lock_guard space(namespace_->mutex); auto& r=namespace_->records.at(b.sandbox);
      nd::require(r.generation==b.generation && r.realm==a->id && !r.binding && r.pending==b);
      nd::require(proof.process_started && proof.tunnel_authenticated && proof.forwarding_verified);
      r.pending.reset();r.binding=b;
      prepared.begin()->second.server_expiry=b.server_expiry;
      prepared.begin()->second.deadline_ms=b.deadline_ms;
      a->tunnels.insert(prepared.extract(prepared.begin()));
      if(provisional)a->unadopted.insert(adoption.extract(adoption.begin()));
      --a->pending; return b;
    } catch (...) {
      {
        std::lock_guard lock(mutex_);
        std::lock_guard space(namespace_->mutex);
        auto it=namespace_->records.find(b.sandbox);
        if(it!=namespace_->records.end() && it->second.realm==a->id) {
          if(it->second.pending==b)it->second.pending.reset();
          if(it->second.binding==b)it->second.binding.reset();
        }
      }
      backend_.close(a->id,b);
      bool revoked=false;try {a->session->revoke(b);revoked=true;} catch (...) {}
      {
        std::lock_guard lock(mutex_); --a->pending;
        if(!revoked && !prepared.empty())a->cleanup.insert(prepared.extract(prepared.begin()));
      }
      throw;
    }
  }
  // Transport-only prepare/adopt boundary. Direct policy APIs remain compatible.
  Response authorize_response(const Peer& p,std::string alias,std::string_view envelope) {
    const auto id=authorize(p,std::move(alias),envelope,true);
    std::shared_ptr<Auth> a;
    // From insertion until Response owns completion, every fallible step is
    // guarded. Lookup uses the already-owned key: rollback needs no allocation.
    try {
      {std::lock_guard lock(mutex_);auto it=auths_.find(id);nd::require(it!=auths_.end());a=it->second;}
      Response response({},[this,a](bool ack) {
        std::lock_guard lock(mutex_);
        auto it=auths_.find(a->id);
        if(it==auths_.end() || it->second!=a || a->adopted)return;
        if(ack && current(a))a->adopted=true;
        else detach(a,false); // undisclosed/unadopted auth needs no receipt
      });
      response.body="{\"ok\":true,\"auth_id\":"+quote(a->id)+",\"user_id\":"+quote(a->identity.user)+
        ",\"node_id\":"+quote(a->identity.node)+",\"browser_allowed\":false,\"tunnels\":[]}";
      return response;
    }catch(...) {
      std::lock_guard lock(mutex_);
      auto it=auths_.find(id);if(it!=auths_.end() && it->second==a && !a->adopted)detach(a,false);
      throw;
    }
  }
private:
  void complete_start(const std::shared_ptr<Auth>& a,const Binding& b,bool ack) {
    // Own the already-allocated node across HTTPS. Leaving a rollback tuple in
    // tunnels would both obstruct a replacement and risk exposing stale proof.
    std::map<std::string,Binding>::node_type receipt;
    {
      std::lock_guard lock(mutex_);
      auto pending=a->unadopted.find(b.sandbox);
      if(pending==a->unadopted.end() || pending->second!=b)return;
      std::lock_guard space(namespace_->mutex);
      auto found=namespace_->records.find(b.sandbox);
      const bool exact=found!=namespace_->records.end() && found->second.realm==a->id && found->second.binding==b;
      a->unadopted.erase(pending);
      if(ack && current(a) && exact && b.deadline_ms>monotonic_())return;
      if(auto it=a->tunnels.find(b.sandbox);it!=a->tunnels.end() && it->second==b)receipt=a->tunnels.extract(it);
      if(!receipt.empty())++a->pending;
      if(exact)found->second.binding.reset(); // never restore a previous generation
      backend_.close(a->id,b);
    }
    bool revoked=false;
    try{a->session->revoke(b);revoked=true;}catch(...){}
    std::lock_guard lock(mutex_);
    if(!receipt.empty()) {
      --a->pending;
      // Preserve exact cleanup after durable poison, remote failure or OOM.
      // Node insertion cannot allocate and cannot overwrite a newer generation.
      if(!revoked)a->cleanup.insert(std::move(receipt));
    }
  }
public:
  Response start_response(const Peer& p,std::string_view id,std::optional<Cursor> prior={}) {
    std::shared_ptr<Auth> a;
    {std::lock_guard lock(mutex_);peer(p);a=get(id);}
    const auto b=start(p,id,prior,true);
    try {
      Response response({},[this,a,b](bool ack){complete_start(a,b,ack);});
      response.body="{\"ok\":true,\"auth_id\":"+quote(a->id)+",\"binding\":"+binding_json(b)+
        ",\"process_started\":true,\"tunnel_authenticated\":true,\"forwarding_verified\":true,\"browser_allowed\":false}";
      return response;
    }catch(...){complete_start(a,b,false);throw;}
  }
  Cursor stop(const Peer& p,std::string_view id,const Cursor& cursor) {
    peer(p); std::shared_ptr<Auth> a; Binding b; Cursor next;
    {
      std::lock_guard lock(mutex_); a=get(id); std::lock_guard space(namespace_->mutex);
      auto found=namespace_->records.find(cursor.sandbox);
      nd::require(found!=namespace_->records.end()); auto& r=found->second;
      nd::require(Namespace::owns(r,p) && r.realm==a->id && r.generation==cursor.generation && (r.binding || r.pending));
      nd::require(r.generation<9007199254740991ULL);
      // Prevalidation/owner preparation may fail without authenticating a
      // mutation: retain the exact live owner and its unchanged retry cursor.
      b=r.binding ? *r.binding : *r.pending;
      next={cursor.sandbox,r.generation+1};
      // From here to local close/authority removal there are no allocations.
      // In particular, never clear the only owner before copying next.sandbox.
      r.binding.reset();r.pending.reset(); ++r.generation;
      backend_.close(a->id,b);
      persist();
      a->tunnels.erase(cursor.sandbox);a->unadopted.erase(cursor.sandbox);
    }
    // Local stop/CAS committed even if the remote revoke fails; lease reaper is
    // the remote safety bound. Status exposes the new service cursor for recovery.
    try { a->session->revoke(b); } catch (...) {}
    return next;
  }
  void retire(const Peer& p,std::string_view id) {
    peer(p); std::shared_ptr<Auth> a;
    { std::lock_guard lock(mutex_); a=cleanup_get(id); if(a->usable)++tickets_.find(a->alias)->second; detach(a); }
    remote_revoke(a); // deliberately never Session::logout
  }
  void logout(const Peer& p,std::string_view id) {
    peer(p); std::shared_ptr<Auth> a;
    { std::lock_guard lock(mutex_); a=cleanup_get(id); if(a->usable)++tickets_.find(a->alias)->second; detach(a); }
    // Local grant and processes are gone BEFORE any fallible remote operation.
    // Late start/ACK rollback may return cleanup after a successful logout.
    // Retain exact receipt retry even though the session logout is idempotent.
    {std::lock_guard lock(mutex_);if(a->remote_logged_out && a->cleanup.empty())return;}
    remote_revoke(a);
    {std::lock_guard lock(mutex_);if(a->remote_logged_out)return;}
    a->session->logout();
    {std::lock_guard lock(mutex_);a->remote_logged_out=true;}
  }
  Cursor cursor(const Peer& p,std::string_view id,std::string_view sandbox) {
    peer(p); std::lock_guard lock(mutex_); const auto a=get(id); std::lock_guard space(namespace_->mutex);
    auto it=namespace_->records.find(std::string(sandbox));
    nd::require(it!=namespace_->records.end() && it->second.owner.sid==p.sid && it->second.central_user==a->identity.central_user);
    return {it->first,it->second.generation};
  }
  // Read-only, one-shot evidence. Never enters status/poll cleanup or caches proof.
  std::string diagnose(const Peer& p,std::string_view id,const Binding& requested) {
    peer(p); std::shared_ptr<Auth> a; Binding b; LeaseBudget budget;
    auto matches=[&] {
      if(!current(a) || !a->adopted)return false;
      const auto it=a->tunnels.find(b.sandbox);
      if(it==a->tunnels.end() || !it->second.same_authority(b) || a->unadopted.contains(b.sandbox))return false;
      const auto r=namespace_->records.find(b.sandbox);
      return r!=namespace_->records.end() && Namespace::owns(r->second,p) && r->second.realm==a->id &&
        r->second.generation==b.generation && r->second.binding && r->second.binding->same_authority(b) &&
        b.deadline_ms>monotonic_() && b.server_expiry>now_();
    };
    {
      std::lock_guard lock(mutex_);a=get(id);
      const auto it=a->tunnels.find(requested.sandbox);
      nd::require(it!=a->tunnels.end() && it->second==requested);b=it->second;
      std::lock_guard space(namespace_->mutex);nd::require(matches());
      const auto start=monotonic_();const auto ttl=(std::min)(b.deadline_ms-start,std::int64_t{5000});
      budget={std::string(nd::lease_clock),start,ttl,start+ttl};budget.validate(start);
    }
    bool fresh=false;
    try {budget.validate(monotonic_());fresh=backend_.diagnose(a->id,b,budget);}catch(...){}
    std::lock_guard lock(mutex_);std::lock_guard space(namespace_->mutex);
    const auto observed=monotonic_();bool timely=false;try{budget.validate(observed);timely=true;}catch(...){}
    const bool authority=matches();fresh=fresh&&timely&&authority;
    std::string reply="{\"ok\":true,\"browser_allowed\":false,\"binding\":"+binding_json(b)+
      ",\"server_expiry\":"+std::to_string(b.server_expiry)+",\"deadline_ms\":"+std::to_string(b.deadline_ms)+
      ",\"clock\":"+quote(nd::lease_clock)+",\"observed_at_ms\":"+std::to_string(observed)+
      ",\"fresh_proof\":"+(fresh?"true":"false")+",\"reason\":"+quote(!authority?"stale_authority":!timely?"probe_deadline":fresh?"verified":"probe_unavailable")+"}";
    // Serialization itself must not publish a proof after its short budget.
    if(fresh) {budget.validate(monotonic_());nd::require(matches());}
    return reply;
  }
  std::string status(const Peer& p,std::string_view id) {
    peer(p); std::shared_ptr<Auth> a; std::vector<Binding> snapshot;
    bool removed=false;
    {
      std::lock_guard lock(mutex_); a=get(id);
      for(const auto& [sandbox,b]:a->tunnels) if(!a->unadopted.contains(sandbox)) snapshot.push_back(b);
    }
    // Kernel/root poll is local and must not wait for HTTPS validation/renewal.
    for(auto b:snapshot) {
      for(;;) {
        bool alive=false; try {alive=b.deadline_ms>monotonic_() && backend_.alive(a->id,b) && b.deadline_ms>monotonic_();}catch(...){}
        std::lock_guard lock(mutex_);
        auto it=a->tunnels.find(b.sandbox);
        if(!current(a) || it==a->tunnels.end() || it->second!=b)break;
        // Tuple equality deliberately excludes lease timing. A completion about
        // old authority cannot kill a renewal, nor certify its current root.
        if(!it->second.same_authority(b)) {b=it->second;continue;}
        if(!alive) {detach_binding(a,b);removed=true;}
        break;
      }
    }
    std::lock_guard lock(mutex_); nd::require(current(a));
    std::string tunnels="[";
    for(const auto& b:snapshot) {
      const auto it=a->tunnels.find(b.sandbox);
      if(it==a->tunnels.end() || it->second!=b || a->unadopted.contains(b.sandbox))continue;
      if(it->second.deadline_ms<=monotonic_()) {detach_binding(a,it->second);removed=true;continue;}
      if(tunnels.size()>1) tunnels+=',';
      tunnels+="{\"binding\":"+binding_json(b)+",\"process_started\":true,\"tunnel_authenticated\":true,\"forwarding_verified\":true}";
    }
    // No positive certification when this observation lost its final helper.
    // The authorization itself survives and can create a fresh generation.
    nd::require(!removed || tunnels.size()>1);
    return "{\"ok\":true,\"auth_id\":"+quote(a->id)+",\"user_id\":"+quote(a->identity.user)+
      ",\"node_id\":"+quote(a->identity.node)+",\"browser_allowed\":false,\"tunnels\":"+tunnels+"]}";
  }
  // Independent of Session's HTTPS mutex; invoked by its own local watchdog.
  void poll() {
    std::vector<std::shared_ptr<Auth>> list;
    {std::lock_guard lock(mutex_);for(const auto& [_,a]:auths_)list.push_back(a);}
    for(const auto& a:list) {
      {std::lock_guard lock(mutex_);if(!current(a)){detach(a,true);continue;}if(!a->adopted)continue;}
      try{(void)status(peer_,a->id);}catch(...){}
    }
  }
  void tick() {
    poll();
    std::vector<std::shared_ptr<Auth>> list;
    { std::lock_guard lock(mutex_); for(const auto& [_,a]:auths_) list.push_back(a); }
    for(const auto& a:list) {
      std::vector<Binding> tunnels;
      bool invalid=false;
      {
        std::lock_guard lock(mutex_);
        if(!current(a)) { detach(a,true); invalid=true; }
        else for(const auto& [sandbox,b]:a->tunnels) if(a->adopted && !a->unadopted.contains(sandbox)) tunnels.push_back(b);
      }
      try {
        if(invalid) throw std::runtime_error("expired");
        a->session->refresh();
        const auto identity=a->session->identity();
        nd::require(identity.user==a->identity.user && identity.node==a->identity.node && identity.central_user==a->identity.central_user && identity.expiry>now_());
        for(const auto& b:tunnels) {
          try {
            nd::require(b.deadline_ms>monotonic_());
            const auto alive=backend_.alive(a->id,b);
            nd::require(alive && b.deadline_ms>monotonic_());
            const auto renewal=a->session->renew(b);
            {
              std::lock_guard lock(mutex_);
              auto it=a->tunnels.find(b.sandbox);
              if(!current(a) || it==a->tunnels.end() || !it->second.same_authority(b)) continue;
              nd::require(renewal.expires_at<=identity.expiry && renewal.expires_at<=a->identity.expiry);
              (void)renewed_deadline(it->second,renewal,monotonic_());
            }
            backend_.renew(a->id,b,renewal);
            std::lock_guard lock(mutex_);
            auto it=a->tunnels.find(b.sandbox);
            if(!current(a) || it==a->tunnels.end() || !it->second.same_authority(b)) continue;
            const auto deadline=renewed_deadline(it->second,renewal,monotonic_());
            it->second.server_expiry=renewal.expires_at;it->second.deadline_ms=deadline;
            std::lock_guard space(namespace_->mutex);
            auto record=namespace_->records.find(b.sandbox);
            if(record!=namespace_->records.end() && record->second.realm==a->id && record->second.binding==b) {
              record->second.binding->server_expiry=renewal.expires_at;
              record->second.binding->deadline_ms=deadline;
            }
          } catch (...) {
            {
              std::lock_guard lock(mutex_);
              auto it=a->tunnels.find(b.sandbox);
              if(!current(a) || it==a->tunnels.end() || it->second!=b) continue;
              if(it->second.same_authority(b)) {
                // Apply the negative under the same lock as the authority
                // comparison; a renewal must not slip between check and kill.
                detach_binding(a,b);continue;
              }
            }
            // A renewed same-tuple authority needs a fresh root/deadline poll,
            // not the old completion's negative or cached positive proof.
            try{(void)status(peer_,a->id);}catch(...){}
          }
        }
        std::lock_guard lock(mutex_);
        if(current(a)) a->last_validation=now_();
      } catch (...) {
        { std::lock_guard lock(mutex_); if(auths_.contains(a->id)) detach(a,true); }
        remote_revoke(a);
      }
      remote_cleanup(a);
    }
  }
};
}
