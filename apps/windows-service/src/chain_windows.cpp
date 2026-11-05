#include "orangespace/chain_windows.hpp"
#include "orangespace/platform_protocol.hpp"
#include "orangespace/prototype_namespace.hpp"
#include "orangespace/windows_service.hpp"
#include <aclapi.h>
#include <sddl.h>
#include <bcrypt.h>
#include <chrono>
#include <set>
#ifdef ORANGESPACE_NATIVE_ACCEPTANCE_TRACE
#include <cstdio>
#endif
#ifndef ORANGESPACE_HELPER_SHA256
#error Fixed helper SHA256 required
#endif
#include "orangespace_runtime.h"
namespace orangespace::service::win {
namespace {
namespace detail = node_session::detail;
using namespace chain;
void checked(BOOL ok, const char*) { if(!ok) throw std::runtime_error("protected runtime rejected"); }
struct LocalClose { void operator()(void* p) const noexcept { if(p) LocalFree(p); } };
using Local=std::unique_ptr<void,LocalClose>;
bool privileged(PSID sid, bool ancestor) {
  if (!sid || !IsValidSid(sid)) return false;
  if (IsWellKnownSid(sid, WinLocalSystemSid) || IsWellKnownSid(sid, WinBuiltinAdministratorsSid)) return true;
  if (!ancestor) return false;
  // Windows drive roots can be owned by the TrustedInstaller service. It is
  // accepted for ancestors only, never for the catalog or its immediate parent.
  PSID ti = nullptr;
  checked(ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &ti), "cannot resolve system trust owner");
  Local owner(ti);
  return EqualSid(sid, ti) != FALSE;
}
void verify_acl(HANDLE handle, bool ancestor) {
  PSID owner = nullptr;
  PACL acl = nullptr;
  PSECURITY_DESCRIPTOR raw = nullptr;
  if (GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                      &owner, nullptr, &acl, nullptr, &raw) != ERROR_SUCCESS) fail("cannot read trust ACL");
  Local descriptor(raw);
  SECURITY_DESCRIPTOR_CONTROL control{};
  DWORD revision = 0;
  checked(GetSecurityDescriptorControl(raw, &control, &revision), "cannot inspect trust ACL");
  std::vector<detail::Ace> entries;
  if (acl) {
    checked(IsValidAcl(acl), "invalid trust ACL");
    for (DWORD i = 0; i < acl->AceCount; ++i) {
      void* raw_ace = nullptr;
      checked(GetAce(acl, i, &raw_ace), "invalid trust ACE");
      const auto* header = static_cast<const ACE_HEADER*>(raw_ace);
      if (header->AceFlags & INHERIT_ONLY_ACE) continue; // Not effective on this object.
      if (header->AceType == ACCESS_ALLOWED_ACE_TYPE) {
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw_ace);
        entries.push_back({detail::AceKind::allow, privileged(const_cast<DWORD*>(&ace->SidStart), ancestor), ace->Mask});
      } else if (header->AceType == ACCESS_DENIED_ACE_TYPE) {
        entries.push_back({detail::AceKind::deny, false, 0});
      } else entries.push_back({detail::AceKind::unsupported, false, 0});
    }
  }
  if (!detail::secure_acl(privileged(owner, ancestor), (control & SE_DACL_PROTECTED) != 0,
                          (control & SE_DACL_PRESENT) != 0 && acl != nullptr, entries, ancestor))
    fail("trust path is not administrator protected");
}

std::wstring installation() {
  std::array<wchar_t, 32768> path{};
  auto n=GetModuleFileNameW(nullptr,path.data(),static_cast<DWORD>(path.size()));
  detail::require(n && n<path.size());
  std::wstring full(path.data(),n);
  detail::require(detail::explicit_local_path(full));
  return full.substr(0,full.rfind(L'\\')+1);
}
std::string utf8(std::wstring_view value) {
  int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),nullptr,0,nullptr,nullptr);
  detail::require(n>0); std::string out(n,'\0');
  detail::require(WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),out.data(),n,nullptr,nullptr)==n);
  return out;
}
// Ancestors and exact file remain open without write/delete sharing through all
// runtime creation and helper launches. No validate-close-reopen race.
class PinnedFile {
  std::vector<Handle> handles_;
public:
  explicit PinnedFile(const std::wstring& path) {
    detail::require(detail::explicit_local_path(path));
    const auto root=path.substr(0,3);
    detail::require(GetDriveTypeW(root.c_str())==DRIVE_FIXED);
    DWORD flags{};
    checked(GetVolumeInformationW(root.c_str(),nullptr,0,nullptr,nullptr,&flags,nullptr,0),"volume");
    detail::require((flags&FS_PERSISTENT_ACLS)!=0);
    std::vector<std::wstring> parts{root};
    for(auto i=path.find(L'\\',3);i!=std::wstring::npos;i=path.find(L'\\',i+1)) parts.push_back(path.substr(0,i));
    parts.push_back(path);
    for(std::size_t i=0;i<parts.size();++i) {
      const bool leaf=i+1==parts.size();
      Handle h(CreateFileW(parts[i].c_str(),READ_CONTROL|FILE_READ_ATTRIBUTES|(leaf?FILE_READ_DATA:0),
        FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS,nullptr));
      detail::require(bool(h));
      FILE_ATTRIBUTE_TAG_INFO attrs{};
      checked(GetFileInformationByHandleEx(h.get(),FileAttributeTagInfo,&attrs,sizeof(attrs)),"attributes");
      detail::require(!(attrs.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT));
      detail::require(leaf ? !(attrs.FileAttributes&FILE_ATTRIBUTE_DIRECTORY) : (attrs.FileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=0);
      verify_acl(h.get(),i+2<parts.size()); handles_.push_back(std::move(h));
    }
  }
  HANDLE file() const {return handles_.back().get();}
  void verify() { for(std::size_t i=0;i<handles_.size();++i) verify_acl(handles_[i].get(),i+2<handles_.size()); }
  void hash() {
    constexpr std::string_view expected=ORANGESPACE_HELPER_SHA256;
    detail::require(expected.size()==64);
    BCRYPT_ALG_HANDLE alg{};
    detail::require(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0)==0);
    struct Alg { BCRYPT_ALG_HANDLE p; ~Alg(){BCryptCloseAlgorithmProvider(p,0);} } ag{alg};
    BCRYPT_HASH_HANDLE hash{};
    detail::require(BCryptCreateHash(alg,&hash,nullptr,0,nullptr,0,0)==0);
    struct Hash { BCRYPT_HASH_HANDLE p; ~Hash(){BCryptDestroyHash(p);} } hg{hash};
    std::array<BYTE,65536> buffer{}; DWORD n{}; std::size_t total{};
    for(;;) {
      checked(ReadFile(handles_.back().get(),buffer.data(),static_cast<DWORD>(buffer.size()),&n,nullptr),"hash read");
      if(!n) break;
      total+=n; detail::require(total<=300*1024*1024);
      detail::require(BCryptHashData(hash,buffer.data(),n,0)==0);
    }
    detail::require(total>0);
    std::array<BYTE,32> digest{}; detail::require(BCryptFinishHash(hash,digest.data(),32,0)==0);
    std::string actual; constexpr char hex[]="0123456789abcdef";
    for(auto c:digest){actual+=hex[c>>4];actual+=hex[c&15];}
    detail::require(actual==expected); verify();
  }
};
// Only public OS ownership/generation metadata, never auth IDs or secrets.
void state_acl(HANDLE h) {
  PSID owner{}; PACL acl{}; PSECURITY_DESCRIPTOR raw{};
  detail::require(GetSecurityInfo(h,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,nullptr,&acl,nullptr,&raw)==ERROR_SUCCESS);
  Local descriptor(raw);
  SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision{};
  checked(GetSecurityDescriptorControl(raw,&control,&revision),"state ACL");
  detail::require(privileged(owner,false) && acl && (control&SE_DACL_PROTECTED));
  for(DWORD i=0;i<acl->AceCount;++i) {
    void* value{};checked(GetAce(acl,i,&value),"state ACE"); const auto* head=static_cast<ACE_HEADER*>(value);
    if(head->AceFlags&INHERIT_ONLY_ACE)continue;
    if(head->AceType==ACCESS_ALLOWED_ACE_TYPE) {
      auto* ace=static_cast<ACCESS_ALLOWED_ACE*>(value);
      detail::require(privileged(&ace->SidStart,false));
    } else detail::require(head->AceType==ACCESS_DENIED_ACE_TYPE);
  }
}
#ifdef ORANGESPACE_NATIVE_ACCEPTANCE_TRACE
enum class SeamEvent { entry, ffi, response, success };
void native_seam_trace(SeamEvent event,std::int64_t rc,unsigned bits) noexcept {
  const auto saved=GetLastError();
  try {
    constexpr const char* names[]={"backend-start-entry","ffi-return","start-response","backend-start-success"};
    char line[96]; const int length=std::snprintf(line,sizeof(line),"%s %lld %u\n",names[static_cast<unsigned>(event)],static_cast<long long>(rc),bits);
    if(length>0 && static_cast<std::size_t>(length)<sizeof(line) && bits<=31) {
      PinnedFile anchor(installation()+L"nodes.json");
      PSECURITY_DESCRIPTOR raw{};
      checked(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;FA;;;SY)(A;;FA;;;BA)",SDDL_REVISION_1,&raw,nullptr),"trace ACL");
      Local descriptor(raw); SECURITY_ATTRIBUTES sa{sizeof(sa),raw,FALSE};
      Handle file(CreateFileW((installation()+L"native-seam-trace.txt").c_str(),FILE_APPEND_DATA|READ_CONTROL|FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ,&sa,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
      BY_HANDLE_FILE_INFORMATION info{};
      if(file && GetFileType(file.get())==FILE_TYPE_DISK && GetFileInformationByHandle(file.get(),&info) &&
         !(info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)) && info.nNumberOfLinks==1 &&
         info.nFileSizeHigh==0 && info.nFileSizeLow<=65536-static_cast<DWORD>(length)) {
        verify_acl(file.get(),false); anchor.verify(); DWORD written{};
        (void)WriteFile(file.get(),line,static_cast<DWORD>(length),&written,nullptr);
      }
    }
  } catch (...) {}
  SetLastError(saved);
}
#endif
class StateStore {
  std::wstring path_;
  std::wstring temporary_;
  const bool prototype_;
  std::unique_ptr<PinnedFile> directory_anchor_;
  std::string last_;
  std::string read() {
    // Pinning this fixed file also pins all protected ancestors throughout read.
    PinnedFile file(path_); state_acl(file.file());
    LARGE_INTEGER n{}; checked(GetFileSizeEx(file.file(),&n),"state size");
    detail::require(n.QuadPart>0 && n.QuadPart<=1024*1024);
    std::string out(static_cast<std::size_t>(n.QuadPart),'\0'); DWORD count{};
    checked(ReadFile(file.file(),out.data(),static_cast<DWORD>(out.size()),&count,nullptr),"state read");
    detail::require(count==out.size()); file.verify(); state_acl(file.file()); return out;
  }
public:
  explicit StateStore(bool prototype=false):prototype_(prototype) {}
  std::vector<Persisted> load() {
    const auto directory=installation();
    const auto layout=prototype_ ? prototype_namespace_paths(directory) :
      PrototypeNamespacePaths{directory+L"nodes.json",directory+L"service-state.json",directory+L"service-state.next"};
    path_=layout.state;temporary_=layout.next;
    // A fixed existing nodes.json anchor retains the protected installation
    // directory/ancestors against replacement for the entire store lifetime.
    directory_anchor_=std::make_unique<PinnedFile>(layout.anchor);
    last_=read(); return parse_state(last_); // absent/corrupt is NEVER empty state
  }
  void save(const std::vector<Persisted>& state) {
    detail::require(directory_anchor_!=nullptr); directory_anchor_->verify();
    const auto data=state_json(state); (void)parse_state(data);
    detail::require(read()==last_); // detect unexpected privileged state drift
    PSECURITY_DESCRIPTOR raw{};
    checked(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;FA;;;SY)(A;;FA;;;BA)",SDDL_REVISION_1,&raw,nullptr),"state descriptor");
    Local descriptor(raw); SECURITY_ATTRIBUTES sa{sizeof(sa),raw,FALSE};
    const auto& temporary=temporary_;
    Handle file(CreateFileW(temporary.c_str(),GENERIC_WRITE|READ_CONTROL,0,&sa,CREATE_NEW,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,nullptr));
    detail::require(bool(file));
    struct Cleanup {Handle& file;std::wstring path;bool owned{true};~Cleanup(){if(owned){file=Handle{};DeleteFileW(path.c_str());}}} cleanup{file,temporary};
    state_acl(file.get()); DWORD count{};
    checked(WriteFile(file.get(),data.data(),static_cast<DWORD>(data.size()),&count,nullptr),"state write");
    detail::require(count==data.size()); checked(FlushFileBuffers(file.get()),"state flush"); file=Handle{};
    detail::require(read()==last_); directory_anchor_->verify();
    checked(MoveFileExW(temporary.c_str(),path_.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH),"state replace");
    cleanup.owned=false; detail::require(read()==data); last_=data;
  }
};
class Node final : public Session {
  std::shared_ptr<node_session::TrustedCatalog> catalog_;
  std::string alias_;
  std::unique_ptr<node_session::NodeSession> session_;
  mutable std::mutex mutex_;
public:
  Node(std::shared_ptr<node_session::TrustedCatalog> c,std::string_view alias,std::string_view envelope)
    :catalog_(std::move(c)),alias_(alias),session_(new node_session::NodeSession(node_session::NodeSession::restore_envelope(*catalog_,alias_,envelope))) {}
  Identity identity() const override {
    std::lock_guard lock(mutex_);
    return {session_->identity().user_id,session_->identity().node_id,session_->expires_at()};
  }
  void refresh() override {
    std::lock_guard lock(mutex_);
    Text envelope(session_->credential_envelope());
    session_.reset(new node_session::NodeSession(node_session::NodeSession::restore_envelope(*catalog_,alias_,envelope.value)));
  }
  LeaseResult create(const Binding& b) override {
    std::lock_guard lock(mutex_);
    return session_->create_tunnel("{\"sandbox_id\":"+quote(b.sandbox)+",\"generation\":"+std::to_string(b.generation)+",\"tunnel_id\":"+quote(b.tunnel)+"}");
  }
  RenewResult renew(const Binding& b) override {
    std::lock_guard lock(mutex_); return session_->renew_tunnel(b.tunnel);
  }
  void revoke(const Binding& b) override { std::lock_guard lock(mutex_); session_->revoke_tunnel(b.tunnel); }
  void logout() override { std::lock_guard lock(mutex_); session_->logout(); }
};
#include "platform_chain_windows.inc"
class WindowsBackend final : public PrototypePlatformBackend {
  std::mutex mutex_;
  bool poisoned_{};
  std::unique_ptr<PinnedFile> helper_,catalog_pin_;
  std::shared_ptr<node_session::TrustedCatalog> catalog_;
  bool platform_mode_{};
  bool prototype_mixed_{};
  std::unique_ptr<PinnedFile> platform_pin_;
  std::optional<platform_session::PlatformConfig> platform_config_;
  PlatformReceipts platform_receipts_;
  struct Realm {
    std::mutex io; // only this runtime serializes; never the global backend map
    std::atomic_bool retired{false};
    std::string node; // immutable after reservation; one static trust domain per realm
    void* runtime{};
    std::set<std::string> exited;
    struct Active : Binding {
      bool submitted{}; // set under mutex immediately before possibly entering FFI
      std::optional<LeaseBudget> original_budget;
      std::int64_t initial_expiry{};
      bool take_attempted{};
      Active(const Binding& b) : Binding(b) {}
    };
    std::map<std::string,Active> active;
    ~Realm() {if(runtime) os_runtime_free(runtime);}
  };
  std::map<std::string,std::shared_ptr<Realm>,std::less<>> realms_;
  struct OrdinaryInvalid {}; // fixed, non-secret, allocation-free private FFI outcome
  std::string call(void* runtime_,std::string_view request) {
    std::array<std::uint8_t,65536> out{};
    auto n=os_runtime_call(runtime_,reinterpret_cast<const std::uint8_t*>(request.data()),request.size(),out.data(),out.size());
#ifdef ORANGESPACE_NATIVE_ACCEPTANCE_TRACE
    native_seam_trace(SeamEvent::ffi,n,0);
#endif
    if(n==-1)throw OrdinaryInvalid{};
    detail::require(n>0 && static_cast<std::size_t>(n)<=out.size());
    return {reinterpret_cast<char*>(out.data()),static_cast<std::size_t>(n)};
  }
public:
  explicit WindowsBackend(bool platform_mode=false,bool prototype_mixed=false)
      :platform_mode_(platform_mode),prototype_mixed_(prototype_mixed) {
    detail::require(!prototype_mixed_ || platform_mode_);
    if(platform_mode_) {
      const auto path=installation()+L"platform.json";
      platform_pin_=std::make_unique<PinnedFile>(path);
      platform_config_.emplace(platform_session::PlatformConfig::load(path));
      platform_pin_->verify();
    }
  }
  void fail_closed() noexcept override {
    decltype(realms_) retired;
    {
      std::lock_guard lock(mutex_);poisoned_=true;retired.swap(realms_);
      for(auto& [_,state]:retired)state->retired=true;
    }
    // Wait only for already-running bounded FFI, without monopolizing the map.
    for(auto& [_,state]:retired) {
      std::lock_guard io(state->io);
      if(state->runtime){os_runtime_free(state->runtime);state->runtime=nullptr;}
    }
  }
  void release(std::string_view realm) noexcept override {
    std::shared_ptr<Realm> state;
    {
      std::lock_guard lock(mutex_);auto it=realms_.find(realm);if(it==realms_.end())return;
      state=it->second;state->retired=true;realms_.erase(it);
    }
    std::lock_guard io(state->io);
    if(state->runtime){os_runtime_free(state->runtime);state->runtime=nullptr;}
  }
  std::shared_ptr<Session> restore(std::string_view alias,std::string_view envelope) override {
    std::shared_ptr<node_session::TrustedCatalog> catalog;
    {
      std::lock_guard lock(mutex_);
      if(!catalog_) {
        auto dir=installation();
        catalog_pin_=std::make_unique<PinnedFile>(dir+L"nodes.json");
        catalog_=std::make_shared<node_session::TrustedCatalog>(node_session::TrustedCatalog::load(dir+L"nodes.json"));
      }
      catalog_pin_->verify(); catalog=catalog_;
      if(platform_mode_)platform_pin_->verify();
    }
    if(platform_mode_) {
      detail::exact_wire_integers(envelope);detail::JsonGuard request(envelope);detail::object(request.value,2);
      auto selected=platform::parse_node(detail::field(request.value,"node"));detail::require(alias==selected.node_id);
      const auto& saved=detail::text(detail::field(request.value,"envelope"));
      auto central=platform_session::Session::restore(*platform_config_,saved);
      auto receipt=platform_receipts_.reserve(catalog,selected.node_id);
      try {
        auto session=std::make_shared<PlatformNode>(catalog,receipt,std::move(central),std::move(selected));
        session->initialize();return session;
      } catch(...) {receipt->abandon();throw;}
    }
    return std::make_shared<Node>(std::move(catalog),alias,envelope);
  }
  std::string id() override {
    std::array<BYTE,16> bytes{};
    detail::require(BCryptGenRandom(nullptr,bytes.data(),16,BCRYPT_USE_SYSTEM_PREFERRED_RNG)==0);
    bytes[6]=(bytes[6]&15)|64; bytes[8]=(bytes[8]&63)|128;
    constexpr char hex[]="0123456789abcdef"; std::string out;
    for(std::size_t i=0;i<bytes.size();++i){if(i==4||i==6||i==8||i==10)out+='-';out+=hex[bytes[i]>>4];out+=hex[bytes[i]&15];}
    return out;
  }
  void reserve(std::string_view realm,const Binding& b) override {
    std::lock_guard lock(mutex_);detail::require(!poisoned_);
    std::size_t count=0;for(const auto& [_,r]:realms_)count+=r->active.size();
    detail::require(count<64 && (realms_.contains(realm) || realms_.size()<256));
    auto found=realms_.find(realm);
    if(found!=realms_.end()) {
      detail::require(!found->second->retired && found->second->node==b.node && found->second->active.emplace(b.tunnel,b).second);
    } else {
      // Publish only a complete owner: either allocation may throw, but neither
      // a null realm nor an empty uncounted realm may become globally visible.
      auto ready=std::make_shared<Realm>();
      ready->node=b.node;
      detail::require(ready->active.emplace(b.tunnel,b).second);
      realms_.emplace(std::string(realm),std::move(ready));
    }
  }
  std::shared_ptr<Realm> reserved(std::string_view realm,const Binding& b) {
    std::lock_guard lock(mutex_);auto it=realms_.find(realm);
    detail::require(!poisoned_ && it!=realms_.end() && !it->second->retired);
    const auto binding=it->second->active.find(b.tunnel);
    detail::require(binding!=it->second->active.end() && binding->second==b);return it->second;
  }
  std::shared_ptr<const std::string> trusted_ca_for_node(std::string_view id) {
    detail::require(catalog_!=nullptr);
    const auto& node=catalog_->federation_node(id);
    detail::require(node.node_id==id);
    return node.ca_pem; // protected static snapshot ONLY, not lease/UI/central data
  }
  Proof start(std::string_view realm,const Binding& b,const LeaseResult& lease) override {
#ifdef ORANGESPACE_NATIVE_ACCEPTANCE_TRACE
    native_seam_trace(SeamEvent::entry,0,0);
#endif
    lease.budget.validate(detail::monotonic_ms());
    std::optional<LeaseBudget> channel_grant;
    if(prototype_mixed_)channel_grant.emplace(lease.budget);
    auto state=reserved(realm,b);std::string encoded;
    std::shared_ptr<const std::string> trusted_ca;
    {
      std::lock_guard lock(mutex_);detail::require(!poisoned_ && !state->retired);
      auto path=installation()+L"sing-box.exe";
      if(!helper_){helper_=std::make_unique<PinnedFile>(path);helper_->hash();}
      helper_->verify();encoded=utf8(path);
      detail::require(state->node==b.node);
      trusted_ca=trusted_ca_for_node(b.node);
    }
    std::lock_guard io(state->io);detail::require(!state->retired);
    (void)reserved(realm,b); // exact stop may have invalidated while waiting for io
    lease.budget.validate(detail::monotonic_ms());
    if(!state->runtime) {
      state->runtime=prototype_mixed_
        ? os_runtime_new_with_local_proxy_v1(reinterpret_cast<const std::uint8_t*>(encoded.data()),encoded.size(),10000,
            trusted_ca ? reinterpret_cast<const std::uint8_t*>(trusted_ca->data()) : nullptr,
            trusted_ca ? trusted_ca->size() : 0,1)
        : trusted_ca
        ? os_runtime_new_with_ca_v1(reinterpret_cast<const std::uint8_t*>(encoded.data()),encoded.size(),10000,
            reinterpret_cast<const std::uint8_t*>(trusted_ca->data()),trusted_ca->size())
        : os_runtime_new(reinterpret_cast<const std::uint8_t*>(encoded.data()),encoded.size(),10000);
      detail::require(state->runtime!=nullptr);
    }
    Text request;
    request.value="{\"schema\":2,\"op\":\"start\",\"binding\":"+binding_json(b)+",\"budget\":"+budget_json(lease.budget)+",\"lease\":";
    request.value+=lease.payload; request.value+='}';
    lease.budget.validate(detail::monotonic_ms());
    {
      std::lock_guard lock(mutex_);
      auto active=state->active.find(b.tunnel);
      detail::require(!poisoned_ && !state->retired && active!=state->active.end() && active->second==b);
      active->second.submitted=true;
    }
    detail::JsonGuard result(call(state->runtime,request.value));
    const auto& root=result.value;
#ifdef ORANGESPACE_NATIVE_ACCEPTANCE_TRACE
    try {
      unsigned bits=state->retired ? 16u : 0u;
      if(const auto* v=root.find("ok");v && v->is_true()) bits|=1u;
      if(const auto* v=root.find("process_started");v && v->is_true()) bits|=2u;
      if(const auto* v=root.find("tunnel_authenticated");v && v->is_true()) bits|=4u;
      if(const auto* v=root.find("forwarding_verified");v && v->is_true()) bits|=8u;
      native_seam_trace(SeamEvent::response,0,bits);
    } catch (...) {}
#endif
    lease.budget.validate(detail::monotonic_ms());
    detail::require(detail::field(root,"ok").is_true() && !state->retired);
    (void)reserved(realm,b); // logout/stop/poison during proof cannot commit
    {
      std::lock_guard lock(mutex_);
      const auto active=state->active.find(b.tunnel);
      detail::require(!poisoned_ && !state->retired && active!=state->active.end() && active->second==b);
      lease.budget.validate(detail::monotonic_ms());
      active->second.server_expiry=lease.expires_at; active->second.deadline_ms=lease.budget.deadline_ms;
      if(channel_grant) {
        active->second.original_budget.emplace(std::move(*channel_grant));
        active->second.initial_expiry=lease.expires_at;
      }
    }
#ifdef ORANGESPACE_NATIVE_ACCEPTANCE_TRACE
    native_seam_trace(SeamEvent::success,0,0);
#endif
    return {detail::field(root,"process_started").is_true(),detail::field(root,"tunnel_authenticated").is_true(),detail::field(root,"forwarding_verified").is_true()};
  }
  LocalChannel take_local_channel(std::string_view realm,const Binding& b) override {
    detail::require(prototype_mixed_ && platform_mode_);
    auto state=reserved(realm,b);
    std::lock_guard io(state->io);
    // IO -> map order matches start/renew. Never hold the map across FFI.
    auto exact=[&](bool unconsumed) {
      std::lock_guard lock(mutex_);
      auto active=state->active.find(b.tunnel);
      detail::require(!poisoned_ && !state->retired && state->runtime &&
        active!=state->active.end() && active->second.submitted &&
        active->second.same_authority(b) && active->second.original_budget &&
        (!unconsumed || !active->second.take_attempted));
      const auto& original=*active->second.original_budget;
      original.validate(detail::monotonic_ms());
      detail::require(b.deadline_ms==original.deadline_ms && b.server_expiry==active->second.initial_expiry);
    };
    auto root_alive=[&] {
      exact(false);
      detail::JsonGuard poll(call(state->runtime,"{\"schema\":2,\"op\":\"poll\"}"));
      const auto* exited=std::get_if<json::Value::Array>(&detail::field(poll.value,"exited").data);
      detail::require(exited!=nullptr);
      for(const auto& item:*exited)
        detail::require(parse_binding(detail::field(item,"binding"))!=b);
      exact(false);
    };
    exact(true);
    LeaseBudget original;
    {
      std::lock_guard lock(mutex_);
      original=*state->active.at(b.tunnel).original_budget;
    }
    exact(true);
    const auto request=binding_json(b);
    exact(true);root_alive();exact(true);
    LocalChannelBuffer output;
    {
      std::lock_guard lock(mutex_);
      // The prior exact check cannot be separated from this consumption fence.
      auto active=state->active.find(b.tunnel);
      detail::require(!poisoned_ && !state->retired && active!=state->active.end() &&
        active->second.same_authority(b) && !active->second.take_attempted);
      original.validate(detail::monotonic_ms());
      active->second.take_attempted=true;
    }
    const auto n=os_runtime_take_local_channel_v1(state->runtime,
      reinterpret_cast<const std::uint8_t*>(request.data()),request.size(),output.bytes.data(),output.bytes.size());
    const auto received=detail::monotonic_ms();
    exact(false);
    detail::require(n>0 && static_cast<std::size_t>(n)<=output.bytes.size());
    root_alive();exact(false);
    auto result=decode_local_channel(std::string_view(reinterpret_cast<const char*>(output.bytes.data()),static_cast<std::size_t>(n)),b,original,received);
    exact(false);root_alive();exact(false);
    const auto now=detail::monotonic_ms();
    detail::require(result.proof_observed_at_ms<=now && now-result.proof_observed_at_ms<3000);
    original.validate(now);
    return result;
  }
  bool confirm_absent(void* runtime,const Binding& b) {
    // A fresh READ-ONLY cleanup observation budget, not renewed lease authority.
    // Old b may already be expired; never reuse or extend its work deadline.
    const auto started=detail::monotonic_ms();
    const LeaseBudget budget{std::string(nd::lease_clock),started,5000,started+5000};
    const auto text=call(runtime,"{\"schema\":2,\"op\":\"probe\",\"binding\":"+binding_json(b)+",\"budget\":"+budget_json(budget)+"}");
    budget.validate(detail::monotonic_ms());
    detail::exact_wire_integers(text);detail::JsonGuard reply(text);
    const auto& root=reply.value;detail::object(root,8);
    detail::require(parse_binding(detail::field(root,"binding"))==b);
    for(const auto key:{"ok","process_alive","forwarding_verified"}) {
      const auto* value=std::get_if<bool>(&detail::field(root,key).data);
      detail::require(value && !*value);
    }
    detail::require(detail::integer(detail::field(root,"lease_deadline_ms"),0)==0 && detail::integer(detail::field(root,"expires_at"),0)==0);
    const auto& reason=detail::text(detail::field(root,"reason"));
    detail::require(reason=="not_active" || reason=="expired" || reason=="helper_stopped");
    const auto observed=detail::integer(detail::field(root,"observed_at_ms"));
    const auto now=detail::monotonic_ms();budget.validate(now);
    detail::require(observed>=started && observed<budget.deadline_ms && observed<=now);
    return true;
  }
  void close(std::string_view realm,const Binding& b) noexcept override {
    try {
      std::shared_ptr<Realm> state; bool submitted=false;
      {
        std::lock_guard lock(mutex_);auto found=realms_.find(realm);if(found==realms_.end())return;
        state=found->second;auto it=state->active.find(b.tunnel);
        if(it==state->active.end() || it->second!=b)return;
        submitted=it->second.submitted;
        state->active.erase(it); // invalidation precedes any wait for proof
      }
      // No FFI could own this tuple. In particular, an unknown close must not
      // escalate into releasing an unrelated sibling's runtime.
      if(!submitted)return;
      std::lock_guard io(state->io);
      if(state->runtime && !state->retired) {
        try {(void)call(state->runtime,"{\"schema\":2,\"op\":\"close\",\"binding\":"+binding_json(b)+"}");}
        catch(const OrdinaryInvalid&) {
          // Same realm.io remains held through the exact negative observation.
          detail::require(confirm_absent(state->runtime,b));
        }
      }
    } catch (...) {release(realm);}
  }
  void renew(std::string_view realm,const Binding& b,const RenewResult& renewal) override {
    renewal.budget.validate(detail::monotonic_ms());
    auto state=reserved(realm,b);std::lock_guard io(state->io);
    detail::require(!state->retired && state->runtime);(void)reserved(realm,b);
    Binding old;
    {
      std::lock_guard lock(mutex_);
      const auto active=state->active.find(b.tunnel);
      detail::require(!poisoned_ && !state->retired && active!=state->active.end() && active->second.same_authority(b));
      old.server_expiry=active->second.server_expiry;old.deadline_ms=active->second.deadline_ms;
    }
    (void)renewed_deadline(old,renewal,detail::monotonic_ms());
    const auto request="{\"schema\":2,\"op\":\"renew\",\"binding\":"+binding_json(b)+",\"expires_at\":"+std::to_string(renewal.expires_at)+",\"budget\":"+budget_json(renewal.budget)+"}";
    (void)renewed_deadline(old,renewal,detail::monotonic_ms());
    detail::JsonGuard reply(call(state->runtime,request));
    detail::require(detail::field(reply.value,"ok").is_true());
    const auto deadline=renewed_deadline(old,renewal,detail::monotonic_ms());
    std::lock_guard lock(mutex_);
    const auto active=state->active.find(b.tunnel);
    detail::require(!poisoned_ && !state->retired && active!=state->active.end() && active->second==b);
    (void)renewed_deadline(old,renewal,detail::monotonic_ms());
    active->second.server_expiry=renewal.expires_at;active->second.deadline_ms=deadline;
  }
  bool diagnose(std::string_view realm,const Binding& b,const LeaseBudget& budget) override {
    budget.validate(detail::monotonic_ms());
    auto state=reserved(realm,b);std::lock_guard io(state->io);
    auto exact=[&] {
      std::lock_guard lock(mutex_);
      const auto it=state->active.find(b.tunnel);
      detail::require(!poisoned_ && !state->retired && state->runtime && it!=state->active.end() && it->second.same_authority(b));
      budget.validate(detail::monotonic_ms());
      detail::require(b.deadline_ms>detail::monotonic_ms() && budget.deadline_ms<=b.deadline_ms);
    };
    exact();
    const auto text=call(state->runtime,"{\"schema\":2,\"op\":\"probe\",\"binding\":"+binding_json(b)+",\"budget\":"+budget_json(budget)+"}");
    exact();detail::exact_wire_integers(text);detail::JsonGuard reply(text);
    const auto& root=reply.value;detail::object(root,8);
    detail::require(parse_binding(detail::field(root,"binding"))==b);
    const auto observed=detail::integer(detail::field(root,"observed_at_ms"));
    detail::require(observed>=budget.request_started_ms && observed<budget.deadline_ms && observed<=detail::monotonic_ms());
    detail::require(detail::integer(detail::field(root,"lease_deadline_ms"),0)==b.deadline_ms && detail::integer(detail::field(root,"expires_at"),0)==b.server_expiry);
    const auto& reason=detail::text(detail::field(root,"reason"));
    detail::require(reason=="verified" || reason=="not_active" || reason=="expired" || reason=="helper_stopped" || reason=="probe_failed" || reason=="stale_authority");
    const bool fresh=detail::field(root,"ok").is_true() && detail::field(root,"process_alive").is_true() && detail::field(root,"forwarding_verified").is_true() && reason=="verified";
    exact();return fresh;
  }
  bool alive(std::string_view realm,const Binding& b) override {
    auto state=reserved(realm,b);std::lock_guard io(state->io);
    if(state->retired || !state->runtime)return false;
    {
      std::lock_guard lock(mutex_);
      auto it=state->active.find(b.tunnel);
      if(it==state->active.end() || it->second!=b || it->second.deadline_ms<=detail::monotonic_ms())return false;
    }
    detail::JsonGuard reply(call(state->runtime,"{\"schema\":2,\"op\":\"poll\"}"));
    const auto* array=std::get_if<json::Value::Array>(&detail::field(reply.value,"exited").data);
    detail::require(array!=nullptr);
    std::lock_guard lock(mutex_);if(state->retired)return false;
    for(const auto& item:*array) {
      const auto& id=detail::text(detail::field(detail::field(item,"binding"),"tunnel_id"));
      state->exited.insert(id);state->active.erase(id);
    }
    auto it=state->active.find(b.tunnel);
    return it!=state->active.end() && it->second==b && it->second.deadline_ms>detail::monotonic_ms() && !state->exited.contains(b.tunnel);
  }
};
std::string envelope_json(const json::Value& value) {
  detail::object(value,5);
  return "{\"schema\":"+std::to_string(detail::integer(detail::field(value,"schema")))+
    ",\"node_id\":"+quote(detail::text(detail::field(value,"node_id")))+
    ",\"api_origin\":"+quote(detail::text(detail::field(value,"api_origin")))+
    ",\"access_token\":"+quote(detail::text(detail::field(value,"access_token")))+
    ",\"expires_at\":"+std::to_string(detail::integer(detail::field(value,"expires_at")))+"}";
}
}
std::int64_t chain_now() { return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count(); }
std::unique_ptr<chain::Backend> make_chain_backend() { return std::make_unique<WindowsBackend>(); }
std::unique_ptr<chain::Backend> make_platform_chain_backend() { return std::make_unique<WindowsBackend>(true); }
std::unique_ptr<PrototypePlatformBackend> make_prototype_platform_chain_backend() { return std::make_unique<WindowsBackend>(true,true); }
std::shared_ptr<chain::Namespace> make_chain_namespace() {
  auto store=std::make_shared<StateStore>();
  return std::make_shared<chain::Namespace>([store]{return store->load();},[store](const auto& state){store->save(state);});
}
std::shared_ptr<chain::Namespace> make_prototype_chain_namespace() {
  // Dedicated protected persisted owner; never an in-memory production namespace
  // and never a mutable ledger inside the pinned closed browser/runtime tree.
  auto store=std::make_shared<StateStore>(true);
  return std::make_shared<chain::Namespace>([store]{return store->load();},[store](const auto& state){store->save(state);});
}
chain::Response dispatch_platform_chain(chain::Engine& engine,const Peer& peer,std::span<const std::uint8_t> bytes) {
  auto request=platform::parse_request(bytes);const auto& root=request.body.value;
  if(request.op==1) {
    const auto selected=platform::parse_node(detail::field(root,"node"));
    return engine.authorize_response(peer,selected.node_id,std::string_view(reinterpret_cast<const char*>(bytes.data()+12),bytes.size()-12));
  }
  if(request.op==7) {
    const auto cursor=engine.register_sandbox(peer,detail::text(detail::field(root,"auth_id")),detail::text(detail::field(root,"sandbox_id")));
    return "{\"ok\":true,\"browser_allowed\":false,\"sandbox_id\":"+chain::quote(cursor.sandbox)+",\"generation\":"+std::to_string(cursor.generation)+"}";
  }
  // Reuse the legacy exact-operation Engine/ACK response paths, not a second
  // ownership implementation. Platform start was required to carry a cursor.
  chain::Text body(std::string(reinterpret_cast<const char*>(bytes.data()+12),bytes.size()-12));
  auto translated=chain::request_frame(static_cast<chain::Op>(request.op),body.value);
  return dispatch_chain(engine,peer,translated);
}
chain::Response dispatch_chain(chain::Engine& engine,const Peer& peer,std::span<const std::uint8_t> bytes) {
  using namespace chain;
  auto request=parse_request(bytes); const auto& root=request.body.value;
  if(request.op==Op::authorize) {
    Text envelope(envelope_json(detail::field(root,"envelope")));
    return engine.authorize_response(peer,detail::text(detail::field(root,"alias")),envelope.value);
  }
  const auto& auth=detail::text(detail::field(root,"auth_id"));
  switch(request.op) {
    case Op::start: {
      std::optional<Cursor> prior;
      if(root.find("sandbox_id")) prior=Cursor{detail::text(detail::field(root,"sandbox_id")),static_cast<std::uint64_t>(detail::integer(detail::field(root,"expected_generation"),0))};
      return engine.start_response(peer,auth,prior);
    }
    case Op::stop: {
      const auto cursor=engine.stop(peer,auth,Cursor{detail::text(detail::field(root,"sandbox_id")),static_cast<std::uint64_t>(detail::integer(detail::field(root,"expected_generation"),0))});
      return "{\"ok\":true,\"browser_allowed\":false,\"sandbox_id\":"+quote(cursor.sandbox)+",\"generation\":"+std::to_string(cursor.generation)+"}";
    }
    case Op::diagnose: return engine.diagnose(peer,auth,parse_binding(detail::field(root,"binding")));
    case Op::logout: engine.logout(peer,auth); break;
    case Op::retire: engine.retire(peer,auth); break;
    case Op::status:
      if(root.find("sandbox_id")) {
        auto c=engine.cursor(peer,auth,detail::text(detail::field(root,"sandbox_id")));
        return "{\"ok\":true,\"browser_allowed\":false,\"auth_id\":"+quote(auth)+",\"sandbox_id\":"+quote(c.sandbox)+",\"generation\":"+std::to_string(c.generation)+"}";
      }
      return engine.status(peer,auth);
    default: detail::require(false);
  }
  return Response(R"({"ok":true,"browser_allowed":false})");
}
}
