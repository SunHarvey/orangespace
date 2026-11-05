#include "network_policy_win.hpp"
#ifdef _WIN32
#include <windows.h>
#include <fwpmu.h>
#include <fwpmtypes.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <mutex>


namespace orangespace::wfp_prototype {
namespace {
// Independent namespace: never share keys with wfp-baseline.
const GUID provider = {0xdbad11e1,0x68a7,0x4db4,{0x89,0x54,0xee,0x8d,0xca,0x2a,0x43,0x21}};
const GUID sublayer = {0xdbad11e2,0x68a7,0x4db4,{0x89,0x54,0xee,0x8d,0xca,0x2a,0x43,0x21}};
GUID key(unsigned slot) { auto g = provider; g.Data1 = 0xdbad1200 + slot; return g; }
const GUID packageProvider = {0xdbad21e1,0x68a7,0x4db4,{0x89,0x54,0xee,0x8d,0xca,0x2a,0x43,0x21}};
const GUID packageSublayer = {0xdbad21e2,0x68a7,0x4db4,{0x89,0x54,0xee,0x8d,0xca,0x2a,0x43,0x21}};
GUID packageKey(unsigned n) { auto g=packageProvider; g.Data1=0xdbad2200+n; return g; }
bool eq(const GUID& a, const GUID& b) { return !!IsEqualGUID(a,b); }
[[noreturn]] void fail(const char* op, DWORD code) {
  throw std::runtime_error(std::string(op) + ":" + std::to_string(code));
}
void check(const char* op, DWORD code) { if (code) fail(op,code); }
void require(bool ok, const char* label = "exact-policy") { if (!ok) fail(label,ERROR_INVALID_DATA); }
void validatePackageSid(PSID sid) {
  require(sid && IsValidSid(sid), "package-sid-invalid");
  const SID_IDENTIFIER_AUTHORITY authority=SECURITY_APP_PACKAGE_AUTHORITY;
  require(*GetSidSubAuthorityCount(sid)==8 &&
    !std::memcmp(GetSidIdentifierAuthority(sid),&authority,sizeof(authority)) &&
    *GetSidSubAuthority(sid,0)==SECURITY_APP_PACKAGE_BASE_RID &&
    GetLengthSid(sid)==GetSidLengthRequired(8), "package-sid-not-canonical-appcontainer");
}
unsigned slot(Rule r) {
  if (r.layer != Layer::ConnectV4) return static_cast<unsigned>(r.layer);
  if (r.kind == RuleKind::All) return 0;
  return 3 + static_cast<unsigned>(r.kind);
}
const GUID& layer(Layer l) {
  switch (l) {
    case Layer::ConnectV4: return FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    case Layer::ConnectV6: return FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    case Layer::ReceiveV4: return FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
    case Layer::ReceiveV6: return FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
  }
  fail("layer",ERROR_INVALID_DATA);
}
struct Transaction {
  HANDLE engine; bool active = true;
  explicit Transaction(HANDLE e):engine(e) { check("FwpmTransactionBegin0",FwpmTransactionBegin0(e,0)); }
  ~Transaction() { if (active) FwpmTransactionAbort0(engine); }
  void commit() { check("FwpmTransactionCommit0",FwpmTransactionCommit0(engine)); active=false; }
};
template<class T> struct Memory {
  T* p = nullptr;
  ~Memory() { if (p) FwpmFreeMemory0(reinterpret_cast<void**>(&p)); }
};
struct NativeRule {
  FWPM_FILTER0 filter{};
  std::array<FWPM_FILTER_CONDITION0,3> conditions{};
  UINT64 weight = 0xffffffffffffffffULL;
  NativeRule(Rule r, FWP_BYTE_BLOB* app, PSID sid=nullptr) {
    filter.filterKey=sid ? packageKey(slot(r)) : key(slot(r));
    filter.providerKey=sid ? const_cast<GUID*>(&packageProvider) : nullptr;
    filter.subLayerKey=sid ? packageSublayer : sublayer; filter.layerKey=layer(r.layer);
    filter.flags=FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_INDEXED;
    filter.displayData.name=const_cast<wchar_t*>(L"OrangeSpace single prototype deny");
    filter.action.type=FWP_ACTION_BLOCK;
    filter.weight.type=FWP_UINT64; filter.weight.uint64=&weight;
    filter.filterCondition=conditions.data(); filter.numFilterConditions=1;
    auto& a=conditions[0]; a.matchType=FWP_MATCH_EQUAL;
    if (sid) {
      validatePackageSid(sid);
      a.fieldKey=FWPM_CONDITION_ALE_PACKAGE_ID;
      a.conditionValue.type=FWP_SID; a.conditionValue.sid=static_cast<SID*>(sid);
    } else {
      a.fieldKey=FWPM_CONDITION_ALE_APP_ID;
      a.conditionValue.type=FWP_BYTE_BLOB_TYPE; a.conditionValue.byteBlob=app;
    }
    if (r.kind == RuleKind::All) return;
    auto& p=conditions[1]; p.fieldKey=FWPM_CONDITION_IP_PROTOCOL;
    p.matchType=r.kind==RuleKind::NonTcp ? FWP_MATCH_NOT_EQUAL : FWP_MATCH_EQUAL;
    p.conditionValue.type=FWP_UINT8; p.conditionValue.uint8=6;
    filter.numFilterConditions=2;
    if (r.kind == RuleKind::NonTcp) return;
    auto& x=conditions[2]; x.matchType=FWP_MATCH_NOT_EQUAL;
    if (r.kind==RuleKind::WrongAddress) {
      x.fieldKey=FWPM_CONDITION_IP_REMOTE_ADDRESS;
      x.conditionValue.type=FWP_UINT32; x.conditionValue.uint32=0x7f000001;
    } else {
      x.fieldKey=FWPM_CONDITION_IP_REMOTE_PORT;
      x.conditionValue.type=FWP_UINT16; x.conditionValue.uint16=r.port;
    }
    filter.numFilterConditions=3;
  }
};
bool sameValue(const FWP_CONDITION_VALUE0& a,const FWP_CONDITION_VALUE0& b) {
  if(a.type!=b.type) return false;
  switch(a.type) {
    case FWP_UINT8:return a.uint8==b.uint8;
    case FWP_UINT16:return a.uint16==b.uint16;
    case FWP_UINT32:return a.uint32==b.uint32;
    case FWP_SID:return a.sid && b.sid && IsValidSid(a.sid) && IsValidSid(b.sid) &&
      GetLengthSid(a.sid)==GetLengthSid(b.sid) && EqualSid(a.sid,b.sid) &&
      !std::memcmp(a.sid,b.sid,GetLengthSid(a.sid));
    case FWP_BYTE_BLOB_TYPE:return a.byteBlob && b.byteBlob &&
      a.byteBlob->size==b.byteBlob->size &&
      (!a.byteBlob->size || (a.byteBlob->data && b.byteBlob->data &&
       !std::memcmp(a.byteBlob->data,b.byteBlob->data,a.byteBlob->size)));
    default:return false;
  }
}
void exact(const FWPM_FILTER0& actual,const FWPM_FILTER0& wanted) {
  const bool exact_metadata = actual.filterId && eq(actual.filterKey,wanted.filterKey) &&
    ((!actual.providerKey && !wanted.providerKey) || (actual.providerKey && wanted.providerKey && eq(*actual.providerKey,*wanted.providerKey))) &&
    eq(actual.subLayerKey,wanted.subLayerKey) &&
    eq(actual.layerKey,wanted.layerKey) && actual.flags==wanted.flags &&
    actual.action.type==FWP_ACTION_BLOCK && actual.weight.type==FWP_UINT64 &&
    actual.weight.uint64 && *actual.weight.uint64==*wanted.weight.uint64 &&
    actual.numFilterConditions==wanted.numFilterConditions && actual.filterCondition &&
    actual.providerData.size==0 && actual.rawContext==0;
  if (!exact_metadata) {
    // Diagnostic only, after the unchanged short-circuit predicate rejected.
    // Public WFP scalar metadata only: never AppId bytes, paths or credentials.
    const auto detail = std::string("exact-filter-metadata(flags=") + std::to_string(actual.flags) +
      ",wanted-flags=" + std::to_string(wanted.flags) +
      ",weight-type=" + std::to_string(actual.weight.type) +
      ",weight=" + (actual.weight.type==FWP_UINT64 && actual.weight.uint64 ? std::to_string(*actual.weight.uint64) : "none") +
      ",id=" + std::to_string(actual.filterId) +
      ",provider-present=" + std::to_string(actual.providerKey!=nullptr) +
      ",layer-equal=" + std::to_string(eq(actual.layerKey,wanted.layerKey)) +
      ",action=" + std::to_string(actual.action.type) +
      ",conditions=" + std::to_string(actual.numFilterConditions) +
      ",wanted-conditions=" + std::to_string(wanted.numFilterConditions) +
      ",provider-data-size=" + std::to_string(actual.providerData.size) +
      ",raw-context=" + std::to_string(actual.rawContext) + ")";
    fail(detail.c_str(),ERROR_INVALID_DATA);
  }
  std::array<bool,3> found{};
  for (UINT32 i=0;i<actual.numFilterConditions;++i) {
    bool match=false;
    for (UINT32 j=0;j<wanted.numFilterConditions;++j) {
      const auto& a=actual.filterCondition[i]; const auto& b=wanted.filterCondition[j];
      if (!found[j] && eq(a.fieldKey,b.fieldKey) && a.matchType==b.matchType && sameValue(a.conditionValue,b.conditionValue)) {
        found[j]=true; match=true; break;
      }
    }
    require(match, "exact-condition-match");
  }
}
}
struct NetworkPolicy::Impl {
  const bool package;
  const GUID& provider;
  const GUID& sublayer;
  bool namespaceOwned=false; // Set immediately after the successful commit.
  bool assignedWeightPinned=false;
  std::uint16_t assignedWeight=0; // Written once from BFE, never from configuration.
  std::array<UINT64,7> createdIds{};
  std::vector<BYTE> sidBytes;
  explicit Impl(bool isPackage=false):package(isPackage),
    provider(isPackage ? packageProvider : wfp_prototype::provider),
    sublayer(isPackage ? packageSublayer : wfp_prototype::sublayer) {}
  GUID key(unsigned n) const { return package ? packageKey(n) : wfp_prototype::key(n); }
  PSID sid() { return sidBytes.empty() ? nullptr : sidBytes.data(); }
  HANDLE engine=nullptr, executable=INVALID_HANDLE_VALUE;
  FWP_BYTE_BLOB* app=nullptr;
  enum class Lifecycle { Empty, Installed, Cleaned };
  Lifecycle lifecycle=Lifecycle::Empty;
  Mode mode=Mode::Offline; std::uint16_t port=0;
  std::mutex mutex;
  ~Impl() {
    if(app) FwpmFreeMemory0(reinterpret_cast<void**>(&app));
    if(engine) FwpmEngineClose0(engine);
    if(executable!=INVALID_HANDLE_VALUE) CloseHandle(executable);
  }
  void pinAssignedWeight(std::uint16_t weight) {
    require(!assignedWeightPinned && weight>=0xff00,"sublayer-weight-pin-once");
    assignedWeight=weight; assignedWeightPinned=true;
  }
  std::uint16_t readSublayerWeight(HANDLE snapshotEngine=nullptr) {
    const auto engine=snapshotEngine ? snapshotEngine : this->engine;
    if(package) {
      Memory<FWPM_PROVIDER0> p;
      check("FwpmProviderGetByKey0",FwpmProviderGetByKey0(engine,&provider,&p.p));
      require(eq(p.p->providerKey,provider) && p.p->flags==FWPM_PROVIDER_FLAG_PERSISTENT &&
        p.p->providerData.size==0 && !p.p->serviceName,"package-provider-metadata");
    }
    Memory<FWPM_SUBLAYER0> s;
    check("FwpmSubLayerGetByKey0",FwpmSubLayerGetByKey0(engine,&sublayer,&s.p));
    const bool same=eq(s.p->subLayerKey,sublayer) && s.p->flags==FWPM_SUBLAYER_FLAG_PERSISTENT &&
      (package ? (s.p->providerKey && eq(*s.p->providerKey,provider)) : !s.p->providerKey) &&
      // BFE may choose the closest available weight to our 0xffff request.
      // Retain the highest 256-value band, not an arbitrary lower-priority layer.
      s.p->weight>=0xff00 && s.p->providerData.size==0;
    if(!same){
      const auto detail=std::string("sublayer-scalars(k=")+std::to_string(eq(s.p->subLayerKey,sublayer))+",f="+std::to_string(s.p->flags)+",p="+std::to_string(s.p->providerKey!=nullptr)+",peq="+std::to_string(s.p->providerKey&&eq(*s.p->providerKey,provider))+",w="+std::to_string(s.p->weight)+",d="+std::to_string(s.p->providerData.size)+")";
      fail(detail.c_str(),ERROR_INVALID_DATA);
    }
    return s.p->weight;
  }
  void metadata(HANDLE snapshotEngine=nullptr) {
    require(assignedWeightPinned,"sublayer-weight-unpinned");
    require(readSublayerWeight(snapshotEngine)==assignedWeight,"sublayer-weight-drift");
  }
  std::vector<VerifiedFilter> inventory(Mode expected,std::uint16_t p,bool recovering=false) {
    require((package ? sid()!=nullptr : app!=nullptr) && engine, "inventory-app-engine");
    std::uint16_t recoveryWeight=0;
    if(recovering) {
      require(!package && lifecycle==Lifecycle::Empty && !assignedWeightPinned,"sublayer-weight-recovery-state");
      recoveryWeight=readSublayerWeight();
    } else metadata();
    const auto wanted=policyRules(expected,p);
    std::vector<VerifiedFilter> out;
    HANDLE enumeration=nullptr;
    check("FwpmFilterCreateEnumHandle0",FwpmFilterCreateEnumHandle0(engine,nullptr,&enumeration));
    try {
      for (;;) {
        Memory<FWPM_FILTER0*> batch; UINT32 count=0;
        check("FwpmFilterEnum0",FwpmFilterEnum0(engine,enumeration,128,&batch.p,&count));
        for(UINT32 i=0;i<count;++i) {
          inspectCandidate(*batch.p[i],wanted,out);
        }
        if(count<128) break;
      }
    } catch (...) { FwpmFilterDestroyEnumHandle0(engine,enumeration); throw; }
    check("FwpmFilterDestroyEnumHandle0",FwpmFilterDestroyEnumHandle0(engine,enumeration));
    require(out.size()==wanted.size(), "inventory-missing-filter");
    // Recovery pins only after the complete closed rule set matches this exact
    // retained executable. The surrounding BFE transaction excludes writers.
    if(recovering) pinAssignedWeight(recoveryWeight);
    return out;
  }
  void inspectCandidate(const FWPM_FILTER0& f,const std::vector<Rule>& wanted,std::vector<VerifiedFilter>& out) {
    bool ours=eq(f.subLayerKey,sublayer) || (f.providerKey && eq(*f.providerKey,provider));
    for(unsigned n=0;n<7;++n) ours |= eq(f.filterKey,key(n));
    if(!ours) return;
    auto it=std::find_if(wanted.begin(),wanted.end(),[&](Rule r){return eq(f.filterKey,key(slot(r)));});
    require(it!=wanted.end(), "inventory-unexpected-filter"); NativeRule native(*it,app,sid()); exact(f,native.filter);
    if(package) require(createdIds[slot(*it)]==f.filterId,"package-filter-not-created-by-owner");
    require(std::none_of(out.begin(),out.end(),[&](auto x){return x.rule==*it;}), "inventory-duplicate-filter");
    out.push_back({f.filterId,*it,package ? IdentityScope::ExactAppContainerSid : IdentityScope::ExecutablePath});
  }
  void add(Rule r) {
    NativeRule n(r,app,sid()); UINT64 id=0;
    check("FwpmFilterAdd0",FwpmFilterAdd0(engine,&n.filter,nullptr,&id));
    if(package) createdIds[slot(r)]=id;
  }
  void replace(Mode next,std::uint16_t p) {
    require(lifecycle==Lifecycle::Installed, "replace-lifecycle");
    require(!package || namespaceOwned,"package-not-owned");
    struct RollbackIds {
      std::array<UINT64,7>& target; std::array<UINT64,7> old; bool committed=false;
      ~RollbackIds() { if(!committed) target=old; }
    } ids{createdIds,createdIds};
    Transaction tx(engine);
    auto old=inventory(mode,port);
    if(mode!=next || port!=p) {
      for(auto f:old) if(f.rule.layer==Layer::ConnectV4)
        check("FwpmFilterDeleteById0",FwpmFilterDeleteById0(engine,f.filterId));
      for(auto r:policyRules(next,p)) if(r.layer==Layer::ConnectV4) add(r);
    }
    (void)inventory(next,p); tx.commit(); ids.committed=true; mode=next; port=p;
    Transaction readback(engine); (void)inventory(mode,port); readback.commit();
  }
  void cleanup() {
    require(lifecycle==Lifecycle::Installed && (!package || namespaceOwned), "cleanup-lifecycle");
    Transaction tx(engine);
    auto owned=inventory(mode,port);
    for(auto f:owned) check("FwpmFilterDeleteById0",FwpmFilterDeleteById0(engine,f.filterId));
    check("FwpmSubLayerDeleteByKey0",FwpmSubLayerDeleteByKey0(engine,&sublayer));
    if(package) check("FwpmProviderDeleteByKey0",FwpmProviderDeleteByKey0(engine,&provider));
    tx.commit();
    if(package) { namespaceOwned=false; lifecycle=Lifecycle::Cleaned; }
    Transaction absence(engine);
    Memory<FWPM_SUBLAYER0> readback;
    require(FwpmSubLayerGetByKey0(engine,&sublayer,&readback.p)==static_cast<DWORD>(FWP_E_SUBLAYER_NOT_FOUND), "cleanup-sublayer-absence");
    if(package) {
      Memory<FWPM_PROVIDER0> p;
      require(FwpmProviderGetByKey0(engine,&provider,&p.p)==static_cast<DWORD>(FWP_E_PROVIDER_NOT_FOUND),"cleanup-provider-absence");
    }
    for(unsigned n=0;n<7;++n) {
      Memory<FWPM_FILTER0> f; auto k=key(n);
      require(FwpmFilterGetByKey0(engine,&k,&f.p)==static_cast<DWORD>(FWP_E_FILTER_NOT_FOUND), "cleanup-filter-absence");
    }
    absence.commit(); lifecycle=Lifecycle::Cleaned;
  }
};
NetworkPolicy::NetworkPolicy():impl_(std::make_unique<Impl>()) {}
NetworkPolicy::~NetworkPolicy()=default;
void NetworkPolicy::installOffline(const std::wstring& path) {
  auto& s=*impl_; std::lock_guard lock(s.mutex);
  // Canonical local DOS path only. No UNC/device/relative/ADS/dot aliases.
  require(path.size()>14 && path[1]==L':' && path[2]==L'\\' &&
    ((path[0]>=L'A' && path[0]<=L'Z') || (path[0]>=L'a' && path[0]<=L'z')) &&
    path.substr(path.size()-11)==L"\\client.exe" && path.find(L'/',0)==std::wstring::npos &&
    path.find(L':',2)==std::wstring::npos && path.find(L'\0')==std::wstring::npos, "install-path-grammar");
  std::size_t start=3;
  while(start<path.size()) {
    auto end=path.find(L'\\',start); if(end==std::wstring::npos) end=path.size();
    auto component=path.substr(start,end-start);
    require(!component.empty() && component!=L"." && component!=L".." && component.back()!=L'.' && component.back()!=L' ', "install-path-component");
    start=end+1;
  }
  if(s.lifecycle==Impl::Lifecycle::Installed) {
    Memory<FWP_BYTE_BLOB> candidate;
    check("FwpmGetAppIdFromFileName0",FwpmGetAppIdFromFileName0(path.c_str(),&candidate.p));
    require(candidate.p->size==s.app->size && !std::memcmp(candidate.p->data,s.app->data,s.app->size), "install-existing-app-id");
    s.replace(Mode::Offline,0); return;
  }
  require(s.lifecycle==Impl::Lifecycle::Empty && !s.app && !s.engine && s.executable==INVALID_HANDLE_VALUE, "install-empty-lifecycle");
  s.executable=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
  if(s.executable==INVALID_HANDLE_VALUE) fail("CreateFileW",GetLastError());
  BY_HANDLE_FILE_INFORMATION info{};
  if(!GetFileInformationByHandle(s.executable,&info)) fail("GetFileInformationByHandle",GetLastError());
  require(!(info.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY)) && info.nNumberOfLinks==1, "install-file-metadata");
  std::vector<wchar_t> resolved(32768);
  DWORD length=GetFinalPathNameByHandleW(s.executable,resolved.data(),static_cast<DWORD>(resolved.size()),FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
  if(!length) fail("GetFinalPathNameByHandleW",GetLastError());
  require(length<resolved.size() && std::wstring(resolved.data())==L"\\\\?\\"+path, "install-final-path");
  check("FwpmGetAppIdFromFileName0",FwpmGetAppIdFromFileName0(path.c_str(),&s.app));
  check("FwpmEngineOpen0",FwpmEngineOpen0(nullptr,RPC_C_AUTHN_WINNT,nullptr,nullptr,&s.engine));
  Transaction tx(s.engine);
  Memory<FWPM_SUBLAYER0> existing;
  DWORD result=FwpmSubLayerGetByKey0(s.engine,&sublayer,&existing.p);
  if(result==static_cast<DWORD>(FWP_E_SUBLAYER_NOT_FOUND)) {
    FWPM_SUBLAYER0 l{}; l.subLayerKey=sublayer;
    l.flags=FWPM_SUBLAYER_FLAG_PERSISTENT; l.weight=0xffff;
    l.displayData.name=const_cast<wchar_t*>(L"OrangeSpace single prototype");
    check("FwpmSubLayerAdd0",FwpmSubLayerAdd0(s.engine,&l,nullptr));
    s.pinAssignedWeight(s.readSublayerWeight());
    for(auto r:policyRules(Mode::Offline,0)) s.add(r);
  } else {
    check("FwpmSubLayerGetByKey0",result);
    // Restart recovery accepts ONLY an exact offline set or an exact proxy set.
    Memory<FWPM_FILTER0> portFilter; auto k=key(6);
    result=FwpmFilterGetByKey0(s.engine,&k,&portFilter.p);
    if(!result) {
      for(UINT32 i=0;i<portFilter.p->numFilterConditions;++i) {
        const auto& c=portFilter.p->filterCondition[i];
        if(eq(c.fieldKey,FWPM_CONDITION_IP_REMOTE_PORT) && c.conditionValue.type==FWP_UINT16) s.port=c.conditionValue.uint16;
      }
      (void)s.inventory(Mode::ProxyOnly,s.port,true);
      auto old=s.inventory(Mode::ProxyOnly,s.port);
      for(auto f:old) if(f.rule.layer==Layer::ConnectV4)
        check("FwpmFilterDeleteById0",FwpmFilterDeleteById0(s.engine,f.filterId));
      s.add({Layer::ConnectV4,RuleKind::All}); s.port=0;
    } else { check("FwpmFilterGetByKey0",result==static_cast<DWORD>(FWP_E_FILTER_NOT_FOUND) ? ERROR_SUCCESS : result); (void)s.inventory(Mode::Offline,0,true); }
  }
  (void)s.inventory(Mode::Offline,0); tx.commit(); s.mode=Mode::Offline; s.port=0;
  Transaction readback(s.engine); (void)s.inventory(Mode::Offline,0); readback.commit();
  s.lifecycle=Impl::Lifecycle::Installed;
}
void NetworkPolicy::switchToProxyOnly(std::uint16_t port) {
  auto& s=*impl_; std::lock_guard lock(s.mutex); require(port!=0, "proxy-port"); s.replace(Mode::ProxyOnly,port);
}
void NetworkPolicy::restoreOffline() {
  auto& s=*impl_; std::lock_guard lock(s.mutex); s.replace(Mode::Offline,0);
}
std::vector<VerifiedFilter> NetworkPolicy::verifyExactPolicy(Mode expected,std::uint16_t port) {
  auto& s=*impl_; std::lock_guard lock(s.mutex);
  require(s.lifecycle==Impl::Lifecycle::Installed, "verify-lifecycle");
  Transaction tx(s.engine);
  auto result=s.inventory(expected,port); tx.commit(); return result;
}
void NetworkPolicy::withPairedSnapshot(PackageNetworkPolicy& package,Mode expected,std::uint16_t port,
  const std::function<void(HANDLE,const std::vector<VerifiedFilter>&)>& callback) {
  auto& s=*impl_; auto& t=*package.impl_;
  std::scoped_lock lock(s.mutex,t.mutex);
  require(s.lifecycle==Impl::Lifecycle::Installed,"verify-lifecycle");
  require(t.namespaceOwned && t.lifecycle==Impl::Lifecycle::Installed,"package-verify-lifecycle");
  require(s.app && s.engine && t.sid() && t.engine,"inventory-app-engine");
  Transaction tx(s.engine);
  s.metadata(s.engine); t.metadata(s.engine);
  const auto wanted=policyRules(expected,port), packageWanted=policyRules(expected,port);
  std::vector<VerifiedFilter> out,packaged;
  HANDLE enumeration=nullptr;
  check("FwpmFilterCreateEnumHandle0",FwpmFilterCreateEnumHandle0(s.engine,nullptr,&enumeration));
  try {
    for (;;) {
      Memory<FWPM_FILTER0*> batch; UINT32 count=0;
      check("FwpmFilterEnum0",FwpmFilterEnum0(s.engine,enumeration,128,&batch.p,&count));
      for(UINT32 i=0;i<count;++i) {
        const auto& f=*batch.p[i];
        s.inspectCandidate(f,wanted,out);
        t.inspectCandidate(f,packageWanted,packaged);
      }
      if(count<128) break;
    }
  } catch (...) { FwpmFilterDestroyEnumHandle0(s.engine,enumeration); throw; }
  check("FwpmFilterDestroyEnumHandle0",FwpmFilterDestroyEnumHandle0(s.engine,enumeration));
  require(out.size()==wanted.size() && packaged.size()==packageWanted.size(),"inventory-missing-filter");
  out.insert(out.end(),packaged.begin(),packaged.end());
  callback(s.engine,out);
  tx.commit();
}
void NetworkPolicy::cleanupAfterExactTreeExit() {
  auto& s=*impl_; std::lock_guard lock(s.mutex);
  s.cleanup();
}
PackageNetworkPolicy::PackageNetworkPolicy():impl_(std::make_unique<NetworkPolicy::Impl>(true)) {}
PackageNetworkPolicy::~PackageNetworkPolicy()=default;
void PackageNetworkPolicy::installOffline(PSID exactAppContainerSid) {
  auto& s=*impl_; std::lock_guard lock(s.mutex);
  using Impl=NetworkPolicy::Impl;
  validatePackageSid(exactAppContainerSid);
  if(s.lifecycle==Impl::Lifecycle::Installed) {
    require(s.namespaceOwned && EqualSid(s.sid(),exactAppContainerSid),"package-existing-sid");
    s.replace(Mode::Offline,0); return;
  }
  require(s.lifecycle==Impl::Lifecycle::Empty && !s.engine && s.sidBytes.empty(),"package-empty-lifecycle");
  s.sidBytes.resize(GetLengthSid(exactAppContainerSid));
  if(!CopySid(static_cast<DWORD>(s.sidBytes.size()),s.sid(),exactAppContainerSid)) fail("CopySid",GetLastError());
  check("FwpmEngineOpen0",FwpmEngineOpen0(nullptr,RPC_C_AUTHN_WINNT,nullptr,nullptr,&s.engine));
  Transaction tx(s.engine);
  Memory<FWPM_PROVIDER0> existingProvider;
  require(FwpmProviderGetByKey0(s.engine,&s.provider,&existingProvider.p)==static_cast<DWORD>(FWP_E_PROVIDER_NOT_FOUND),"package-namespace-not-fresh-provider");
  Memory<FWPM_SUBLAYER0> existingSublayer;
  require(FwpmSubLayerGetByKey0(s.engine,&s.sublayer,&existingSublayer.p)==static_cast<DWORD>(FWP_E_SUBLAYER_NOT_FOUND),"package-namespace-not-fresh-sublayer");
  for(unsigned n=0;n<7;++n) {
    Memory<FWPM_FILTER0> f; auto k=s.key(n);
    require(FwpmFilterGetByKey0(s.engine,&k,&f.p)==static_cast<DWORD>(FWP_E_FILTER_NOT_FOUND),"package-namespace-not-fresh-filter");
  }
  FWPM_PROVIDER0 p{}; p.providerKey=s.provider; p.flags=FWPM_PROVIDER_FLAG_PERSISTENT;
  p.displayData.name=const_cast<wchar_t*>(L"OrangeSpace prototype exact package deny");
  check("FwpmProviderAdd0",FwpmProviderAdd0(s.engine,&p,nullptr));
  FWPM_SUBLAYER0 l{}; l.subLayerKey=s.sublayer; l.providerKey=const_cast<GUID*>(&s.provider);
  l.flags=FWPM_SUBLAYER_FLAG_PERSISTENT; l.weight=0xffff; l.displayData.name=p.displayData.name;
  check("FwpmSubLayerAdd0",FwpmSubLayerAdd0(s.engine,&l,nullptr));
  s.pinAssignedWeight(s.readSublayerWeight());
  for(auto r:policyRules(Mode::Offline,0)) s.add(r);
  (void)s.inventory(Mode::Offline,0);
  tx.commit();
  // No fallible work between successful commit and recording ownership. If the
  // subsequent readback fails, caller can still restore deny / explicitly clean.
  s.namespaceOwned=true; s.lifecycle=Impl::Lifecycle::Installed;
  s.mode=Mode::Offline; s.port=0;
  Transaction readback(s.engine); (void)s.inventory(Mode::Offline,0); readback.commit();
}
void PackageNetworkPolicy::switchToProxyOnly(std::uint16_t port) {
  auto& s=*impl_; std::lock_guard lock(s.mutex); require(port!=0,"proxy-port"); s.replace(Mode::ProxyOnly,port);
}
void PackageNetworkPolicy::restoreOffline() {
  auto& s=*impl_; std::lock_guard lock(s.mutex); s.replace(Mode::Offline,0);
}
std::vector<VerifiedFilter> PackageNetworkPolicy::verifyExactPolicy(Mode expected,std::uint16_t port) {
  auto& s=*impl_; std::lock_guard lock(s.mutex);
  require(s.namespaceOwned && s.lifecycle==NetworkPolicy::Impl::Lifecycle::Installed,"package-verify-lifecycle");
  Transaction tx(s.engine); auto result=s.inventory(expected,port); tx.commit(); return result;
}
void PackageNetworkPolicy::cleanupAfterExactTreeExit() {
  auto& s=*impl_; std::lock_guard lock(s.mutex); s.cleanup();
}
}
#endif
