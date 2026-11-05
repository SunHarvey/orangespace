#include "owned_loopback_exemption_win.hpp"
#ifdef _WIN32
#include <netfw.h>
#include <algorithm>
#include <stdexcept>
#include <string>
#include <cstring>
namespace orangespace::wfp_prototype {
namespace {
using Owner=OwnedLoopbackExemption;
struct Api {
  HMODULE module=LoadLibraryExW(L"FirewallAPI.dll",nullptr,LOAD_LIBRARY_SEARCH_SYSTEM32);
  decltype(&NetworkIsolationGetAppContainerConfig) get=nullptr;
  decltype(&NetworkIsolationSetAppContainerConfig) set=nullptr;
  DWORD error=ERROR_SUCCESS;
  Api(){
    if(!module){error=GetLastError();return;}
    auto g=GetProcAddress(module,"NetworkIsolationGetAppContainerConfig");
    auto s=GetProcAddress(module,"NetworkIsolationSetAppContainerConfig");
    static_assert(sizeof(g)==sizeof(get)&&sizeof(s)==sizeof(set));
    std::memcpy(&get,&g,sizeof(get));std::memcpy(&set,&s,sizeof(set));
    if(!get||!set)error=ERROR_PROC_NOT_FOUND;
  }
  ~Api(){if(module)FreeLibrary(module);}
};
// Microsoft Learn GetAppContainerConfig's FreeAppContainerConfig sample:
// HeapFree each Sid THEN HeapFree array. NOT NetworkIsolationFreeAppContainers.
struct Config {
  DWORD count=0; PSID_AND_ATTRIBUTES entries=nullptr;
  ~Config() { if(entries) { for(DWORD i=0;i<count;++i) HeapFree(GetProcessHeap(),0,entries[i].Sid); HeapFree(GetProcessHeap(),0,entries); } }
};
bool contains(const Owner::Snapshot& list, const std::vector<BYTE>& sid) {
  return std::any_of(list.begin(),list.end(),[&](const auto& x){return x.sid==sid;});
}
DWORD write(Owner::Snapshot& list) {
  std::vector<SID_AND_ATTRIBUTES> native; native.reserve(list.size());
  for(auto& e:list) native.push_back({e.sid.data(),e.attributes});
  Api api;if(api.error)return api.error;
  return api.set(static_cast<DWORD>(native.size()),native.empty()?nullptr:native.data());
}
}
DWORD OwnedLoopbackExemption::read(Snapshot& out) {
  Api api;if(api.error)return api.error;
  Config c; DWORD e=api.get(&c.count,&c.entries);
  if(e) return e;
  if((c.count&&!c.entries)||c.count>65536) return ERROR_INVALID_DATA;
  Snapshot next; next.reserve(c.count);
  for(DWORD i=0;i<c.count;++i) {
    auto s=c.entries[i].Sid; if(!s||!IsValidSid(s)) return ERROR_INVALID_SID;
    auto p=static_cast<const BYTE*>(s);
    next.push_back({std::vector<BYTE>(p,p+GetLengthSid(s)),c.entries[i].Attributes});
  }
  out=std::move(next); return ERROR_SUCCESS;
}
bool OwnedLoopbackExemption::equivalent(Snapshot a,Snapshot b) {
  auto less=[](const Entry& x,const Entry& y){return x.sid==y.sid?x.attributes<y.attributes:x.sid<y.sid;};
  std::sort(a.begin(),a.end(),less); std::sort(b.begin(),b.end(),less); return a==b;
}
OwnedLoopbackExemption::OwnedLoopbackExemption(PSID sid) {
  const SID_IDENTIFIER_AUTHORITY packageAuthority={{0,0,0,0,0,15}};
  if(!sid||!IsValidSid(sid)||*GetSidSubAuthorityCount(sid)!=8 ||
     std::memcmp(GetSidIdentifierAuthority(sid),&packageAuthority,sizeof(packageAuthority)) ||
     *GetSidSubAuthority(sid,0)!=SECURITY_APP_PACKAGE_BASE_RID)
    throw std::runtime_error("unique-package-sid-required");
  auto p=static_cast<const BYTE*>(sid);sid_.assign(p,p+GetLengthSid(sid));
  DWORD e=read(baseline_); if(e) throw std::runtime_error("NetworkIsolationGetAppContainerConfig:"+std::to_string(e));
  if(contains(baseline_,sid_)) throw std::runtime_error("refuse-preexisting-loopback-SID");
}
OwnedLoopbackExemption::Receipt OwnedLoopbackExemption::appendAfterVerifiedWfp() {
  Receipt r; Snapshot now;
  r.getBefore=read(now); if(r.getBefore) return r;
  if(attempted_||!equivalent(now,baseline_)||contains(now,sid_)){r.getBefore=ERROR_INVALID_STATE;return r;}
  now.push_back({sid_,0});
  // Prepare payload before publishing mutation ownership. Always read back even
  // on Set error: an error is NOT proof the external write had no effect.
  attempted_=true;r.setAttempted=true; r.set=write(now);
  Snapshot after;r.getAfter=read(after);r.exact=!r.set&&!r.getAfter&&equivalent(now,after);return r;
}
OwnedLoopbackExemption::Receipt OwnedLoopbackExemption::removeOnlyOwned() {
  Receipt r;Snapshot now;r.getBefore=read(now);if(r.getBefore)return r;
  if(!attempted_){r.exact=equivalent(now,baseline_);return r;}
  // Never replay the old baseline: preserve EVERY currently present other SID,
  // including privileged-writer additions/drift. Remove our unique SID only.
  now.erase(std::remove_if(now.begin(),now.end(),[&](const Entry& e){return e.sid==sid_;}),now.end());
  Snapshot before;r.getBefore=read(before);if(r.getBefore)return r;
  auto expected=before;expected.erase(std::remove_if(expected.begin(),expected.end(),[&](const Entry& e){return e.sid==sid_;}),expected.end());
  if(!equivalent(now,expected)){r.getBefore=ERROR_INVALID_STATE;return r;}
  if(contains(before,sid_)){r.setAttempted=true;r.set=write(now);}
  Snapshot after;r.getAfter=read(after);r.exact=!r.set&&!r.getAfter&&equivalent(now,after)&&!contains(after,sid_);
  return r;
}
}
#endif
