#include "service_binding.hpp"
#include "fresh_rule_inspection.hpp"
#include "online_control_win.hpp"
#include "orangespace/prototype_namespace.hpp"
#include <atomic>
#include "../../windows-client/prototype/private_channel.hpp"
#include "owned_loopback_exemption_win.hpp"
#ifndef ORANGESPACE_PROTOTYPE_NODE_UUID
#error Trusted SG node build parameter required
#endif

#include "orangespace/windows_service.hpp"
#include "network_policy_win.hpp"
#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <sddl.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <fwpmu.h>
#include <shlobj.h>
#include <thread>
#include <mutex>
#include <future>
#include "orangespace/process_observation_acl.hpp"
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <array>
#include <vector>
#include <string>
#include <algorithm>
using orangespace::service::win::Handle;
using orangespace::service::win::token_peer;
namespace p=orangespace::prototype;
namespace fs=std::filesystem;
namespace {
std::atomic<HANDLE> stop_event{},service_stop_event{}; SERVICE_STATUS_HANDLE scm_handle{};
thread_local const char* stage="entry";
void report_fixed(const char* label,DWORD code){HANDLE log=RegisterEventSourceW(nullptr,p::kService);if(!log)return;wchar_t text[128]{};MultiByteToWideChar(CP_UTF8,0,label,static_cast<int>(std::min<std::size_t>(std::strlen(label),127)),text,127);LPCWSTR strings[]{text};ReportEventW(log,EVENTLOG_ERROR_TYPE,0,1,nullptr,1,sizeof(code),strings,&code);DeregisterEventSource(log);}
const char* fixed_startup_error(const char* message) noexcept {
 if(!message)return nullptr;
 for(const char* fixed:{"protected runtime rejected","trust path is not administrator protected","invalid platform session data","invalid node session data","cannot open protected trust path","cannot read trust ACL","cannot inspect trust ACL","invalid trust ACL","invalid trust ACE","cannot inspect trust path","trust path contains a reparse point or invalid object","invalid trust file size","cannot read trust configuration","incomplete trust configuration"})
  if(std::strcmp(message,fixed)==0)return fixed;
 return nullptr;
}
struct Failure {DWORD code;};
void need(bool ok){if(!ok)throw Failure{GetLastError()?GetLastError():ERROR_INVALID_DATA};}
std::uint64_t birth(HANDLE h){FILETIME a{},b{},c{},d{};need(GetProcessTimes(h,&a,&b,&c,&d)!=0);return (std::uint64_t(a.dwHighDateTime)<<32)|a.dwLowDateTime;}
bool live(HANDLE h){return WaitForSingleObject(h,0)==WAIT_TIMEOUT;}
std::vector<BYTE> info(HANDLE t,TOKEN_INFORMATION_CLASS k){DWORD n=0;GetTokenInformation(t,k,nullptr,0,&n);need(n&&n<=65536);std::vector<BYTE>b(n);need(GetTokenInformation(t,k,b.data(),n,&n)!=0);return b;}
std::wstring sidtext(PSID s){LPWSTR x{};need(ConvertSidToStringSidW(s,&x)!=0);std::wstring out(x);LocalFree(x);return out;}
// Unknown/callback/object ACE semantics are denied, never guessed.
void protected_object(HANDLE h,bool ancestor=false){PSECURITY_DESCRIPTOR sd{};PSID owner{};PACL acl{};
 need(GetSecurityInfo(h,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,nullptr,&acl,nullptr,&sd)==ERROR_SUCCESS);
 struct Free{void*p;~Free(){LocalFree(p);}}free{sd};
 PSID ti{};need(ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",&ti)!=0);Free freeti{ti};
 const auto privileged=[&](PSID s){return p::TrustedAuthority(IsWellKnownSid(s,WinLocalSystemSid)||IsWellKnownSid(s,WinBuiltinAdministratorsSid),EqualSid(s,ti)!=0,ancestor);};
 bool ownerok=owner&&privileged(owner);need(ownerok&&acl&&IsValidAcl(acl));
 for(DWORD i=0;i<acl->AceCount;i++){void* v{};need(GetAce(acl,i,&v)!=0);auto* head=(ACE_HEADER*)v;
  if(head->AceFlags&INHERIT_ONLY_ACE)continue;
  need(head->AceType==ACCESS_ALLOWED_ACE_TYPE||head->AceType==ACCESS_DENIED_ACE_TYPE);
  if(head->AceType==ACCESS_ALLOWED_ACE_TYPE){auto*a=(ACCESS_ALLOWED_ACE*)v;
   constexpr DWORD mut=FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_EA|FILE_WRITE_ATTRIBUTES|FILE_DELETE_CHILD|DELETE|WRITE_DAC|WRITE_OWNER|GENERIC_WRITE|GENERIC_ALL;
   DWORD effective=mut;if(ancestor)effective&=~FILE_APPEND_DATA;need(!(a->Mask&effective)||privileged((PSID)&a->SidStart));}}
 BY_HANDLE_FILE_INFORMATION fi{};need(GetFileInformationByHandle(h,&fi)!=0);need(!(fi.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT));
}
Handle pin(const fs::path& path,bool directory,bool ancestor=false){Handle h(CreateFileW(path.c_str(),GENERIC_READ|READ_CONTROL,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|(directory?FILE_FLAG_BACKUP_SEMANTICS:0),nullptr));need(bool(h));protected_object(h.get(),ancestor);BY_HANDLE_FILE_INFORMATION f{};need(GetFileInformationByHandle(h.get(),&f)!=0);need(directory?bool(f.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY):(!(f.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)&&f.nNumberOfLinks==1));return h;}
std::string digest(HANDLE h){BCRYPT_ALG_HANDLE alg{};BCRYPT_HASH_HANDLE hash{};
 need(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0)==0);
 struct Alg{BCRYPT_ALG_HANDLE h;~Alg(){BCryptCloseAlgorithmProvider(h,0);}}a{alg};
 DWORD n=0,len=0;need(BCryptGetProperty(alg,BCRYPT_OBJECT_LENGTH,(PUCHAR)&len,sizeof(len),&n,0)==0);std::vector<BYTE> obj(len);
 need(BCryptCreateHash(alg,&hash,obj.data(),len,nullptr,0,0)==0);
 struct Hash{BCRYPT_HASH_HANDLE h;~Hash(){BCryptDestroyHash(h);}}hh{hash};
 LARGE_INTEGER zero{};need(SetFilePointerEx(h,zero,nullptr,FILE_BEGIN)!=0);std::array<BYTE,65536>b{};DWORD got=0;
 do{need(ReadFile(h,b.data(),DWORD(b.size()),&got,nullptr)!=0);if(got)need(BCryptHashData(hash,b.data(),got,0)==0);}while(got);
 std::array<BYTE,32>d{};need(BCryptFinishHash(hash,d.data(),DWORD(d.size()),0)==0);std::string out;for(auto c:d){out+="0123456789abcdef"[c>>4];out+="0123456789abcdef"[c&15];}return out;
}
struct Runtime {
 fs::path dir,exe;std::vector<Handle> pins;std::map<std::wstring,std::string> hashes;
 Runtime(){stage="runtime-inventory";wchar_t module[32768]{};DWORD n=GetModuleFileNameW(nullptr,module,32768);need(n&&n<32768);dir=fs::path(module).parent_path();exe=dir/L"client.exe";
  auto ancestor=dir;for(;;){pins.push_back(pin(ancestor,true,ancestor!=dir));auto next=ancestor.parent_path();if(next==ancestor||next.empty())break;ancestor=next;}
  pins.push_back(pin(dir/L"runtime.inventory.tsv",false));auto h=pins.back().get();LARGE_INTEGER sz{};need(GetFileSizeEx(h,&sz)!=0&&sz.QuadPart>0&&sz.QuadPart<=1048576);
  std::string text(std::size_t(sz.QuadPart),'\0');DWORD read=0;need(ReadFile(h,text.data(),DWORD(text.size()),&read,nullptr)!=0&&read==text.size());
  std::set<std::wstring> listed;std::size_t off=0;unsigned entries=0;
  while(off<text.size()){auto end=text.find('\n',off);need(end!=std::string::npos);auto line=text.substr(off,end-off);off=end+1;auto a=line.find('\t'),b=line.find('\t',a+1);need(a==64&&b!=std::string::npos&&b>a+1&&++entries<=4096);
   auto hash=line.substr(0,a),size=line.substr(a+1,b-a-1),rel=line.substr(b+1);need(hash.find_first_not_of("0123456789abcdef")==std::string::npos&&size.find_first_not_of("0123456789")==std::string::npos&&size.size()<=15);
   need(p::ValidRelative(rel));
   fs::path relative(rel);need(!relative.is_absolute());std::wstring key=relative.generic_wstring();std::transform(key.begin(),key.end(),key.begin(),::towlower);need(listed.insert(key).second);
   auto parent=(dir/relative).parent_path();while(parent!=dir){pins.push_back(pin(parent,true));parent=parent.parent_path();}
   auto file=pin(dir/relative,false);LARGE_INTEGER actual{};need(GetFileSizeEx(file.get(),&actual)!=0&&actual.QuadPart>=0&&std::to_string(actual.QuadPart)==size);need(digest(file.get())==hash);hashes.emplace(key,hash);pins.push_back(std::move(file));
  }
  need(hashes.contains(L"client.exe")&&hashes.contains(L"client.dll")&&hashes.contains(L"libcef.dll"));
  // Closed inventory: no unlisted file can enter DLL/resource loading.
  for(auto const&e:fs::recursive_directory_iterator(dir)){DWORD attr=GetFileAttributesW(e.path().c_str());need(attr!=INVALID_FILE_ATTRIBUTES&&!(attr&FILE_ATTRIBUTE_REPARSE_POINT));if(e.is_directory())continue;auto rel=fs::relative(e.path(),dir).generic_wstring();std::transform(rel.begin(),rel.end(),rel.begin(),::towlower);if(rel==L"runtime.inventory.tsv")continue;need(listed.contains(rel));}
 }
 bool image(HANDLE process){wchar_t path[32768]{};DWORD n=32768;if(!QueryFullProcessImageNameW(process,0,path,&n)||_wcsicmp(path,exe.c_str()))return false;auto h=pin(exe,false);return digest(h.get())==hashes.at(L"client.exe");}
};
struct Session {DWORD id{};Handle token;orangespace::service::Peer peer;std::wstring sid;
 Session(){stage="wts-active-unlocked";PWTS_SESSION_INFOW sessions{};DWORD count=0;need(WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE,0,1,&sessions,&count)!=0);for(DWORD i=0;i<count;i++)if(sessions[i].State==WTSActive){need(!id&&sessions[i].SessionId);id=sessions[i].SessionId;}WTSFreeMemory(sessions);need(id!=0);
  LPWSTR data{};DWORD bytes=0;need(WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,id,WTSSessionInfoEx,&data,&bytes)!=0);auto*x=(WTSINFOEXW*)data;bool unlocked=bytes>=sizeof(WTSINFOEXW)&&x->Level==1&&x->Data.WTSInfoExLevel1.SessionFlags==WTS_SESSIONSTATE_UNLOCK;WTSFreeMemory(data);need(unlocked);
  HANDLE t{};need(WTSQueryUserToken(id,&t)!=0);token=Handle(t);
  auto primary=info(t,TokenType);need(primary.size()==sizeof(TOKEN_TYPE)&&*(TOKEN_TYPE*)primary.data()==TokenPrimary);
  stage="wts-ordinary-token";auto elevation=info(t,TokenElevation),app=info(t,TokenIsAppContainer),caps=info(t,TokenCapabilities);
  need(elevation.size()==sizeof(TOKEN_ELEVATION)&&app.size()==sizeof(DWORD)&&caps.size()>=sizeof(DWORD));
  need(!((TOKEN_ELEVATION*)elevation.data())->TokenIsElevated&&!*(DWORD*)app.data()&&((TOKEN_GROUPS*)caps.data())->GroupCount==0);
  peer=token_peer(t);need(peer.session==id&&peer.logon);auto user=info(t,TokenUser);sid=sidtext(((TOKEN_USER*)user.data())->User.Sid);
 }
 bool same(){const char* caller=stage;struct Restore{const char*s;~Restore(){stage=s;}}restore{caller};try{Session now;return now.id==id&&now.peer.sid==peer.sid&&now.peer.logon==peer.logon;}catch(...){return false;}}
};
std::vector<wchar_t> environment(Session&s,PSID package){
 wchar_t win[32768]{},sys[32768]{};need(GetWindowsDirectoryW(win,32768)&&GetSystemDirectoryW(sys,32768));
 DWORD n=32768;std::vector<wchar_t> home(n);need(GetUserProfileDirectoryW(s.token.get(),home.data(),&n)!=0);
 PWSTR local{},roaming{};need(SHGetKnownFolderPath(FOLDERID_LocalAppData,0,s.token.get(),&local)==S_OK);need(SHGetKnownFolderPath(FOLDERID_RoamingAppData,0,s.token.get(),&roaming)==S_OK);
 struct Free{PWSTR a,b;~Free(){CoTaskMemFree(a);CoTaskMemFree(b);}}free{local,roaming};
 need(ImpersonateLoggedOnUser(s.token.get())!=0);bool ok=false;fs::path temp;PWSTR folder{};try{auto sid=sidtext(package);if(GetAppContainerFolderPath(sid.c_str(),&folder)==S_OK){
  // Validate the OS-selected package and every non-root ancestor as the WTS user,
  // before launch: cap0 cannot query attributes outside its private package.
  for(auto path=fs::path(folder);!path.empty()&&path!=path.root_path();path=path.parent_path()){
   const auto attributes=GetFileAttributesW(path.c_str());need(attributes!=INVALID_FILE_ATTRIBUTES&&!(attributes&FILE_ATTRIBUTE_REPARSE_POINT)&&(attributes&FILE_ATTRIBUTE_DIRECTORY));
  }
  temp=fs::path(folder)/L"Temp";fs::create_directories(temp);ok=true;}}catch(...){}if(folder)CoTaskMemFree(folder);BOOL reverted=RevertToSelf();need(ok&&reverted);
 std::map<std::wstring,std::wstring> values{{L"SystemRoot",win},{L"WINDIR",win},{L"PATH",sys},{L"USERPROFILE",home.data()},{L"LOCALAPPDATA",local},{L"APPDATA",roaming},{L"TEMP",temp.wstring()},{L"TMP",temp.wstring()}};
 std::vector<wchar_t> result;for(auto&[k,v]:values){auto x=k+L"="+v;result.insert(result.end(),x.begin(),x.end());result.push_back(0);}result.push_back(0);return result;
}
struct Root {
 Handle job,process,thread;PSID package{};std::wstring profile;bool created=false,exited=false;DWORD pid{};std::uint64_t created_at{};std::array<BYTE,16> cookie{};std::uint64_t generation{},epoch{};
 ~Root(){if(process){DWORD code=STILL_ACTIVE;if(GetExitCodeProcess(process.get(),&code)&&code!=STILL_ACTIVE)report_fixed("root-exit-before-cleanup",code);}if(job)TerminateJobObject(job.get(),71);if(process&&live(process.get())){TerminateProcess(process.get(),71);WaitForSingleObject(process.get(),5000);}if(process&&WaitForSingleObject(process.get(),5000)==WAIT_OBJECT_0){JOBOBJECT_BASIC_ACCOUNTING_INFORMATION a{};exited=QueryInformationJobObject(job.get(),JobObjectBasicAccountingInformation,&a,sizeof(a),nullptr)&&a.ActiveProcesses==0;}if(created&&(!process||exited)){// Only a new known profile, under its original user's token context (caller owns context).
   // Cleanup context is deliberately not guessed here; retain profile for operator recovery.
  }if(package)FreeSid(package);}
 void prepare_identity(Runtime&r,Session&s,std::string_view sandbox){stage="appcontainer-create";
  // Engine.start already validated the protected namespace's OS SID + central
  // owner of this UUID. No caller-supplied profile/path is accepted here.
  need(orangespace::service::chain::nd::uuid(sandbox));
  auto paths=orangespace::service::win::prototype_namespace_paths(r.dir.wstring()+L"\\");
  auto anchor=pin(paths.anchor,false);auto state_dir=pin(fs::path(paths.anchor).parent_path(),true);
  const auto namespace_hash=digest(anchor.get());
  std::string central;
  {auto ledger=pin(paths.state,false);LARGE_INTEGER size{};need(GetFileSizeEx(ledger.get(),&size)&&size.QuadPart>0&&size.QuadPart<=1048576);std::string text(static_cast<std::size_t>(size.QuadPart),'\0');DWORD n{};need(ReadFile(ledger.get(),text.data(),DWORD(text.size()),&n,nullptr)&&n==text.size());for(const auto& row:orangespace::service::chain::parse_state(text))if(row.sandbox==sandbox){need(row.sid==s.peer.sid&&orangespace::service::chain::nd::uuid(row.central_user));central=row.central_user;}need(!central.empty());}
  std::string key=namespace_hash+"|"+std::string(s.sid.begin(),s.sid.end())+"|"+central+"|"+std::string(sandbox);
  BCRYPT_ALG_HANDLE alg{};need(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0)==0);std::array<BYTE,32> hashed{};
  const auto hashed_ok=BCryptHash(alg,nullptr,0,reinterpret_cast<PUCHAR>(key.data()),DWORD(key.size()),hashed.data(),DWORD(hashed.size()));BCryptCloseAlgorithmProvider(alg,0);need(hashed_ok==0);
  profile=L"OS.SG.";for(std::size_t i=0;i<24;++i){profile+=L"0123456789abcdef"[hashed[i]>>4];profile+=L"0123456789abcdef"[hashed[i]&15];}
  auto marker=fs::path(paths.anchor).parent_path()/(profile+L".profile");const auto expected=key+"\n"+std::string(profile.begin(),profile.end());
  DWORD marker_attrs=GetFileAttributesW(marker.c_str());const bool reuse=marker_attrs!=INVALID_FILE_ATTRIBUTES;
  if(reuse){auto held=pin(marker,false);LARGE_INTEGER size{};need(GetFileSizeEx(held.get(),&size)&&size.QuadPart==static_cast<LONGLONG>(expected.size()));std::string bytes(expected.size(),'\0');DWORD n{};need(ReadFile(held.get(),bytes.data(),DWORD(bytes.size()),&n,nullptr)&&n==bytes.size()&&bytes==expected);}
  else need(GetLastError()==ERROR_FILE_NOT_FOUND);
  need(ImpersonateLoggedOnUser(s.token.get())!=0);HRESULT hr=CreateAppContainerProfile(profile.c_str(),L"OrangeSpace Singapore",L"Owned persistent sandbox",nullptr,0,&package);BOOL reverted=RevertToSelf();need(reverted);
  if(reuse){need(hr==HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS));need(DeriveAppContainerSidFromAppContainerName(profile.c_str(),&package)==S_OK);}
  else {need(hr==S_OK);PSECURITY_DESCRIPTOR sd{};need(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)",SDDL_REVISION_1,&sd,nullptr));SECURITY_ATTRIBUTES sa{sizeof(sa),sd,FALSE};Handle leaf(CreateFileW(marker.c_str(),GENERIC_WRITE,0,&sa,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr));LocalFree(sd);need(bool(leaf));DWORD n{};need(WriteFile(leaf.get(),expected.data(),DWORD(expected.size()),&n,nullptr)&&n==expected.size()&&FlushFileBuffers(leaf.get()));}
  created=true;
 }
 void launch_suspended(Runtime&r,Session&s) {
  need(created&&package&&!job&&!process&&!thread);
  need(BCryptGenRandom(nullptr,cookie.data(),DWORD(cookie.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG)==0&&p::Nonzero(cookie));need(BCryptGenRandom(nullptr,(PUCHAR)&generation,sizeof(generation),BCRYPT_USE_SYSTEM_PREFERRED_RNG)==0&&generation);need(BCryptGenRandom(nullptr,(PUCHAR)&epoch,sizeof(epoch),BCRYPT_USE_SYSTEM_PREFERRED_RNG)==0&&epoch);stage="root-private-job";job=Handle(CreateJobObjectW(nullptr,nullptr));need(bool(job));JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;need(SetInformationJobObject(job.get(),JobObjectExtendedLimitInformation,&limits,sizeof(limits))!=0);
  SECURITY_CAPABILITIES caps{};caps.AppContainerSid=package;caps.Capabilities=nullptr;caps.CapabilityCount=0;
  SIZE_T size=0;InitializeProcThreadAttributeList(nullptr,1,0,&size);std::vector<BYTE> storage(size);auto attrs=(PPROC_THREAD_ATTRIBUTE_LIST)storage.data();need(InitializeProcThreadAttributeList(attrs,1,0,&size)!=0);struct Attributes{PPROC_THREAD_ATTRIBUTE_LIST p;~Attributes(){DeleteProcThreadAttributeList(p);}}owned{attrs};need(UpdateProcThreadAttribute(attrs,0,PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,&caps,sizeof(caps),nullptr,nullptr)!=0);
  STARTUPINFOEXW si{};si.StartupInfo.cb=sizeof(si);si.StartupInfo.lpDesktop=const_cast<LPWSTR>(L"winsta0\\default");si.lpAttributeList=attrs;PROCESS_INFORMATION pi{};std::wstring command=L"\""+r.exe.wstring()+L"\"";
  auto env=environment(s,package);stage="CreateProcessAsUserW-lowbox";
  // Resolve the already-created per-user AppContainer in that OS user's context.
  // Retain the suspended process before any fallible post-create check.
  need(ImpersonateLoggedOnUser(s.token.get())!=0);
  BOOL made=CreateProcessAsUserW(s.token.get(),r.exe.c_str(),command.data(),nullptr,nullptr,FALSE,CREATE_SUSPENDED|EXTENDED_STARTUPINFO_PRESENT|CREATE_UNICODE_ENVIRONMENT,env.data(),r.dir.c_str(),&si.StartupInfo,&pi);
  DWORD create_error=made?ERROR_SUCCESS:GetLastError();BOOL create_reverted=RevertToSelf();
  if(!made)throw Failure{create_error?create_error:ERROR_INVALID_DATA};
  process=Handle(pi.hProcess);thread=Handle(pi.hThread);pid=pi.dwProcessId;need(create_reverted!=0);created_at=birth(process.get());
  stage="AssignProcessToJobObject";if(!AssignProcessToJobObject(job.get(),process.get())){TerminateProcess(process.get(),71);throw Failure{GetLastError()};}need(contained(process.get())&&r.image(process.get()));
 }
 bool contained(HANDLE h){
  BOOL in=FALSE;if(!IsProcessInJob(h,job.get(),&in)||!in){report_fixed("peer-not-in-owned-job",GetProcessId(h));return false;}
  HANDLE raw{};if(!OpenProcessToken(h,TOKEN_QUERY,&raw)){report_fixed("peer-token-query-failed",GetLastError());return false;}
  Handle t(raw);auto ac=info(t.get(),TokenIsAppContainer),sid=info(t.get(),TokenAppContainerSid),cap=info(t.get(),TokenCapabilities),elevation=info(t.get(),TokenElevation),type=info(t.get(),TokenType);
  need(ac.size()==sizeof(DWORD)&&sid.size()>=sizeof(TOKEN_APPCONTAINER_INFORMATION)&&cap.size()>=sizeof(DWORD)&&elevation.size()==sizeof(TOKEN_ELEVATION)&&type.size()==sizeof(TOKEN_TYPE)&&*(TOKEN_TYPE*)type.data()==TokenPrimary);const DWORD elevated=((TOKEN_ELEVATION*)elevation.data())->TokenIsElevated;
  const bool app=*(DWORD*)ac.data()!=0;auto actual=((TOKEN_APPCONTAINER_INFORMATION*)sid.data())->TokenAppContainer;
  const bool same=actual&&EqualSid(actual,package);const DWORD count=((TOKEN_GROUPS*)cap.data())->GroupCount;
  const bool allowed=app&&same&&count==0&&!elevated;if(!allowed)report_fixed("peer-containment-flags",1u|(app?2u:0u)|(same?4u:0u)|(count==0?8u:0u)|(count<<8));return allowed;
 }
};
// Query-only observation of this Service's token, never duplication/impersonation.
struct TokenObservation {
 // Single-thread scoped owner. Requires quiescent external privileged writers:
 // read/compare/write is NOT a CAS. Existing handles cannot be revoked; these
 // user-SID metadata rights span logons, independently of pipe SID/session/LUID.
 static constexpr SECURITY_INFORMATION query=OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION;
 // Preallocate before mutation: a full ACL also needs the self-relative SD
 // header and owner/group SIDs; SetKernelObjectSecurity retains ACL free space.
 struct Snapshot {std::vector<BYTE> bytes=std::vector<BYTE>(65536+2*SECURITY_MAX_SID_SIZE+sizeof(SECURITY_DESCRIPTOR_RELATIVE));DWORD size{};};
 Handle token;
 Snapshot baseline,expected,current;
 std::vector<BYTE> storage=std::vector<BYTE>(65532);
 bool changed=false,verified=false;
 static void check(bool ok){if(!ok)throw Failure{ERROR_INVALID_DATA};}
 bool read(Snapshot&out,DWORD* native_error=nullptr) noexcept {
  DWORD size{};if(native_error)*native_error=0;
  if(!GetKernelObjectSecurity(token.get(),query,out.bytes.data(),DWORD(out.bytes.size()),&size)){if(native_error)*native_error=GetLastError();return false;}
  if(!size||size>out.bytes.size())return false;
  out.size=size;return IsValidSecurityDescriptor(out.bytes.data())&&GetSecurityDescriptorLength(out.bytes.data())<=size;
 }
 static PACL acl(Snapshot&s){PACL a{};BOOL present{},def{};check(GetSecurityDescriptorDacl(s.bytes.data(),&present,&a,&def)&&present&&a&&IsValidAcl(a));return a;}
 static SECURITY_DESCRIPTOR_CONTROL bits(Snapshot&s){SECURITY_DESCRIPTOR_CONTROL b{};DWORD rev{};check(GetSecurityDescriptorControl(s.bytes.data(),&b,&rev)!=0);return b;}
 static bool same_acl(PACL a,PACL b){
  ACL_SIZE_INFORMATION x{},y{};check(GetAclInformation(a,&x,sizeof(x),AclSizeInformation)&&GetAclInformation(b,&y,sizeof(y),AclSizeInformation));
  return a->AclRevision==b->AclRevision&&a->AceCount==b->AceCount&&x.AclBytesInUse==y.AclBytesInUse&&
   std::memcmp((BYTE*)a+sizeof(ACL),(BYTE*)b+sizeof(ACL),x.AclBytesInUse-sizeof(ACL))==0;
 }
 static bool identity(Snapshot&a,Snapshot&b){
  PSID ao{},bo{},ag{},bg{};BOOL d{};
  check(GetSecurityDescriptorOwner(a.bytes.data(),&ao,&d)&&GetSecurityDescriptorOwner(b.bytes.data(),&bo,&d)&&
   GetSecurityDescriptorGroup(a.bytes.data(),&ag,&d)&&GetSecurityDescriptorGroup(b.bytes.data(),&bg,&d));
  return ao&&bo&&ag&&bg&&IsValidSid(ao)&&IsValidSid(bo)&&IsValidSid(ag)&&IsValidSid(bg)&&EqualSid(ao,bo)&&EqualSid(ag,bg)&&bits(a)==bits(b);
 }
 static bool same(Snapshot&a,Snapshot&b){return identity(a,b)&&same_acl(acl(a),acl(b));}
 static void prepare(SECURITY_DESCRIPTOR&sd,Snapshot&base,PACL a){
  PACL unused{};BOOL present{},def{};
  check(GetSecurityDescriptorDacl(base.bytes.data(),&present,&unused,&def)&&InitializeSecurityDescriptor(&sd,SECURITY_DESCRIPTOR_REVISION)&&SetSecurityDescriptorDacl(&sd,TRUE,a,def));
  constexpr SECURITY_DESCRIPTOR_CONTROL mask=SE_DACL_PROTECTED|SE_DACL_AUTO_INHERITED|SE_DACL_AUTO_INHERIT_REQ;
  check(SetSecurityDescriptorControl(&sd,mask,bits(base)&mask)!=0);
 }
 void diagnose_readback(bool got,DWORD native_error,PACL wanted) noexcept {
  try {
   report_fixed("token-rb-read-ok",got);report_fixed("token-rb-read-error",native_error);
   if(!got)return;
   report_fixed("token-rb-baseline-control",bits(baseline));report_fixed("token-rb-current-control",bits(current));
   PSID bo{},co{},bg{},cg{};BOOL def{};
   const bool owners=GetSecurityDescriptorOwner(baseline.bytes.data(),&bo,&def)&&GetSecurityDescriptorOwner(current.bytes.data(),&co,&def);
   const bool groups=GetSecurityDescriptorGroup(baseline.bytes.data(),&bg,&def)&&GetSecurityDescriptorGroup(current.bytes.data(),&cg,&def);
   report_fixed("token-rb-owner-equal",owners&&bo&&co&&IsValidSid(bo)&&IsValidSid(co)&&EqualSid(bo,co));
   report_fixed("token-rb-group-equal",groups&&bg&&cg&&IsValidSid(bg)&&IsValidSid(cg)&&EqualSid(bg,cg));
   auto actual=acl(current);ACL_SIZE_INFORMATION a{},w{};
   check(GetAclInformation(actual,&a,sizeof(a),AclSizeInformation)&&GetAclInformation(wanted,&w,sizeof(w),AclSizeInformation));
   report_fixed("token-rb-actual-revision",actual->AclRevision);report_fixed("token-rb-wanted-revision",wanted->AclRevision);
   report_fixed("token-rb-actual-count",actual->AceCount);report_fixed("token-rb-wanted-count",wanted->AceCount);
   report_fixed("token-rb-actual-used",a.AclBytesInUse);report_fixed("token-rb-wanted-used",w.AclBytesInUse);
   static constexpr const char* labels[8][9]={
   {"token-rb-0-actual-mask","token-rb-0-wanted-mask","token-rb-0-actual-type","token-rb-0-wanted-type","token-rb-0-actual-flags","token-rb-0-wanted-flags","token-rb-0-actual-size","token-rb-0-wanted-size","token-rb-0-sid-equal"},
   {"token-rb-1-actual-mask","token-rb-1-wanted-mask","token-rb-1-actual-type","token-rb-1-wanted-type","token-rb-1-actual-flags","token-rb-1-wanted-flags","token-rb-1-actual-size","token-rb-1-wanted-size","token-rb-1-sid-equal"},
   {"token-rb-2-actual-mask","token-rb-2-wanted-mask","token-rb-2-actual-type","token-rb-2-wanted-type","token-rb-2-actual-flags","token-rb-2-wanted-flags","token-rb-2-actual-size","token-rb-2-wanted-size","token-rb-2-sid-equal"},
   {"token-rb-3-actual-mask","token-rb-3-wanted-mask","token-rb-3-actual-type","token-rb-3-wanted-type","token-rb-3-actual-flags","token-rb-3-wanted-flags","token-rb-3-actual-size","token-rb-3-wanted-size","token-rb-3-sid-equal"},
   {"token-rb-4-actual-mask","token-rb-4-wanted-mask","token-rb-4-actual-type","token-rb-4-wanted-type","token-rb-4-actual-flags","token-rb-4-wanted-flags","token-rb-4-actual-size","token-rb-4-wanted-size","token-rb-4-sid-equal"},
   {"token-rb-5-actual-mask","token-rb-5-wanted-mask","token-rb-5-actual-type","token-rb-5-wanted-type","token-rb-5-actual-flags","token-rb-5-wanted-flags","token-rb-5-actual-size","token-rb-5-wanted-size","token-rb-5-sid-equal"},
   {"token-rb-6-actual-mask","token-rb-6-wanted-mask","token-rb-6-actual-type","token-rb-6-wanted-type","token-rb-6-actual-flags","token-rb-6-wanted-flags","token-rb-6-actual-size","token-rb-6-wanted-size","token-rb-6-sid-equal"},
   {"token-rb-7-actual-mask","token-rb-7-wanted-mask","token-rb-7-actual-type","token-rb-7-wanted-type","token-rb-7-actual-flags","token-rb-7-wanted-flags","token-rb-7-actual-size","token-rb-7-wanted-size","token-rb-7-sid-equal"}
   };
   for(DWORD i=0;i<8&&(i<actual->AceCount||i<wanted->AceCount);++i){
    void* av{};void* wv{};
    const bool have_a=i<actual->AceCount&&GetAce(actual,i,&av);
    const bool have_w=i<wanted->AceCount&&GetAce(wanted,i,&wv);
    auto ah=have_a?(ACE_HEADER*)av:nullptr;auto wh=have_w?(ACE_HEADER*)wv:nullptr;
    const auto plain=[](ACE_HEADER* h){return h&&(h->AceType==ACCESS_ALLOWED_ACE_TYPE||h->AceType==ACCESS_DENIED_ACE_TYPE)&&h->AceSize>=sizeof(ACCESS_ALLOWED_ACE);};
    auto aa=plain(ah)?(ACCESS_ALLOWED_ACE*)av:nullptr;auto wa=plain(wh)?(ACCESS_ALLOWED_ACE*)wv:nullptr;
    if(aa)report_fixed(labels[i][0],aa->Mask);
    if(wa)report_fixed(labels[i][1],wa->Mask);
    if(ah){report_fixed(labels[i][2],ah->AceType);report_fixed(labels[i][4],ah->AceFlags);report_fixed(labels[i][6],ah->AceSize);}
    if(wh){report_fixed(labels[i][3],wh->AceType);report_fixed(labels[i][5],wh->AceFlags);report_fixed(labels[i][7],wh->AceSize);}
    PSID as=aa?(PSID)&aa->SidStart:nullptr;PSID ws=wa?(PSID)&wa->SidStart:nullptr;
    const bool valid_a=as&&IsValidSid(as)&&GetLengthSid(as)<=ah->AceSize-(sizeof(ACCESS_ALLOWED_ACE)-sizeof(DWORD));
    const bool valid_w=ws&&IsValidSid(ws)&&GetLengthSid(ws)<=wh->AceSize-(sizeof(ACCESS_ALLOWED_ACE)-sizeof(DWORD));
    report_fixed(labels[i][8],valid_a&&valid_w&&EqualSid(as,ws));
   }
  }catch(...){} // Diagnostics never grant acceptance or cleanup authority.
 }
 void restore() noexcept {
  if(!changed)return;
  try {
   // Unknown API outcomes and mismatched readbacks are not cleanup authority.
   if(!verified||!read(current)||!same(current,expected)||!identity(current,baseline)){
    report_fixed("token-observation-restore-retained",ERROR_INVALID_DATA);return;
   }
   SECURITY_DESCRIPTOR sd{};prepare(sd,baseline,acl(baseline));
   if(!read(current)||!same(current,expected)){report_fixed("token-observation-restore-drift",ERROR_INVALID_DATA);return;}
   if(!SetKernelObjectSecurity(token.get(),DACL_SECURITY_INFORMATION,&sd)){
    report_fixed("token-observation-restore-write",GetLastError());return;
   }
   if(!read(current)||!same(current,baseline)){report_fixed("token-observation-restore-readback",ERROR_INVALID_DATA);return;}
   changed=false;
  }catch(...){report_fixed("token-observation-restore-invalid",ERROR_INVALID_DATA);}
 }
 // Constructed last, destroyed first even when the constructor throws after
 // its write. All buffers exist before mutation; cleanup never allocates/throws.
 struct Guard {TokenObservation&owner;~Guard() noexcept {owner.restore();}}guard{*this};
 TokenObservation(const TokenObservation&)=delete;
 TokenObservation&operator=(const TokenObservation&)=delete;
 TokenObservation(Session&s,PSID package){
  stage="service-token-query-observation";HANDLE raw{};need(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|READ_CONTROL|WRITE_DAC,&raw)!=0);token=Handle(raw);
  check(read(baseline));auto original=acl(baseline);check(identity(baseline,baseline));
  std::copy_n(baseline.bytes.data(),baseline.size,expected.bytes.data());expected.size=baseline.size;
  check(read(current)&&same(current,expected));
  PSID user{};need(ConvertStringSidToSidW(s.sid.c_str(),&user)!=0);struct Sid{PSID p;~Sid(){LocalFree(p);}}sid{user};
  check(user&&package&&IsValidSid(user)&&IsValidSid(package));
  auto next=(PACL)storage.data();check(InitializeAcl(next,DWORD(storage.size()),original->AclRevision)!=0);
  for(DWORD i=0;i<original->AceCount;i++){
   void*v{};check(GetAce(original,i,&v)!=0);auto*h=(ACE_HEADER*)v;
   check(h->AceType==ACCESS_ALLOWED_ACE_TYPE||h->AceType==ACCESS_DENIED_ACE_TYPE);
   check(h->AceSize>=sizeof(ACCESS_ALLOWED_ACE));auto*a=(ACCESS_ALLOWED_ACE*)v;PSID peer=(PSID)&a->SidStart;
   check(IsValidSid(peer)&&GetLengthSid(peer)<=h->AceSize-(sizeof(ACCESS_ALLOWED_ACE)-sizeof(DWORD)));
   check(AddAce(next,original->AclRevision,MAXDWORD,v,h->AceSize)!=0);
  }
  // Preserve EVERY baseline ACE byte/order, including inherited denies and
  // same-SID rights. Never canonicalize or merge a previous published result.
  const auto append=[&](PSID peer){
   for(DWORD i=0;i<next->AceCount;i++){
    void*v{};check(GetAce(next,i,&v)!=0);auto*a=(ACCESS_ALLOWED_ACE*)v;
    if(a->Header.AceType==ACCESS_ALLOWED_ACE_TYPE&&!a->Header.AceFlags&&a->Mask==TOKEN_QUERY&&EqualSid((PSID)&a->SidStart,peer))return;
   }
   check(AddAccessAllowedAceEx(next,original->AclRevision,0,TOKEN_QUERY,peer)!=0);
  };
  append(user);append(package);
  if(same_acl(original,next)){check(read(current)&&same(current,expected));return;}
  SECURITY_DESCRIPTOR sd{};prepare(sd,baseline,next);
  check(read(current)&&same(current,expected)); // immediately adjacent to write
  if(!SetKernelObjectSecurity(raw,DACL_SECURITY_INFORMATION,&sd)){
   report_fixed("token-observation-publish-write",GetLastError());throw Failure{ERROR_INVALID_DATA};
  }
  changed=true; // guard retains ownership before any fallible readback
  DWORD read_error{};const bool got=read(current,&read_error);
  diagnose_readback(got,read_error,next);
  check(got&&identity(current,baseline)&&same_acl(acl(current),next));
  std::copy_n(current.bytes.data(),current.size,expected.bytes.data());expected.size=current.size;verified=true;
 }
};
bool io(HANDLE pipe,void* data,DWORD size,bool write){
 const DWORD entry_error=GetLastError();const auto started=GetTickCount64();SetLastError(entry_error);
 DWORD n=0,initial_error=0,wait_result=WAIT_FAILED,wait_error=0;BOOL synchronous=FALSE;
 const auto failed=[&](const char* label,DWORD native_error){
  const DWORD boundary_error=GetLastError();const auto elapsed=GetTickCount64()-started;
  report_fixed(label,native_error);
  report_fixed("admission-io-write",static_cast<DWORD>(write));
  report_fixed("admission-io-sync-ok",static_cast<DWORD>(synchronous!=FALSE));
  report_fixed("admission-io-initial-error",initial_error);
  report_fixed("admission-io-native-error",native_error);
  report_fixed("admission-io-wait-result",wait_result);
  report_fixed("admission-io-wait-error",wait_error);
  report_fixed("admission-io-requested",size);report_fixed("admission-io-done",n);
  report_fixed("admission-io-elapsed-ms",static_cast<DWORD>(std::min<ULONGLONG>(elapsed,MAXDWORD)));
  SetLastError(boundary_error);return false;
 };
 Handle event(CreateEventW(nullptr,TRUE,FALSE,nullptr));if(!event){const DWORD error=GetLastError();return failed("admission-io-event",error);}
 OVERLAPPED ov{};ov.hEvent=event.get();BOOL ok=write?WriteFile(pipe,data,size,&n,&ov):ReadFile(pipe,data,size,&n,&ov);
 synchronous=ok;if(!ok)initial_error=GetLastError();DWORD native_error=initial_error;
 if(!ok&&initial_error==ERROR_IO_PENDING){
  HANDLE waits[]{stop_event,event.get()};wait_result=WaitForMultipleObjects(2,waits,FALSE,1500);if(wait_result==WAIT_FAILED)wait_error=GetLastError();
  if(wait_result!=WAIT_OBJECT_0+1){CancelIoEx(pipe,&ov);const BOOL completed=GetOverlappedResult(pipe,&ov,&n,TRUE);native_error=completed?0:GetLastError();return failed("admission-io-wait",native_error);}
  ok=GetOverlappedResult(pipe,&ov,&n,FALSE);native_error=ok?0:GetLastError();
 }
 if(!(ok&&n==size))return failed("admission-io-transfer",native_error);
 return ok&&n==size;
}
void diagnose_private_offer(const p::PrivateOffer& o,std::int64_t now) noexcept {
 const DWORD saved=GetLastError();try {
  const bool past=o.proof>=0&&now>=o.proof;
  report_fixed("private-offer-proof-age-ms",past?static_cast<DWORD>(std::min<std::int64_t>(now-o.proof,MAXDWORD)):MAXDWORD);
  report_fixed("private-offer-proof-valid",o.proof>=o.started&&past&&now-o.proof<3000);
  report_fixed("private-offer-budget-valid",o.started>=0&&o.ttl>0&&o.ttl<=30000&&o.started<=INT64_MAX-o.ttl&&o.deadline==o.started+o.ttl&&now>=o.started&&now<o.deadline);
  report_fixed("private-offer-lease-remaining-ms",o.deadline>=0&&o.deadline>now?static_cast<DWORD>(std::min<std::int64_t>(o.deadline-now,MAXDWORD)):0);
  report_fixed("private-offer-binding-valid",p::CanonicalUuid(o.user)&&p::CanonicalUuid(o.sandbox)&&p::CanonicalUuid(o.node)&&p::CanonicalUuid(o.tunnel)&&o.generation&&o.expiry>0&&o.binding_deadline>=o.deadline&&o.port);
  report_fixed("private-offer-secrets-valid",p::PrivateSecret(o.username,o.username_size)&&p::PrivateSecret(o.password,o.password_size));
 }catch(...){}SetLastError(saved);
}
Handle pipe_for(Session&s,Root&r,bool first){auto acl=L"D:P(A;;GA;;;SY)(A;;0x12019b;;;"+s.sid+L")(A;;0x12019b;;;"+sidtext(r.package)+L")";PSECURITY_DESCRIPTOR sd{};need(ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(),SDDL_REVISION_1,&sd,nullptr)!=0);SECURITY_ATTRIBUTES sa{sizeof(sa),sd,FALSE};Handle h(CreateNamedPipeW(p::kPipe,PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED|(first?FILE_FLAG_FIRST_PIPE_INSTANCE:0),PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,65,512,512,1500,&sa));LocalFree(sd);need(bool(h));return h;}
p::Binding peer(HANDLE pipe,Session&s,Root&r,Runtime&runtime,Handle&retained,const p::Request&q,bool root_committed){ULONG opener=0;need(GetNamedPipeClientProcessId(pipe,&opener)!=0);DWORD pid=opener;
 if(q.pid!=opener){
  report_fixed("pipe-broker-opener",opener);report_fixed("pipe-claimed-descendant",q.pid);
  // Chromium may broker a sandboxed child's pipe open. Only the committed,
  // retained browser root can mediate; the claimed child is still independently
  // checked against the private Job, pinned image and OS owner/session/logon.
  need(root_committed&&opener==r.pid&&live(r.process.get())&&birth(r.process.get())==r.created_at&&runtime.image(r.process.get()));pid=q.pid;
 }
 stage="peer-process-open";retained=Handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,pid));need(bool(retained)&&live(retained.get()));
 stage="peer-contained-image";need(r.contained(retained.get())&&runtime.image(retained.get()));HANDLE t{};need(OpenProcessToken(retained.get(),TOKEN_QUERY,&t)!=0);Handle token(t);auto actual=token_peer(t);need(actual.sid==s.peer.sid&&actual.session==s.id&&actual.logon==s.peer.logon);
 need(ImpersonateNamedPipeClient(pipe)!=0);HANDLE tt{};BOOL opened=OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&tt);BOOL reverted=RevertToSelf();need(opened&&reverted);Handle threadtoken(tt);auto pipepeer=token_peer(tt);need(pipepeer.sid==actual.sid&&pipepeer.session==actual.session&&pipepeer.logon==actual.logon);return {pid,actual.session,birth(retained.get())};}
std::array<BYTE,32> hashbytes(const std::vector<BYTE>&bytes){
 need(bytes.size()<=1048576);BCRYPT_ALG_HANDLE alg{};need(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0)==0);
 struct A{BCRYPT_ALG_HANDLE h;~A(){BCryptCloseAlgorithmProvider(h,0);}}a{alg};std::array<BYTE,32> out{};
 need(BCryptHash(alg,nullptr,0,const_cast<PUCHAR>(bytes.data()),DWORD(bytes.size()),out.data(),DWORD(out.size()))==0);return out;
}
struct Canonical : p::BoundedSnapshot {
 void put(const void*data,std::size_t n){need(p::BoundedSnapshot::put(data,n));}
 template<class T>void scalar(const T&v){put(&v,sizeof(v));}
};
std::array<BYTE,32> rules_snapshot(Runtime&r,orangespace::wfp_prototype::NetworkPolicy&net,orangespace::wfp_prototype::PackageNetworkPolicy&package_network,std::uint16_t port){
 using namespace orangespace::wfp_prototype;
 std::array<BYTE,32> digest{};
 net.withPairedSnapshot(package_network,Mode::ProxyOnly,port,[&](HANDLE engine,const std::vector<VerifiedFilter>& filters){
 auto verified=filters;need(verified.size()==12);
 std::sort(verified.begin(),verified.end(),[](auto a,auto b){return a.filterId<b.filterId;});
 Canonical c;c.put(r.exe.c_str(),r.exe.wstring().size()*sizeof(wchar_t));auto image=r.hashes.at(L"client.exe");c.put(image.data(),image.size());
 for(auto v:verified){FWPM_FILTER0*f{};need(FwpmFilterGetById0(engine,v.filterId,&f)==ERROR_SUCCESS);struct F{FWPM_FILTER0*p;~F(){FwpmFreeMemory0((void**)&p);}}free{f};
  need(f->filterId==v.filterId&&f->action.type==FWP_ACTION_BLOCK&&f->numFilterConditions>=1&&f->numFilterConditions<=3&&f->filterCondition&&(v.identityScope==IdentityScope::ExactAppContainerSid?f->providerKey!=nullptr:f->providerKey==nullptr)&&f->weight.type==FWP_UINT64&&f->weight.uint64&&f->effectiveWeight.type==FWP_UINT64&&f->effectiveWeight.uint64);
  c.scalar(v.identityScope);c.scalar(v.filterId);c.scalar(v.rule.layer);c.scalar(v.rule.kind);c.scalar(v.rule.port);c.scalar(f->filterKey);const bool hasProvider=f->providerKey!=nullptr;c.scalar(hasProvider);if(hasProvider)c.scalar(*f->providerKey);c.scalar(f->layerKey);c.scalar(f->subLayerKey);c.scalar(f->action.type);c.scalar(f->flags);c.scalar(*f->weight.uint64);c.scalar(*f->effectiveWeight.uint64);c.scalar(f->numFilterConditions);
  for(DWORD i=0;i<f->numFilterConditions;i++){auto&x=f->filterCondition[i];c.scalar(x.fieldKey);c.scalar(x.matchType);c.scalar(x.conditionValue.type);
   switch(x.conditionValue.type){case FWP_UINT8:c.scalar(x.conditionValue.uint8);break;case FWP_UINT16:c.scalar(x.conditionValue.uint16);break;case FWP_UINT32:c.scalar(x.conditionValue.uint32);break;case FWP_BYTE_BLOB_TYPE:need(x.conditionValue.byteBlob!=nullptr);c.put(x.conditionValue.byteBlob->data,x.conditionValue.byteBlob->size);break;case FWP_SID:need(IsValidSid(x.conditionValue.sid)!=0);c.put(x.conditionValue.sid,GetLengthSid(x.conditionValue.sid));break;default:need(false);}
  }
  PSECURITY_DESCRIPTOR sd{};need(FwpmFilterGetSecurityInfoByKey0(engine,&f->filterKey,OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,nullptr,nullptr,nullptr,nullptr,&sd)==ERROR_SUCCESS);LPWSTR text{};BOOL converted=ConvertSecurityDescriptorToStringSecurityDescriptorW(sd,SDDL_REVISION_1,OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&text,nullptr);FwpmFreeMemory0((void**)&sd);need(converted!=0);c.put(text,wcslen(text)*sizeof(wchar_t));LocalFree(text);
 }
 digest=hashbytes(c.bytes);
 });
 return digest;
}
bool scm_self(){SC_HANDLE manager=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);if(!manager)return false;SC_HANDLE svc=OpenServiceW(manager,p::kService,SERVICE_QUERY_STATUS);SERVICE_STATUS_PROCESS state{};DWORD n{};bool ok=svc&&QueryServiceStatusEx(svc,SC_STATUS_PROCESS_INFO,(LPBYTE)&state,sizeof(state),&n)&&state.dwProcessId==GetCurrentProcessId()&&state.dwCurrentState==SERVICE_RUNNING;if(svc)CloseServiceHandle(svc);CloseServiceHandle(manager);return ok;}
void verify_job_members(Runtime&r,Session&s,Root&root){
 constexpr DWORD capacity=4096;
 constexpr unsigned max_retirement_retries=3;
 std::vector<ULONG_PTR> storage((sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST)+capacity*sizeof(ULONG_PTR)+sizeof(ULONG_PTR)-1)/sizeof(ULONG_PTR));
 auto*list=reinterpret_cast<JOBOBJECT_BASIC_PROCESS_ID_LIST*>(storage.data());
 const auto read_members=[&]{
  need(QueryInformationJobObject(root.job.get(),JobObjectBasicProcessIdList,list,DWORD(storage.size()*sizeof(ULONG_PTR)),nullptr)!=0);
  need(list->NumberOfAssignedProcesses==list->NumberOfProcessIdsInList&&list->NumberOfProcessIdsInList<=capacity);
 };
 read_members();
 for(unsigned retries=0;;){
  bool saw_root=false,restart=false;
  for(DWORD i=0;i<list->NumberOfProcessIdsInList;i++){
   const auto raw_pid=list->ProcessIdList[i];need(raw_pid&&raw_pid<=0xffffffffu);const DWORD pid=DWORD(raw_pid);
   Handle retained(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,pid));
   if(!retained){
    // A child can finish between the Job query and OpenProcess. Require a
    // fresh kernel snapshot without that PID, then verify every member again.
    need(pid!=root.pid&&retries<max_retirement_retries);
    read_members();
    const auto end=list->ProcessIdList+list->NumberOfProcessIdsInList;
    need(std::find(list->ProcessIdList,end,raw_pid)==end);
    ++retries;restart=true;break;
   }
   const DWORD observed=WaitForSingleObject(retained.get(),0);
   if(observed==WAIT_OBJECT_0&&pid!=root.pid)continue;
   need(observed==WAIT_TIMEOUT);
   try {
    const auto created=birth(retained.get());need(GetProcessId(retained.get())==pid);
    if(pid==root.pid){need(created==root.created_at);saw_root=true;}
    need(root.contained(retained.get())&&r.image(retained.get()));
    HANDLE raw{};need(OpenProcessToken(retained.get(),TOKEN_QUERY,&raw)!=0);Handle token(raw);auto actual=token_peer(raw);
    need(actual.sid==s.peer.sid&&actual.session==s.id&&actual.logon==s.peer.logon);
    const DWORD final_wait=WaitForSingleObject(retained.get(),0);
    need((pid!=root.pid&&final_wait==WAIT_OBJECT_0)||(final_wait==WAIT_TIMEOUT&&birth(retained.get())==created&&GetProcessId(retained.get())==pid));
   }catch(...){if(pid!=root.pid&&WaitForSingleObject(retained.get(),0)==WAIT_OBJECT_0)continue;throw;}
  }
  if(!restart){need(saw_root);return;}
 }
}
struct AdmissionWorker {
 std::future<void> done;
 std::thread thread;
 template<class F> explicit AdmissionWorker(F&& work){
  std::packaged_task<void()> task(std::forward<F>(work));
  done=task.get_future();
  thread=std::thread(std::move(task));
 }
};
void reap_admission_workers(std::vector<AdmissionWorker>& workers){
 for(auto it=workers.begin();it!=workers.end();){
  if(it->done.wait_for(std::chrono::seconds(0))==std::future_status::ready){
   it->thread.join();it=workers.erase(it);
  }else ++it;
 }
}
p::Reply native_mechanism_validated(Runtime&r,Session&s,Root&root,p::FreshRuleInspection&inspections){
 const ULONGLONG proof_started=GetTickCount64();
 struct ProofElapsed{ULONGLONG start;~ProofElapsed(){report_fixed("proof-elapsed-ms",static_cast<DWORD>(GetTickCount64()-start));}}elapsed{proof_started};
 p::Reply proof{};
 stage="proof-session-owner";need(s.same());HANDLE raw{};need(OpenProcessToken(root.process.get(),TOKEN_QUERY,&raw)!=0);Handle token(raw);auto peer=token_peer(raw);need(peer.sid==s.peer.sid&&peer.session==s.id&&peer.logon==s.peer.logon);proof.evidence|=1u<<0;
 report_fixed("proof-session-elapsed-ms",static_cast<DWORD>(GetTickCount64()-proof_started));
 stage="proof-root-instance";need(live(root.process.get())&&birth(root.process.get())==root.created_at&&GetProcessId(root.process.get())==root.pid);proof.evidence|=1u<<1;
 stage="proof-runtime-pins";need(r.image(root.process.get())&&!r.hashes.empty()&&r.pins.size()>=r.hashes.size());
 // Constructor hashed every inventory file on these still-held, deny-write/delete-share handles.
 // Do not hash the full CEF payload per ACK: no writer can coexist with the retained pins.
 for(auto&h:r.pins){BY_HANDLE_FILE_INFORMATION fi{};need(GetFileInformationByHandle(h.get(),&fi)&&!(fi.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT));if(!(fi.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY))need(fi.nNumberOfLinks==1);}proof.evidence|=1u<<2;
 report_fixed("proof-runtime-elapsed-ms",static_cast<DWORD>(GetTickCount64()-proof_started));
 stage="proof-job-containment";JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};DWORD flags{};need(GetHandleInformation(root.job.get(),&flags)&&!(flags&HANDLE_FLAG_INHERIT)&&QueryInformationJobObject(root.job.get(),JobObjectExtendedLimitInformation,&limits,sizeof(limits),nullptr));need(limits.BasicLimitInformation.LimitFlags==JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE&&root.contained(root.process.get()));verify_job_members(r,s,root);proof.evidence|=1u<<3;
 stage="proof-offline-filter-snapshot";proof.rules_digest=inspections.snapshot();proof.evidence|=1u<<4;proof.evidence|=1u<<8;
 report_fixed("proof-rules-elapsed-ms",static_cast<DWORD>(GetTickCount64()-proof_started));
 // Same live kernel premises as reviewed zero-capability DNS ACCESS_DENIED probe.
 // CEF and packet-trace compatibility remain native acceptance, not a startup cycle.
 stage="proof-appcontainer-identity";need(root.created&&root.package&&root.contained(root.process.get()));PSID derived{};need(DeriveAppContainerSidFromAppContainerName(root.profile.c_str(),&derived)==S_OK);bool exact=EqualSid(derived,root.package)!=0;FreeSid(derived);need(exact);proof.evidence|=1u<<5;
 stage="proof-service-scm-system";need(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw)!=0);Handle own(raw);auto u=info(raw,TokenUser);need(IsWellKnownSid(((TOKEN_USER*)u.data())->User.Sid,WinLocalSystemSid)&&scm_self());proof.evidence|=1u<<6;
 stage="proof-live-stop-owner";need(stop_event&&WaitForSingleObject(stop_event,0)==WAIT_TIMEOUT&&live(root.process.get()));proof.evidence|=1u<<7;
 proof.server_pid=GetCurrentProcessId();proof.server_created=birth(GetCurrentProcess());proof.root_pid=root.pid;proof.root_created=root.created_at;proof.generation=root.generation;proof.rules_epoch=root.epoch;proof.job_cookie=root.cookie;return proof;
}

// Full fresh proof runs outside the publication lock. Recheck exact retained
// kernel identities and revocation immediately before publishing either phase.
void admission_fence(Root&root,HANDLE retained,const p::Binding&binding){
 need(WaitForSingleObject(stop_event,0)==WAIT_TIMEOUT&&live(root.process.get())&&
      birth(root.process.get())==root.created_at&&GetProcessId(root.process.get())==root.pid&&
      root.contained(root.process.get())&&live(retained)&&birth(retained)==binding.created&&
      GetProcessId(retained)==binding.pid&&root.contained(retained)&&scm_self());
}
void status(DWORD state,DWORD error=0){static DWORD checkpoint=0;SERVICE_STATUS s{SERVICE_WIN32_OWN_PROCESS,state,DWORD((state==SERVICE_RUNNING||state==SERVICE_START_PENDING)?SERVICE_ACCEPT_STOP:0),error,0,state==SERVICE_START_PENDING?++checkpoint:0,state==SERVICE_START_PENDING?5000u:0u};need(SetServiceStatus(scm_handle,&s)!=0);}
void WINAPI control(DWORD code){if(code==SERVICE_CONTROL_STOP){SetEvent(service_stop_event);SetEvent(stop_event);}}
void WINAPI main_service(DWORD,LPWSTR*){scm_handle=RegisterServiceCtrlHandlerW(p::kService,control);if(!scm_handle)return;status(SERVICE_START_PENDING);Handle stop(CreateEventW(nullptr,TRUE,FALSE,nullptr)),run_stop(CreateEventW(nullptr,TRUE,FALSE,nullptr));stop_event=run_stop.get();service_stop_event=stop.get();DWORD error=0;
 try {stage="LocalSystem";HANDLE raw{};need(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw)!=0);Handle own(raw);auto u=info(raw,TokenUser);need(IsWellKnownSid(((TOKEN_USER*)u.data())->User.Sid,WinLocalSystemSid)!=0);Runtime runtime;std::unique_ptr<Session> selected;
  // No interactive session is not a reason to create a session-0 root.
  while(WaitForSingleObject(stop_event,0)==WAIT_TIMEOUT&&!selected){try{selected=std::make_unique<Session>();}catch(...){WaitForSingleObject(stop_event,1000);status(SERVICE_START_PENDING);}}
  need(bool(selected));auto&session=*selected;
  orangespace::service::win::ProcessObservationAcl observation;
  auto pkgpeer=session.peer;
  stage="offline-WFP-install-readback";orangespace::wfp_prototype::NetworkPolicy network;try{network.installOffline(runtime.exe.wstring());}catch(const std::runtime_error& e){report_fixed(e.what(),ERROR_INVALID_DATA);throw;}
  stage="service-observation-publish";observation.publish({{session.id,session.peer}});
  stage="service-control-construct";orangespace::service::win::PrototypeControl control(session.peer,service_stop_event,ORANGESPACE_PROTOTYPE_NODE_UUID);
  stage="service-control-start";control.start();stage="service-running-status";status(SERVICE_RUNNING);
  need(bool(run_stop));
  while(WaitForSingleObject(service_stop_event,0)==WAIT_TIMEOUT){
  std::shared_ptr<const orangespace::service::win::LocalChannel> channel;
  while(WaitForSingleObject(service_stop_event,0)==WAIT_TIMEOUT&&!channel)channel=control.wait_channel(200);
  if(!channel)break;channel->budget.validate(orangespace::service::chain::nd::monotonic_ms());control.verify_live(*channel);need(session.same());
  try {
  need(ResetEvent(run_stop.get())!=0&&WaitForSingleObject(service_stop_event,0)==WAIT_TIMEOUT);
  Root root;
  root.prepare_identity(runtime,session,channel->binding.sandbox);
  orangespace::wfp_prototype::PackageNetworkPolicy package_network;
  orangespace::wfp_prototype::OwnedLoopbackExemption exemption(root.package);
  stage="root-offline-policy";
  (void)network.verifyExactPolicy(orangespace::wfp_prototype::Mode::Offline);
  package_network.installOffline(root.package);
  struct Cleanup {
   Root&r;orangespace::wfp_prototype::NetworkPolicy&n;orangespace::wfp_prototype::PackageNetworkPolicy&p;orangespace::wfp_prototype::OwnedLoopbackExemption&e;
   ~Cleanup(){
    SetEvent(stop_event);if(r.job)TerminateJobObject(r.job.get(),71);bool denied=true,removed=false;
    try{n.restoreOffline();(void)n.verifyExactPolicy(orangespace::wfp_prototype::Mode::Offline);}catch(...){denied=false;}
    try{p.restoreOffline();(void)p.verifyExactPolicy(orangespace::wfp_prototype::Mode::Offline);}catch(...){denied=false;}
    // Removal is attempted even if either restore/readback failed.
    try{removed=e.removeOnlyOwned().exact;}catch(...){}
    if(!denied||!removed){report_fixed("online-cleanup-retained-deny",ERROR_INVALID_DATA);return;}
    try{
     // A failed creation can leave an installed policy without a process.
     JOBOBJECT_BASIC_ACCOUNTING_INFORMATION a{};
     if(!r.process||(r.job&&WaitForSingleObject(r.process.get(),5000)==WAIT_OBJECT_0&&QueryInformationJobObject(r.job.get(),JobObjectBasicAccountingInformation,&a,sizeof(a),nullptr)&&a.ActiveProcesses==0))
      p.cleanupAfterExactTreeExit();
    }catch(...){report_fixed("online-cleanup-retained-deny",ERROR_INVALID_DATA);}
   }
  }cleanup{root,network,package_network,exemption};
  channel->budget.validate(orangespace::service::chain::nd::monotonic_ms());control.verify_live(*channel);
  need(session.same()&&WaitForSingleObject(service_stop_event,0)==WAIT_TIMEOUT);
  root.launch_suspended(runtime,session);
  TokenObservation token_observation(session,root.package);auto listener=pipe_for(session,root,true);
  auto ws=sidtext(root.package);pkgpeer.sid=std::string(ws.begin(),ws.end());observation.publish({{session.id,session.peer},{0,pkgpeer}});
  // Desktop setup has no network authority. Keep both policies offline while
  // the root is suspended and the interactive owner acknowledges its desktop.
  stage="desktop-root-publication";
  control.verify_live(*channel);channel->budget.validate(orangespace::service::chain::nd::monotonic_ms());
  {auto sid=sidtext(root.package);control.publish_root(*channel,std::string(sid.begin(),sid.end()),std::string(root.profile.begin(),root.profile.end()),root.pid,root.created_at);}
  stage="desktop-ack-wait";
  while(!control.desktop_configured()&&!control.closing()&&WaitForSingleObject(service_stop_event,100)==WAIT_TIMEOUT){control.verify_live(*channel);channel->budget.validate(orangespace::service::chain::nd::monotonic_ms());}
  need(control.desktop_configured()&&!control.closing()&&WaitForSingleObject(service_stop_event,0)==WAIT_TIMEOUT);
  stage="root-proxy-policy";
  channel->budget.validate(orangespace::service::chain::nd::monotonic_ms());control.verify_live(*channel);
  network.switchToProxyOnly(channel->port);package_network.switchToProxyOnly(channel->port);
  need(network.verifyExactPolicy(orangespace::wfp_prototype::Mode::ProxyOnly,channel->port).size()==6&&package_network.verifyExactPolicy(orangespace::wfp_prototype::Mode::ProxyOnly,channel->port).size()==6);
  need(exemption.appendAfterVerifiedWfp().exact);
  p::FreshRuleInspection inspections([&]{
   control.verify_live(*channel);
   orangespace::wfp_prototype::OwnedLoopbackExemption::Snapshot actual;
   need(orangespace::wfp_prototype::OwnedLoopbackExemption::read(actual)==ERROR_SUCCESS);
   unsigned owned=0;for(const auto&entry:actual)if(IsValidSid(const_cast<BYTE*>(entry.sid.data()))&&EqualSid(const_cast<BYTE*>(entry.sid.data()),root.package)){need(entry.attributes==0);++owned;}need(owned==1);
   return rules_snapshot(runtime,network,package_network,channel->port);
  });
  auto baseline=native_mechanism_validated(runtime,session,root,inspections);
  std::mutex gate;bool root_committed=false;std::set<std::pair<DWORD,std::uint64_t>> admitted;std::vector<AdmissionWorker> workers;workers.reserve(65);
  struct Join {std::vector<AdmissionWorker>&w;Root&r;p::FreshRuleInspection&inspections;~Join(){SetEvent(stop_event);TerminateJobObject(r.job.get(),71);for(auto&t:w)if(t.thread.joinable())t.thread.join();inspections.stop();}}join{workers,root,inspections};
  stage="desktop-resume";
  need(!control.closing()&&WaitForSingleObject(service_stop_event,0)==WAIT_TIMEOUT);
  channel->budget.validate(orangespace::service::chain::nd::monotonic_ms());
  control.verify_live(*channel);
  need(ResumeThread(root.thread.get())!=DWORD(-1));
  // Independent continuous full-proof watchdog: accept never queues behind it.
  // Join owns all threads before any referenced Runtime/Root/NetworkPolicy closes.
  workers.emplace_back([&]{
   try{while(WaitForSingleObject(stop_event,0)==WAIT_TIMEOUT){
    auto current=native_mechanism_validated(runtime,session,root,inspections);need(p::SameSnapshot(baseline,current));
   }}catch(const Failure&f){report_fixed(stage,f.code);SetEvent(stop_event);TerminateJobObject(root.job.get(),71);}
   catch(...){report_fixed("admission-watchdog-exception",ERROR_INVALID_DATA);SetEvent(stop_event);TerminateJobObject(root.job.get(),71);}
  });
  while(live(root.process.get())&&WaitForSingleObject(stop_event,0)==WAIT_TIMEOUT){
   Handle ev(CreateEventW(nullptr,TRUE,FALSE,nullptr));need(bool(ev));OVERLAPPED ov{};ov.hEvent=ev.get();BOOL connected=ConnectNamedPipe(listener.get(),&ov);
   if(!connected&&GetLastError()==ERROR_IO_PENDING){HANDLE waits[]{stop_event,ev.get()};DWORD w=WaitForMultipleObjects(2,waits,FALSE,200);if(w!=WAIT_OBJECT_0+1){CancelIoEx(listener.get(),&ov);DWORD n{};GetOverlappedResult(listener.get(),&ov,&n,TRUE);if(w==WAIT_TIMEOUT)continue;break;}DWORD n{};need(GetOverlappedResult(listener.get(),&ov,&n,FALSE)!=0);}else need(connected||GetLastError()==ERROR_PIPE_CONNECTED);
   stage="admission-worker-capacity";reap_admission_workers(workers);
   need(workers.size()<65);auto next=pipe_for(session,root,false);
   workers.emplace_back([&,pipe=std::move(listener)]()mutable{
    try{
     Handle retained;p::Binding binding{};p::Request q{};p::Commit commit;p::Reply reply{};ULONG pipe_opener{};
     need(GetNamedPipeClientProcessId(pipe.get(),&pipe_opener)!=0);
     stage="request-read";need(io(pipe.get(),&q,sizeof(q),false));
     bool committed_root{};{std::lock_guard lock(gate);committed_root=root_committed;}
     binding=peer(pipe.get(),session,root,runtime,retained,q,committed_root);need(commit.offer(q,binding));
     reply=native_mechanism_validated(runtime,session,root,inspections);
     {std::lock_guard lock(gate);admission_fence(root,retained.get(),binding);need(p::SameSnapshot(baseline,reply));need(admitted.insert({binding.pid,binding.created}).second);}
     // All fallible ownership allocation and replay registration precede publication.
     reply.magic=p::kMagic;reply.version=p::kVersion;reply.size=sizeof(reply);reply.status=1;reply.pid=binding.pid;reply.session=binding.session;reply.created=binding.created;reply.nonce=q.nonce;
     stage="provisional-write";need(io(pipe.get(),&reply,sizeof(reply),true));BYTE ack{};stage="ack-read";need(io(pipe.get(),&ack,1,false));
     {std::lock_guard lock(gate);committed_root=root_committed;}
     Handle check;auto again=peer(pipe.get(),session,root,runtime,check,q,committed_root);need(check.get()&&birth(check.get())==birth(retained.get())&&GetProcessId(check.get())==GetProcessId(retained.get()));
     auto now=native_mechanism_validated(runtime,session,root,inspections);
     {std::lock_guard lock(gate);admission_fence(root,retained.get(),binding);need(p::SameSnapshot(reply,now)&&commit.ack(ack,q,again));if(binding.pid==root.pid&&binding.created==root.created_at)root_committed=true;}
     // No potentially blocking pipe I/O while holding the admission state lock.
     reply.status=2;stage="committed-write";need(io(pipe.get(),&reply,sizeof(reply),true));
     if(binding.pid==root.pid&&binding.created==root.created_at){
      need(pipe_opener==root.pid);stage="private-live-verify";control.verify_live(*channel);
      stage="private-offer-build";p::PrivateOwner private_owner;auto&o=private_owner.offer;o.base=reply;
      need(BCryptGenRandom(nullptr,o.nonce.data(),32,BCRYPT_USE_SYSTEM_PREFERRED_RNG)==0);
      const auto copy_uuid=[](auto&out,std::string_view in){need(in.size()==out.size());std::memcpy(out.data(),in.data(),in.size());};
      copy_uuid(o.user,channel->binding.user);copy_uuid(o.sandbox,channel->binding.sandbox);copy_uuid(o.node,channel->binding.node);copy_uuid(o.tunnel,channel->binding.tunnel);
      o.generation=channel->binding.generation;o.expiry=channel->binding.server_expiry;o.binding_deadline=channel->binding.deadline_ms;
      o.started=channel->budget.request_started_ms;o.ttl=channel->budget.remaining_ttl_ms;o.deadline=channel->budget.deadline_ms;o.proof=control.fresh_forwarding_proof(*channel);o.port=channel->port;
      const auto u=channel->username.view(),password=channel->password.view();need(u.size()<=255&&password.size()<=255);o.username_size=static_cast<std::uint16_t>(u.size());o.password_size=static_cast<std::uint16_t>(password.size());std::memcpy(o.username.data(),u.data(),u.size());std::memcpy(o.password.data(),password.data(),password.size());
      stage="private-offer-validate";const auto private_now=orangespace::service::chain::nd::monotonic_ms();const bool valid_private_offer=p::ValidPrivateOffer(o,reply,private_now);if(!valid_private_offer)diagnose_private_offer(o,private_now);need(valid_private_offer);
      p::PrivateReceipt expected{};expected.base=reply;expected.nonce=o.nonce;stage="private-offer-hash";BCRYPT_ALG_HANDLE alg{};need(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0)==0);const auto hashed=BCryptHash(alg,nullptr,0,reinterpret_cast<PUCHAR>(&o),sizeof(o),expected.digest.data(),32);BCryptCloseAlgorithmProvider(alg,0);need(hashed==0);
      stage="private-offer-write";need(io(pipe.get(),&o,sizeof(o),true));p::PrivateReceipt acknowledged{};stage="private-ack-read";need(io(pipe.get(),&acknowledged,sizeof(acknowledged),false));need(p::ValidPrivateReceipt(expected,acknowledged,6));
      auto final_proof=native_mechanism_validated(runtime,session,root,inspections);control.verify_live(*channel);
      {std::lock_guard lock(gate);admission_fence(root,retained.get(),binding);need(p::SameSnapshot(reply,final_proof)&&p::ValidPrivateOffer(o,reply,orangespace::service::chain::nd::monotonic_ms()));}
      stage="private-committed-write";need(io(pipe.get(),&expected,sizeof(expected),true));
      while(WaitForSingleObject(stop_event,200)==WAIT_TIMEOUT){
       control.verify_live(*channel);auto command=control.next_command();p::BrowserFrame observed;
       stage="browser-command-write";need(io(pipe.get(),&command,sizeof(command),true));
       stage="browser-state-read";need(io(pipe.get(),&observed,sizeof(observed),false));control.observe(observed);
       if(command.command==5){
        // Graceful CEF close flushes its persistent profile before bounded kill.
        HANDLE waits[]{service_stop_event.load(),root.process.get()};WaitForMultipleObjects(2,waits,FALSE,5000);SetEvent(stop_event);break;
       }
       if(observed.phase==0){SetEvent(stop_event);break;}
      }
      return;
     }
     report_fixed("admission-committed",binding.pid);
     const auto retire_child=[&]{
      // Only a retained, signalled child reaches this point. Its PID/birth
      // cannot pass the live-process fence again, even if the PID is reused.
      {std::lock_guard lock(gate);admitted.erase({binding.pid,binding.created});}
      report_fixed("admission-child-exited",binding.pid);
     };
     while(WaitForSingleObject(stop_event,200)==WAIT_TIMEOUT){
      // A retained, kernel-signalled non-root process has no remaining work
      // to revoke. Chromium normally retires utility children during startup.
      // A live disconnect or any unknown observation still revokes the Job.
      stage="admission-monitor-process";
      const DWORD process_wait=WaitForSingleObject(retained.get(),0);
      if(process_wait==WAIT_OBJECT_0&&binding.pid!=root.pid){retire_child();break;}
      need(process_wait==WAIT_TIMEOUT&&birth(retained.get())==binding.created);
      stage="admission-monitor-pipe";
      DWORD pending{};const bool pipe_ok=PeekNamedPipe(pipe.get(),nullptr,0,nullptr,&pending,nullptr)!=0;
      if(!pipe_ok&&binding.pid!=root.pid&&WaitForSingleObject(retained.get(),0)==WAIT_OBJECT_0){retire_child();break;}
      need(pipe_ok&&pending==0);
      ULONG pid{};need(GetNamedPipeClientProcessId(pipe.get(),&pid)&&pid==pipe_opener);
     }
    }catch(const Failure&f){report_fixed(stage,f.code);SetEvent(stop_event);TerminateJobObject(root.job.get(),71);}catch(...){report_fixed("admission-worker-exception",ERROR_INVALID_DATA);SetEvent(stop_event);TerminateJobObject(root.job.get(),71);}
   });listener=std::move(next);
  }
  SetEvent(stop_event);TerminateJobObject(root.job.get(),71);
  }
  catch(...){if(!control.closing()||WaitForSingleObject(service_stop_event,0)!=WAIT_TIMEOUT)throw;}
  control.finish_run(*channel);
  observation.publish({{session.id,session.peer}});
  }
  network.cleanupAfterExactTreeExit();
 }catch(const Failure&f){error=f.code;}catch(const std::exception& e){error=ERROR_INVALID_DATA;if(std::strcmp(stage,"service-control-construct")==0)if(const char* fixed=fixed_startup_error(e.what()))report_fixed(fixed,error);}catch(...){error=ERROR_INVALID_DATA;}
 // Protected operator diagnosis: SCM exit code + fixed stage in Application event log.
 HANDLE log=RegisterEventSourceW(nullptr,p::kService);if(log){wchar_t label[128]{};MultiByteToWideChar(CP_UTF8,0,stage,-1,label,128);LPCWSTR strings[]{label};ReportEventW(log,EVENTLOG_ERROR_TYPE,0,1,nullptr,1,sizeof(error),strings,&error);DeregisterEventSource(log);}status(SERVICE_STOPPED,error);
}
}
int wmain(){SERVICE_TABLE_ENTRYW entries[]{{const_cast<LPWSTR>(p::kService),main_service},{nullptr,nullptr}};return StartServiceCtrlDispatcherW(entries)?0:int(GetLastError());}
