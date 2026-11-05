#pragma once
#ifndef _WIN32
#error This adapter requires Windows; portable policy is separate.
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <bcrypt.h>
#include <shlobj.h>
#include <array>
#include <algorithm>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include "phase1_guardian_policy.hpp"
namespace phase1_guardian::win {
struct Failure:std::runtime_error { explicit Failure():std::runtime_error("G_NATIVE_UNKNOWN"){} };
inline void need(bool b){if(!b)throw Failure();}
class Handle {
 HANDLE h_=nullptr;
public:
 Handle()=default; explicit Handle(HANDLE h):h_(h){} ~Handle(){reset();}
 Handle(const Handle&)=delete;Handle& operator=(const Handle&)=delete;
 Handle(Handle&& o)noexcept:h_(o.h_){o.h_=nullptr;}
 Handle& operator=(Handle&&o)noexcept{if(this!=&o){reset();h_=o.h_;o.h_=nullptr;}return *this;}
 HANDLE get()const{return h_;} explicit operator bool()const{return h_&&h_!=INVALID_HANDLE_VALUE;}
 HANDLE* put(){reset();return &h_;}
 void reset(HANDLE h=nullptr){if(h_&&h_!=INVALID_HANDLE_VALUE)CloseHandle(h_);h_=h;}
};
class ScHandle {
 SC_HANDLE h_=nullptr;
public:
 ~ScHandle(){reset();} ScHandle()=default;ScHandle(const ScHandle&)=delete;ScHandle& operator=(const ScHandle&)=delete;
 SC_HANDLE get()const{return h_;} explicit operator bool()const{return h_!=nullptr;}
 void reset(SC_HANDLE h=nullptr){if(h_)CloseServiceHandle(h_);h_=h;}
};
using Digest=std::array<unsigned char,32>;
inline Digest sha256(const void* p,std::size_t n){
 need(n<=0xffffffffu);BCRYPT_ALG_HANDLE a=nullptr;need(BCryptOpenAlgorithmProvider(&a,BCRYPT_SHA256_ALGORITHM,nullptr,0)>=0);
 struct Close {BCRYPT_ALG_HANDLE h;~Close(){BCryptCloseAlgorithmProvider(h,0);}} close{a};
 Digest out{};need(BCryptHash(a,nullptr,0,(PUCHAR)p,(ULONG)n,out.data(),(ULONG)out.size())>=0);return out;
}
inline std::string hex(const Digest& d){std::string s;for(auto c:d){s.push_back("0123456789abcdef"[c>>4]);s.push_back("0123456789abcdef"[c&15]);}return s;}
inline bool valid_nonce(const std::wstring&s){return s.size()==32&&std::all_of(s.begin(),s.end(),[](wchar_t c){return(c>=L'0'&&c<=L'9')||(c>=L'a'&&c<=L'f');});}
inline std::wstring module_path(){std::wstring s(32768,L'\0');DWORD n=GetModuleFileNameW(nullptr,s.data(),(DWORD)s.size());need(n&&n<s.size());s.resize(n);return s;}
inline std::uint64_t ft(FILETIME t){return(std::uint64_t(t.dwHighDateTime)<<32)|t.dwLowDateTime;}
inline std::uint64_t now(){FILETIME t{};GetSystemTimeAsFileTime(&t);return ft(t);}
inline std::wstring image(HANDLE h){std::wstring s(32768,L'\0');DWORD n=(DWORD)s.size();need(QueryFullProcessImageNameW(h,0,s.data(),&n));s.resize(n);return s;}
inline bool equal_path(const std::wstring&a,const std::wstring&b){return CompareStringOrdinal(a.c_str(),(int)a.size(),b.c_str(),(int)b.size(),TRUE)==CSTR_EQUAL;}
inline bool sid_is(PSID sid,const wchar_t* text){PSID p=nullptr;need(ConvertStringSidToSidW(text,&p));bool b=EqualSid(sid,p);LocalFree(p);return b;}
inline bool privileged(PSID sid){return sid_is(sid,L"S-1-5-18")||sid_is(sid,L"S-1-5-32-544")||sid_is(sid,L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");}
// Reject writable/reparse targets, never repair or widen their permissions.
inline void protected_object(HANDLE h,bool strict_children){
 PSECURITY_DESCRIPTOR sd=nullptr;PSID owner=nullptr;PACL acl=nullptr;
 need(GetSecurityInfo(h,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,nullptr,&acl,nullptr,&sd)==ERROR_SUCCESS);
 struct Free {PSECURITY_DESCRIPTOR p;~Free(){LocalFree(p);}} free{sd};
 need(owner&&privileged(owner)&&acl);BOOL present=FALSE,def=FALSE;PACL check=nullptr;need(GetSecurityDescriptorDacl(sd,&present,&check,&def)&&present&&check);
 for(DWORD i=0;i<acl->AceCount;++i){void* ptr=nullptr;need(GetAce(acl,i,&ptr));auto* head=(ACE_HEADER*)ptr;
  if(head->AceFlags&INHERIT_ONLY_ACE)continue;
  if(head->AceType==ACCESS_DENIED_ACE_TYPE)continue;
  need(head->AceType==ACCESS_ALLOWED_ACE_TYPE);
  auto* a=(ACCESS_ALLOWED_ACE*)ptr;DWORD forbidden=WRITE_DAC|WRITE_OWNER|DELETE|FILE_DELETE_CHILD|GENERIC_ALL|GENERIC_WRITE;
  if(strict_children)forbidden|=FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_EA|FILE_WRITE_ATTRIBUTES;
  need(!(a->Mask&forbidden)||privileged((PSID)&a->SidStart));
 }
 BY_HANDLE_FILE_INFORMATION info{};need(GetFileInformationByHandle(h,&info));need(!(info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT));
}
struct FileId {std::uint32_t volume=0,high=0,low=0;};
inline FileId file_id(HANDLE h){BY_HANDLE_FILE_INFORMATION i{};need(GetFileInformationByHandle(h,&i));return{i.dwVolumeSerialNumber,i.nFileIndexHigh,i.nFileIndexLow};}
inline bool same_id(FileId a,FileId b){return a.volume==b.volume&&a.high==b.high&&a.low==b.low;}
inline Handle read_file(const std::wstring&p){Handle h(CreateFileW(p.c_str(),GENERIC_READ|READ_CONTROL,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));need(bool(h));protected_object(h.get(),true);return h;}
inline Digest file_hash(HANDLE h){
 LARGE_INTEGER sz{};need(GetFileSizeEx(h,&sz)&&sz.QuadPart>=0&&sz.QuadPart<=64*1024*1024);
 std::vector<unsigned char>b((std::size_t)sz.QuadPart);DWORD n=0;LARGE_INTEGER zero{};need(SetFilePointerEx(h,zero,nullptr,FILE_BEGIN));need(ReadFile(h,b.data(),(DWORD)b.size(),&n,nullptr)&&n==b.size());return sha256(b.data(),b.size());
}
template<class T>inline T read_struct(HANDLE h){LARGE_INTEGER sz{};need(GetFileSizeEx(h,&sz)&&sz.QuadPart==sizeof(T));T v{};DWORD n=0;need(ReadFile(h,&v,sizeof(v),&n,nullptr)&&n==sizeof(v));return v;}
#pragma pack(push,1)
struct Identity {std::uint32_t pid=0;std::uint64_t created=0;Digest image_path_sha256{},principal_sha256{};std::uint32_t session=0;std::uint8_t system=0;};
// No secrets: all fields are public ownership IDs, hashes, and bounded budgets.
struct Approval {
 char magic[8];std::uint32_t version;char nonce[32];FileId root;
 Digest service_sha256,guardian_sha256,helper_sha256;
 Identity controller;std::uint32_t lease_ms;std::uint32_t expected_helpers;
};
struct SelfClaim {char magic[8];std::uint32_t generation;char nonce[32];Identity process;};
struct Entry {char magic[8];std::uint64_t sequence;std::uint32_t event,generation,index,code,full_acceptance;Identity process;Digest config,approval;FileId root;char nonce[32];};
#pragma pack(pop)
inline Identity describe(HANDLE h){
 Identity i{};i.pid=GetProcessId(h);need(i.pid);FILETIME c{},e{},k{},u{};need(GetProcessTimes(h,&c,&e,&k,&u));i.created=ft(c);auto path=image(h);i.image_path_sha256=sha256(path.data(),path.size()*sizeof(wchar_t));
 Handle t;need(OpenProcessToken(h,TOKEN_QUERY,t.put()));DWORD n=0;GetTokenInformation(t.get(),TokenUser,nullptr,0,&n);need(n&&n<65536);std::vector<unsigned char>b(n);need(GetTokenInformation(t.get(),TokenUser,b.data(),n,&n));auto* user=(TOKEN_USER*)b.data();
 i.system=sid_is(user->User.Sid,L"S-1-5-18");need(GetTokenInformation(t.get(),TokenSessionId,&i.session,sizeof(i.session),&n));
 TOKEN_STATISTICS stats{};need(GetTokenInformation(t.get(),TokenStatistics,&stats,sizeof(stats),&n));
 std::vector<unsigned char>identity(GetLengthSid(user->User.Sid));need(CopySid((DWORD)identity.size(),identity.data(),user->User.Sid));
 auto add=[&](const void*p,std::size_t size){auto* c=(const unsigned char*)p;identity.insert(identity.end(),c,c+size);};add(&i.session,sizeof(i.session));add(&stats.AuthenticationId,sizeof(stats.AuthenticationId));i.principal_sha256=sha256(identity.data(),identity.size());return i;
}
inline bool same(const Identity&a,const Identity&b){return a.pid==b.pid&&a.created==b.created&&a.image_path_sha256==b.image_path_sha256&&a.principal_sha256==b.principal_sha256&&a.session==b.session&&a.system==b.system;}
inline std::wstring program_files(){PWSTR p=nullptr;need(SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramFiles,KF_FLAG_DEFAULT,nullptr,&p)));std::wstring s(p);CoTaskMemFree(p);return s;}
struct Scope {
 std::wstring nonce,root,service_exe,guardian_exe;std::vector<Handle> ancestors;Handle service_file,guardian_file,manifest_file;Approval approval{};FileId id{};
 explicit Scope(const std::wstring& n):nonce(n){
  need(valid_nonce(n));root=program_files()+L"\\OrangeSpacePhase1Guardian-"+n;
  // Hold every ancestor against rename/delete. This deliberately rejects UNC and reparse roots.
  need(root.size()>3&&root[1]==L':'&&root[2]==L'\\');
  for(std::size_t end=3;;){std::wstring p=root.substr(0,end);Handle h(CreateFileW(p.c_str(),FILE_READ_ATTRIBUTES|READ_CONTROL,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));need(bool(h));protected_object(h.get(),end==root.size());ancestors.push_back(std::move(h));if(end==root.size())break;end=root.find(L'\\',end+1);if(end==std::wstring::npos)end=root.size();}
  id=file_id(ancestors.back().get());
  service_exe=root+L"\\phase1_guardian_fixture_service.exe";guardian_exe=root+L"\\phase1_guardian_driver.exe";
  service_file=read_file(service_exe);guardian_file=read_file(guardian_exe);manifest_file=read_file(root+L"\\phase1_guardian_approval.bin");approval=read_struct<Approval>(manifest_file.get());
  need(std::memcmp(approval.magic,"OSGAP001",8)==0&&approval.version==1&&same_id(id,approval.root));
  std::string ascii(n.begin(),n.end());need(std::memcmp(approval.nonce,ascii.data(),32)==0);
  need(approval.lease_ms>=1000&&approval.lease_ms<=120000&&approval.expected_helpers<=2);
  need(file_hash(service_file.get())==approval.service_sha256&&file_hash(guardian_file.get())==approval.guardian_sha256);
 }
 void recheck(){for(std::size_t i=0;i<ancestors.size();++i)protected_object(ancestors[i].get(),i+1==ancestors.size());need(same_id(id,file_id(ancestors.back().get())));protected_object(service_file.get(),true);protected_object(guardian_file.get(),true);protected_object(manifest_file.get(),true);}
 std::wstring claim_name(unsigned generation)const{need(generation<16);return root+L"\\phase1_guardian_root_"+std::to_wstring(generation)+L".bin";}
};
inline Handle new_protected_file(const std::wstring& path){
 PSECURITY_DESCRIPTOR sd=nullptr;need(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)",SDDL_REVISION_1,&sd,nullptr));
 SECURITY_ATTRIBUTES sa{sizeof(sa),sd,FALSE};Handle h(CreateFileW(path.c_str(),GENERIC_WRITE|READ_CONTROL,FILE_SHARE_READ,&sa,CREATE_NEW,FILE_FLAG_WRITE_THROUGH|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));LocalFree(sd);need(bool(h));protected_object(h.get(),true);return h;
}
class Journal {
 Scope& scope_;Handle file_;std::uint64_t seq_=0;Digest config_{};bool poisoned_=false;
public:
 explicit Journal(Scope&s):scope_(s){
  s.recheck();file_=new_protected_file(s.root+L"\\phase1_guardian_receipt.bin");
  std::wstring config=L"OrangeSpaceFoundation|LocalSystem|own_process|demand|"+s.service_exe;config_=sha256(config.data(),config.size()*sizeof(wchar_t));
  need(append(0,0,describe(GetCurrentProcess())));
 }
 bool append(unsigned event,unsigned gen,const Identity& process={},unsigned index=0,unsigned code=0)noexcept{
  if(poisoned_)return false;
  try{scope_.recheck();Entry e{};std::memcpy(e.magic,"OSGRC001",8);e.sequence=++seq_;e.event=event;e.generation=gen;e.index=index;e.code=code;e.process=process;e.config=config_;e.approval=sha256(&scope_.approval,sizeof(scope_.approval));e.root=scope_.id;std::memcpy(e.nonce,scope_.approval.nonce,32);
   DWORD n=0;bool ok=WriteFile(file_.get(),&e,sizeof(e),&n,nullptr)&&n==sizeof(e)&&FlushFileBuffers(file_.get());poisoned_=!ok;return ok;
  }catch(...){poisoned_=true;return false;}
 }
};
struct Held {Handle object;Identity identity{};bool receipted=false;};
// Event IDs are fixed and contain no raw service config, argv, or exception text.
enum Event:unsigned { provision_intent=1,provision_owned=2,start_intent=3,start_returned=4,root_held=5,helper_held=6,operation_intent=7,operation_returned=8,public_error=9,absent=10,restart_generation=11,watch_reason=12,service_status=13,final_report=14 };
class WinAdapter final:public Adapter {
 Scope& s_;Journal& j_;ScHandle manager_,service_;Held root_;Handle helper_file_,controller_;std::vector<Held> helpers_,history_;IntentSet intents_;unsigned gen_=0;bool attempted_=false,created_=false;std::uint64_t earliest_=0;
 void prewrite(){
  unsigned mask=0;for(unsigned h=0;h<helpers();++h)if(helpers_[h].receipted)mask|=1u<<h;
  intents_.prepare(root_.receipted,mask,[&](Action action,unsigned index){
   auto identity=action==Action::terminate_helper?helpers_[index].identity:root_.identity;
   return j_.append(operation_intent,gen_,identity,action==Action::remove?helpers():index,(unsigned)action);
  });
 }
 bool config_ok(){
  if(!created_||!service_)return false;
  s_.recheck();
  DWORD n=0;QueryServiceConfigW(service_.get(),nullptr,0,&n);if(GetLastError()!=ERROR_INSUFFICIENT_BUFFER||!n||n>65536)return false;std::vector<unsigned char>b(n);auto* c=(QUERY_SERVICE_CONFIGW*)b.data();if(!QueryServiceConfigW(service_.get(),c,n,&n))return false;
  return c->dwServiceType==SERVICE_WIN32_OWN_PROCESS&&c->dwStartType==SERVICE_DEMAND_START&&c->dwErrorControl==SERVICE_ERROR_IGNORE&&c->lpBinaryPathName&&std::wstring(c->lpBinaryPathName)==L"\""+s_.service_exe+L"\""&&c->lpServiceStartName&&_wcsicmp(c->lpServiceStartName,L"LocalSystem")==0&&c->lpDependencies&&!*c->lpDependencies;
 }
 bool held_valid(Held& h,const std::wstring&path){
  try{return h.object&&h.receipted&&h.identity.system&&same(h.identity,describe(h.object.get()))&&equal_path(image(h.object.get()),path)&&config_ok();}catch(...){return false;}
 }
 bool post(bool result,Action a,unsigned index=0){return j_.append(operation_returned,gen_,root_.identity,index,(unsigned(a)<<16)|(result?0:1))&&result;}
public:
 WinAdapter(Scope&s,Journal&j,HANDLE controller):s_(s),j_(j){
  need(DuplicateHandle(GetCurrentProcess(),controller,GetCurrentProcess(),controller_.put(),PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,0));
  need(same(describe(controller_.get()),s_.approval.controller)&&WaitForSingleObject(controller_.get(),0)==WAIT_TIMEOUT);
 }
 bool owned()const{return created_;}
 unsigned generation()const{return gen_;}
 bool provision(){
  need(!created_);s_.recheck();
  for(unsigned g=0;g<16;++g){DWORD attr=GetFileAttributesW(s_.claim_name(g).c_str());need(attr==INVALID_FILE_ATTRIBUTES&&GetLastError()==ERROR_FILE_NOT_FOUND);}
  manager_.reset(OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT|SC_MANAGER_CREATE_SERVICE));need(bool(manager_));
  SC_HANDLE prior=OpenServiceW(manager_.get(),L"OrangeSpaceFoundation",SERVICE_QUERY_STATUS);if(prior){CloseServiceHandle(prior);return false;}need(GetLastError()==ERROR_SERVICE_DOES_NOT_EXIST);
  need(j_.append(provision_intent,gen_));prewrite();need(intents_.permits(Action::stop)&&intents_.permits(Action::remove));auto command=L"\""+s_.service_exe+L"\"";
  service_.reset(CreateServiceW(manager_.get(),L"OrangeSpaceFoundation",L"OrangeSpaceFoundation",SERVICE_QUERY_CONFIG|SERVICE_QUERY_STATUS|SERVICE_START|SERVICE_STOP|DELETE,SERVICE_WIN32_OWN_PROCESS,SERVICE_DEMAND_START,SERVICE_ERROR_IGNORE,command.c_str(),nullptr,nullptr,nullptr,L"LocalSystem",nullptr));
  if(!service_)return false;
  created_=true;bool noted=j_.append(provision_owned,gen_);return config_ok()&&noted;
 }
 bool start(){
  if(!config_ok()||attempted_||!before(Action::stop)||!intents_.permits(Action::remove))return false;
  s_.recheck();
  // Refuse a prior generation claim, even if it looks like ours.
  DWORD attr=GetFileAttributesW(s_.claim_name(gen_).c_str());if(attr!=INVALID_FILE_ATTRIBUTES)return false;DWORD e=GetLastError();if(e!=ERROR_FILE_NOT_FOUND)return false;
  if(!j_.append(start_intent,gen_))return false;
  attempted_=true;earliest_=now();
  auto arg=std::to_wstring(gen_);LPCWSTR args[]={arg.c_str()};bool ok=StartServiceW(service_.get(),1,args)!=FALSE;bool noted=j_.append(start_returned,gen_,{},0,ok?0:1);return ok&&noted;
 }
 Status query()override{
  if(!config_ok())return{};
  SERVICE_STATUS_PROCESS p{};DWORD n=0;if(!QueryServiceStatusEx(service_.get(),SC_STATUS_PROCESS_INFO,(LPBYTE)&p,sizeof(p),&n))return{};
  State st=State::unknown;switch(p.dwCurrentState){case SERVICE_STOPPED:st=State::stopped;break;case SERVICE_START_PENDING:st=State::start_pending;break;case SERVICE_STOP_PENDING:st=State::stop_pending;break;case SERVICE_RUNNING:st=State::running;break;default:break;}
  // Pending SCM PIDs are NOT authority. capture() uses the protected self-claim.
  return{st,p.dwProcessId};
 }
 bool capture(std::uint32_t /*untrusted_pending_pid*/)override{
  if(root_.object)return root_.receipted;
  if(!attempted_||!config_ok())return false;
  try{auto claim=read_file(s_.claim_name(gen_));auto c=read_struct<SelfClaim>(claim.get());std::string nonce(s_.nonce.begin(),s_.nonce.end());
   need(std::memcmp(c.magic,"OSGRT001",8)==0&&c.generation==gen_&&std::memcmp(c.nonce,nonce.data(),32)==0&&c.process.system&&c.process.created>=earliest_);
   Held candidate;candidate.object.reset(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE|PROCESS_TERMINATE,FALSE,c.process.pid));need(bool(candidate.object));candidate.identity=describe(candidate.object.get());need(same(c.process,candidate.identity)&&equal_path(image(candidate.object.get()),s_.service_exe));
   // A protected self-claim is emitted only inside the fixed dummy's SCM ServiceMain.
   // Cross-check SCM's PID when documented valid; never use pending PID to kill.
   auto status=query();need(status.state!=State::unknown);if(status.state==State::running)need(status.pid==candidate.identity.pid);
   root_=std::move(candidate);intents_.written[1]=false;intents_.written[4]=false;root_.receipted=j_.append(root_held,gen_,root_.identity);prewrite();return root_.receipted&&intents_.permits(Action::terminate_root);
  }catch(...){return false;}
 }
 bool has_root()const override{return bool(root_.object);}
 bool start_attempted()const override{return attempted_;}
 bool valid_root()override{return held_valid(root_,s_.service_exe);}
 bool root_exited()override{return root_.object&&WaitForSingleObject(root_.object.get(),0)==WAIT_OBJECT_0;}
 // In-process integration only; no driver command imports arbitrary handles or paths.
 // The caller's protected metadata is reviewed independently of this narrow adapter.
 bool retain_helper(HANDLE actual,const Identity& approved){
  if(helpers_.size()>=s_.approval.expected_helpers||!approved.system||!config_ok()||WaitForSingleObject(controller_.get(),0)!=WAIT_TIMEOUT)return false;
  try{if(!helper_file_)helper_file_=read_file(s_.root+L"\\sing-box.exe");need(file_hash(helper_file_.get())==s_.approval.helper_sha256);Held h;need(DuplicateHandle(GetCurrentProcess(),actual,GetCurrentProcess(),h.object.put(),PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_TERMINATE|SYNCHRONIZE,FALSE,0));h.identity=describe(h.object.get());need(same(h.identity,approved)&&equal_path(image(h.object.get()),s_.root+L"\\sing-box.exe")&&WaitForSingleObject(h.object.get(),0)==WAIT_TIMEOUT);
   for(const auto& old:helpers_)need(old.identity.pid!=h.identity.pid||old.identity.created!=h.identity.created);
   helpers_.push_back(std::move(h));auto& owned=helpers_.back();unsigned index=(unsigned)helpers_.size()-1;intents_.written[2+index]=false;intents_.written[4]=false;owned.receipted=j_.append(helper_held,gen_,owned.identity,index);prewrite();return owned.receipted&&intents_.permits(Action::terminate_helper,index)&&WaitForSingleObject(controller_.get(),0)==WAIT_TIMEOUT;
  }catch(...){return false;}
 }
 unsigned helpers()const override{return(unsigned)helpers_.size();}
 bool valid_helper(unsigned i)override{return i<helpers_.size()&&held_valid(helpers_[i],s_.root+L"\\sing-box.exe");}
 bool helper_exited(unsigned i)override{return i<helpers_.size()&&WaitForSingleObject(helpers_[i].object.get(),0)==WAIT_OBJECT_0;}
 bool before(Action a,unsigned i=0)override{
  if(!config_ok())return false;
  if(a==Action::terminate_root&&!valid_root())return false;
  if(a==Action::terminate_helper&&!valid_helper(i))return false;
  // Prewrite ALL known exact-object cleanup intents before the first effect.
  // Later report/disk failure does not revoke these already durable narrow intents.
  prewrite();
  return intents_.permits(a,i);
 }
 bool stop()override{if(!intents_.permits(Action::stop)||!config_ok())return false;SERVICE_STATUS st{};bool ok=ControlService(service_.get(),SERVICE_CONTROL_STOP,&st)!=FALSE;return post(ok,Action::stop);}
 bool terminate_root()override{if(!intents_.permits(Action::terminate_root)||!valid_root())return false;return post(TerminateProcess(root_.object.get(),0xe0470001)!=FALSE,Action::terminate_root);}
 bool terminate_helper(unsigned i)override{if(!intents_.permits(Action::terminate_helper,i)||!valid_helper(i))return false;bool ok=TerminateProcess(helpers_[i].object.get(),0xe0470002)!=FALSE;return post(ok,Action::terminate_helper,i);}
 bool remove_and_verify_absence()override{
  if(!intents_.permits(Action::remove)||!config_ok()||query().state!=State::stopped||(attempted_&&!root_exited()))return false;
  if(helpers_.size()!=s_.approval.expected_helpers)return false;
  for(unsigned i=0;i<helpers();++i)if(!helper_exited(i))return false;
  if(!DeleteService(service_.get()))return false;
  bool noted=j_.append(operation_returned,gen_,root_.identity,0,(unsigned)Action::remove<<16);service_.reset();
  for(unsigned i=0;i<20;++i){SC_HANDLE h=OpenServiceW(manager_.get(),L"OrangeSpaceFoundation",SERVICE_QUERY_STATUS);if(h){CloseServiceHandle(h);}else{DWORD e=GetLastError();if(e==ERROR_SERVICE_DOES_NOT_EXIST){created_=false;bool final=j_.append(absent,gen_,root_.identity);return final&&noted;}if(e!=ERROR_SERVICE_MARKED_FOR_DELETE)return false;}Sleep(100);}
  return false;
 }
 void pause()override{Sleep(100);}
 bool record(Code c)override{return j_.append(public_error,gen_,root_.identity,0,(unsigned)c);}
 bool next_generation(){
  if(gen_>=15||!root_exited()||query().state!=State::stopped||helpers_.size()!=s_.approval.expected_helpers)return false;
  for(unsigned i=0;i<helpers();++i)if(!helper_exited(i))return false;
  if(!j_.append(restart_generation,gen_+1,root_.identity))return false;
  history_.push_back(std::move(root_));for(auto& h:helpers_)history_.push_back(std::move(h));helpers_.clear();root_=Held{};intents_=IntentSet{};++gen_;attempted_=false;return true;
 }
};
} // namespace phase1_guardian::win
