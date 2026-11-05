#pragma once
#ifndef UNICODE
#define UNICODE
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// Test-only Win32 transport/identity primitives. Never production entry points.
#include "orangespace/node_session.hpp"
#include <windows.h>
#include "phase1_os_b_policy.hpp"
#include <sddl.h>
#include <userenv.h>
#include <shlobj.h>
#include <bcrypt.h>
#include <memory>
#include <algorithm>
namespace phase1_os_b {
namespace ns=orangespace::node_session;
struct Failure {const char* stage;DWORD code;};
inline void need(bool ok,const char* stage){if(!ok){auto e=GetLastError();throw Failure{stage,e?e:ERROR_INVALID_DATA};}}
struct Handle {
 HANDLE h=nullptr;Handle()=default;explicit Handle(HANDLE v):h(v){}
 Handle(const Handle&)=delete;Handle& operator=(const Handle&)=delete;
 Handle(Handle&& o)noexcept:h(o.h){o.h=nullptr;}
 ~Handle(){reset();}
 void reset(HANDLE v=nullptr){if(h&&h!=INVALID_HANDLE_VALUE)CloseHandle(h);h=v;}
};
struct JobAdmission {
 std::vector<BYTE> storage;LPPROC_THREAD_ATTRIBUTE_LIST list=nullptr;
 explicit JobAdmission(HANDLE& job){
  SIZE_T n=0;InitializeProcThreadAttributeList(nullptr,1,0,&n);need(n>0&&n<65536,"job_attribute_size");storage.resize(n);list=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
  if(!InitializeProcThreadAttributeList(list,1,0,&n)){list=nullptr;need(false,"job_attribute_init");}
  if(!UpdateProcThreadAttribute(list,0,PROC_THREAD_ATTRIBUTE_JOB_LIST,&job,sizeof(job),nullptr,nullptr)){auto e=GetLastError();DeleteProcThreadAttributeList(list);list=nullptr;SetLastError(e);need(false,"job_attribute_set");}
 }
 ~JobAdmission(){if(list)DeleteProcThreadAttributeList(list);}
};
inline bool launch_privileges(HANDLE token){
 DWORD n=0;GetTokenInformation(token,TokenPrivileges,nullptr,0,&n);need(n>0&&n<65536,"launch_privileges_size");std::vector<BYTE>b(n);need(GetTokenInformation(token,TokenPrivileges,b.data(),n,&n),"launch_privileges");
 const auto* p=reinterpret_cast<TOKEN_PRIVILEGES*>(b.data());
 for(const auto* name:{SE_INCREASE_QUOTA_NAME,SE_ASSIGNPRIMARYTOKEN_NAME}){
  LUID luid{};need(LookupPrivilegeValueW(nullptr,name,&luid),"launch_privilege_lookup");bool present=false;for(DWORD i=0;i<p->PrivilegeCount;++i)if(p->Privileges[i].Luid.LowPart==luid.LowPart&&p->Privileges[i].Luid.HighPart==luid.HighPart&&!(p->Privileges[i].Attributes&SE_PRIVILEGE_REMOVED))present=true;
  if(!present)return false;
 }return true;
}
struct Wiped {
 std::string value;
 explicit Wiped(std::string s={}):value(std::move(s)){}
 Wiped(const Wiped&)=delete;Wiped& operator=(const Wiped&)=delete;
 ~Wiped(){if(!value.empty())SecureZeroMemory(value.data(),value.size());}
};
struct LocalFreeDeleter{void operator()(void* p)const{if(p)LocalFree(p);}};
using Local=std::unique_ptr<void,LocalFreeDeleter>;
inline std::wstring wide(std::string_view s){
 need(!s.empty()&&s.size()<98304&&s.find(char(0))==std::string_view::npos,"utf8_size");
 int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),int(s.size()),nullptr,0);need(n>0,"utf8");
 std::wstring out(n,L'\0');need(MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),int(s.size()),out.data(),n)==n,"utf8");return out;
}
inline std::string narrow(std::wstring_view s){
 int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s.data(),int(s.size()),nullptr,0,nullptr,nullptr);need(n>0,"wide");
 std::string out(n,'\0');need(WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s.data(),int(s.size()),out.data(),n,nullptr,nullptr)==n,"wide");return out;
}
struct Identity{std::wstring sid;std::uint64_t luid{};DWORD session{};};
inline Identity identity(HANDLE token){
 DWORD n=0;GetTokenInformation(token,TokenUser,nullptr,0,&n);need(n>0&&n<=65536,"token_size");std::vector<BYTE> info(n);
 need(GetTokenInformation(token,TokenUser,info.data(),n,&n),"token_user");wchar_t* sid=nullptr;
 need(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(info.data())->User.Sid,&sid),"token_sid");Local free(sid);
 TOKEN_STATISTICS stats{};need(GetTokenInformation(token,TokenStatistics,&stats,sizeof(stats),&n),"token_luid");
 Identity id{sid,(std::uint64_t(static_cast<std::uint32_t>(stats.AuthenticationId.HighPart))<<32)|stats.AuthenticationId.LowPart,0};
 need(GetTokenInformation(token,TokenSessionId,&id.session,sizeof(id.session),&n),"token_session");return id;
}
inline Identity current_identity(){
 HANDLE impersonation=nullptr;if(OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&impersonation)){Handle close(impersonation);throw Failure{"no_thread_impersonation",ERROR_BAD_IMPERSONATION_LEVEL};}
 need(GetLastError()==ERROR_NO_TOKEN,"thread_token_query");Handle t;need(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&t.h),"process_token");return identity(t.h);
}
inline bool ordinary(){
 Handle t;need(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&t.h),"ordinary_token");DWORD n=0;TOKEN_ELEVATION e{};
 need(GetTokenInformation(t.h,TokenElevation,&e,sizeof(e),&n),"ordinary_elevation");
 BYTE sid[SECURITY_MAX_SID_SIZE];n=sizeof(sid);need(CreateWellKnownSid(WinBuiltinAdministratorsSid,nullptr,sid,&n),"admin_sid");BOOL admin=TRUE;
 need(CheckTokenMembership(nullptr,sid,&admin),"admin_member");
 GetTokenInformation(t.h,TokenIntegrityLevel,nullptr,0,&n);need(n>0&&n<65536,"integrity_size");std::vector<BYTE>b(n);
 need(GetTokenInformation(t.h,TokenIntegrityLevel,b.data(),n,&n),"integrity");auto p=reinterpret_cast<TOKEN_MANDATORY_LABEL*>(b.data())->Label.Sid;
 return !e.TokenIsElevated&&!admin&&*GetSidSubAuthority(p,*GetSidSubAuthorityCount(p)-1)==SECURITY_MANDATORY_MEDIUM_RID;
}
// Overlapped byte pipes only. One owned pending op/process, max_frame+4
// bytes and two native handles. No stack buffer/OVERLAPPED reaches the kernel.
// User-mode waits: absolute frame deadline + at most 50ms cancellation grace.
// Native kernel calls/CloseHandle are not a real-time guarantee.
struct NativeIo {
 Handle pipe,event;OVERLAPPED ov{};Wiped bytes;bool pending=false;
 NativeIo(HANDLE source,DWORD size):bytes(std::string(size,'\0')){
  need(DuplicateHandle(GetCurrentProcess(),source,GetCurrentProcess(),&pipe.h,0,FALSE,DUPLICATE_SAME_ACCESS),"io_duplicate");
  event.reset(CreateEventW(nullptr,TRUE,FALSE,nullptr));need(event.h!=nullptr,"io_event");ov.hEvent=event.h;
 }
 bool completed()const noexcept{return WaitForSingleObject(event.h,0)==WAIT_OBJECT_0&&HasOverlappedIoCompleted(&ov);}
 void cancel()noexcept{CancelIoEx(pipe.h,&ov);} // failure never becomes success
 void wait_cancel(unsigned ms)noexcept{WaitForSingleObject(event.h,ms);}
};
inline IoBudget<NativeIo> private_io_budget;
struct IoLease {
 std::unique_ptr<NativeIo> op;
 IoLease(HANDLE h,DWORD size){
  need(size<=max_frame+4,"io_owned_size");
  if(!private_io_budget.reserve())throw Failure{"io_pending_budget_or_poison",ERROR_BUSY};
  try{op=std::make_unique<NativeIo>(h,size);}catch(...){private_io_budget.release();throw;}
 }
 ~IoLease(){
  if(op&&op->pending&&!op->completed()&&cancel_pending(*op)==CancelOutcome::retained){private_io_budget.quarantine(std::move(op));return;}
  op.reset();private_io_budget.release();
 }
 IoLease(const IoLease&)=delete;IoLease& operator=(const IoLease&)=delete;
};
inline void require_io_time(ULONGLONG deadline){
 if(GetTickCount64()>=deadline)throw Failure{"pipe_timeout",WAIT_TIMEOUT};
}
inline void await_io(NativeIo& op,ULONGLONG deadline,DWORD& n){
 const auto left=remaining_ms(GetTickCount64(),deadline);
 if(!left||WaitForSingleObject(op.event.h,left)!=WAIT_OBJECT_0)throw Failure{"pipe_timeout",WAIT_TIMEOUT};
 require_io_time(deadline);
 need(GetOverlappedResult(op.pipe.h,&op.ov,&n,FALSE),"pipe_io_result");
 require_io_time(deadline);
}
inline void transfer_until(HANDLE h,void* data,DWORD size,bool write,ULONGLONG deadline){
 need(size>0&&size<=max_frame+4,"io_size");auto* p=static_cast<char*>(data);IoProgress progress(size,deadline);
 while(!progress.complete()){
  if(!progress.remaining(GetTickCount64()))throw Failure{"pipe_timeout",WAIT_TIMEOUT};
  const auto chunk=progress.left();IoLease lease(h,chunk);auto& op=*lease.op;if(write)std::copy_n(p+progress.done,chunk,op.bytes.value.data());DWORD n=0;
  require_io_time(progress.deadline); // Allocation/duplication/event and write staging use the original budget.
  BOOL ok=write?WriteFile(op.pipe.h,op.bytes.value.data(),chunk,&n,&op.ov):ReadFile(op.pipe.h,op.bytes.value.data(),chunk,&n,&op.ov);
  if(!ok){const auto error=GetLastError();need(error==ERROR_IO_PENDING,"pipe_io");op.pending=true;await_io(op,progress.deadline,n);}
  require_io_time(progress.deadline);
  const auto offset=progress.done;need(progress.advance(n),"pipe_exact");
  require_io_time(progress.deadline); // Includes the final chunk, before exposing read bytes or success.
  if(!write)std::copy_n(op.bytes.value.data(),n,p+offset);
 }
}
inline void send_private(HANDLE h,std::string_view s,DWORD timeout){
 const auto deadline=GetTickCount64()+timeout;
 need(!s.empty()&&s.size()<=max_frame,"private_size");Wiped packet;packet.value.reserve(4+s.size());put32(packet.value,DWORD(s.size()));packet.value.append(s);
 transfer_until(h,packet.value.data(),DWORD(packet.value.size()),true,deadline);
}
inline std::string read_private(HANDLE h,DWORD timeout){
 const auto deadline=GetTickCount64()+timeout;char head[4];transfer_until(h,head,4,false,deadline);std::size_t p=0;auto n=get32(std::string_view(head,4),p);need(n>0&&n<=max_frame,"private_size");Wiped body{std::string(n,'\0')};
 transfer_until(h,body.value.data(),n,false,deadline);return std::move(body.value);
}
inline void connect_owned_private(HANDLE pipe,DWORD timeout){
 const auto deadline=GetTickCount64()+timeout;IoLease lease(pipe,0);auto& op=*lease.op;
 require_io_time(deadline);
 BOOL ok=ConnectNamedPipe(op.pipe.h,&op.ov);auto error=GetLastError();if(ok||error==ERROR_PIPE_CONNECTED){require_io_time(deadline);return;}
 need(error==ERROR_IO_PENDING,"connect_pending");op.pending=true;DWORD n=0;await_io(op,deadline,n);
}
inline Local descriptor(const std::wstring& sddl){PSECURITY_DESCRIPTOR p=nullptr;need(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&p,nullptr),"descriptor");return Local(p);}
inline bool path_absent(const std::wstring& path){auto a=GetFileAttributesW(path.c_str());auto e=GetLastError();return a==INVALID_FILE_ATTRIBUTES&&(e==ERROR_FILE_NOT_FOUND||e==ERROR_PATH_NOT_FOUND);}
inline Presence registry_presence(HKEY root,const std::wstring& key){HKEY h=nullptr;auto e=RegOpenKeyExW(root,key.c_str(),0,KEY_READ,&h);if(h)RegCloseKey(h);return e==ERROR_FILE_NOT_FOUND?Presence::absent:(e==ERROR_SUCCESS?Presence::present:Presence::unknown);}
inline bool registry_absent(HKEY root,const std::wstring& key){return registry_presence(root,key)==Presence::absent;}
inline std::wstring store_root(){PWSTR p=nullptr;need(SHGetKnownFolderPath(FOLDERID_LocalAppData,0,nullptr,&p)==S_OK,"b_local_appdata");std::wstring out=p;CoTaskMemFree(p);return out+L"\\OrangeSpace-Credentials-v1";}
inline std::string random_hex(std::size_t bytes){std::vector<BYTE> b(bytes);need(BCryptGenRandom(nullptr,b.data(),ULONG(b.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG)==0,"random");std::string out;for(auto v:b){out+="0123456789abcdef"[v>>4];out+="0123456789abcdef"[v&15];}SecureZeroMemory(b.data(),b.size());return out;}
}
