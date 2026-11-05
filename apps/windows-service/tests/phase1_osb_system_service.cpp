#include "phase1_osb_system_win.hpp"
#include "phase1_osb_system_config.hpp" // generated into isolated scratch build dir
#include <aclapi.h>
#include <wtsapi32.h>
#include <sstream>
#include <set>
#include <cstring>
#ifndef PROC_THREAD_ATTRIBUTE_JOB_LIST
#define PROC_THREAD_ATTRIBUTE_JOB_LIST ProcThreadAttributeValue(13,FALSE,TRUE,FALSE)
#endif
namespace {
using namespace osbs;
const std::wstring root=OSBS_ROOT;
const std::wstring service_name=L"OrangeSpaceOSBAdmission-" OSBS_NONCE;
constexpr const wchar_t* service_leaf=L"phase1_osb_system_service.exe";
constexpr const wchar_t* worker_leaf=L"phase1_osb_system_probe_worker.exe";
SERVICE_STATUS_HANDLE status_handle=nullptr;
Handle stop_event;
void status(DWORD state,DWORD code=NO_ERROR){SERVICE_STATUS s{};s.dwServiceType=SERVICE_WIN32_OWN_PROCESS;s.dwCurrentState=state;s.dwControlsAccepted=state==SERVICE_RUNNING?SERVICE_ACCEPT_STOP:0;s.dwWin32ExitCode=code;s.dwWaitHint=state==SERVICE_STOP_PENDING?15000:0;SetServiceStatus(status_handle,&s);}
DWORD WINAPI control(DWORD command,DWORD,void*,void*){if(command==SERVICE_CONTROL_STOP){SetEvent(stop_event.h);status(SERVICE_STOP_PENDING);}return NO_ERROR;}
bool privileged(PSID sid,bool ancestor){return trusted_owner(sid_text(sid),ancestor);}
std::wstring canonical(HANDLE h){std::vector<wchar_t>b(32768);DWORD n=GetFinalPathNameByHandleW(h,b.data(),static_cast<DWORD>(b.size()),FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);require(n>0&&n<b.size());return std::wstring(b.data(),n);}
void validate(HANDLE h,bool directory,bool ancestor,const std::wstring& path){
 BY_HANDLE_FILE_INFORMATION f{};win(GetFileInformationByHandle(h,&f)!=0);
 require(!(f.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT));require(bool(f.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)==directory);
 if(!directory)require(f.nNumberOfLinks==1);
 std::wstring expected=L"\\\\?\\"+path;if(expected.size()>7&&expected.back()==L'\\')expected.pop_back();
 std::wstring actual=canonical(h);if(actual.size()>7&&actual.back()==L'\\')actual.pop_back();
 require(_wcsicmp(actual.c_str(),expected.c_str())==0);
 PSID owner=nullptr;PACL dacl=nullptr;PSECURITY_DESCRIPTOR sd=nullptr;
 DWORD security_error=GetSecurityInfo(h,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,nullptr,&dacl,nullptr,&sd);if(security_error!=ERROR_SUCCESS)throw security_error;
 bool safe=owner&&privileged(owner,ancestor)&&dacl;
 SECURITY_DESCRIPTOR_CONTROL ctl{};DWORD revision=0;
 if(!GetSecurityDescriptorControl(sd,&ctl,&revision)||(!ancestor&&!(ctl&SE_DACL_PROTECTED)))safe=false;

 if(dacl)for(DWORD i=0;i<dacl->AceCount;++i){void* p=nullptr;if(!GetAce(dacl,i,&p)){safe=false;break;}auto head=static_cast<ACE_HEADER*>(p);if(head->AceFlags&INHERIT_ONLY_ACE)continue;
  if(head->AceType==ACCESS_DENIED_ACE_TYPE)continue;
  if(head->AceType!=ACCESS_ALLOWED_ACE_TYPE){safe=false;break;}
  auto ace=static_cast<ACCESS_ALLOWED_ACE*>(p);if(!acl_ace_safe(head->AceType,head->AceFlags,ace->Mask,sid_text(&ace->SidStart)))safe=false;
 }
 LocalFree(sd);require(safe);
}
struct Adapter {
 std::vector<Handle> held;Handle wt,job,process,thread,child_token;std::string sid,worker_hash;Identity source{};
 DWORD error=0,pid=0,exit_code=STILL_ACTIVE;FILETIME creation{};BY_HANDLE_FILE_INFORMATION worker_file{};Identity observed_child{};bool job_member=false;bool receipt_ready=false,child_created=false,child_reaped=false,cleanup_uncertain=false;std::string stage="startup";
 template<class F> bool run(const char* name,F fn){stage=name;try{fn();return true;}catch(DWORD e){error=e;return false;}catch(...){error=ERROR_UNHANDLED_EXCEPTION;return false;}}
 bool stopped(){return WaitForSingleObject(stop_event.h,0)!=WAIT_TIMEOUT;}
 void checkpoint(){require(!stopped());}
 Handle open(const std::wstring& p,bool dir,bool ancestor=false){
  Handle h(CreateFileW(p.c_str(),GENERIC_READ|READ_CONTROL,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|(dir?FILE_FLAG_BACKUP_SEMANTICS:0),nullptr));win(bool(h));validate(h.h,dir,ancestor,p);return h;
 }
 void record(const wchar_t* leaf,const std::string& state){
  // Immutable per-stage receipt. A fresh root cannot replay or replace a prior receipt.
  std::wstring final=root+L"\\"+leaf,temp=final+L".pending";
  PSECURITY_DESCRIPTOR sd=nullptr;win(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)",SDDL_REVISION_1,&sd,nullptr)!=0);
  SECURITY_ATTRIBUTES sa{sizeof(sa),sd,FALSE};Handle f(CreateFileW(temp.c_str(),GENERIC_READ|GENERIC_WRITE|READ_CONTROL|DELETE,FILE_SHARE_READ,&sa,CREATE_NEW,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_WRITE_THROUGH,nullptr));DWORD create_error=GetLastError();LocalFree(sd);if(!f)throw create_error;validate(f.h,false,false,temp);
  std::ostringstream o;o<<"schema=osb-system-admission-v1\nnonce="<<OSBS_NONCE_A<<"\nstage="<<state<<"\nwin32="<<error<<"\npid="<<pid<<"\ncreation_high="<<creation.dwHighDateTime<<"\ncreation_low="<<creation.dwLowDateTime<<"\nexit="<<exit_code<<"\nchild_created="<<child_created<<"\nchild_reaped="<<child_reaped<<"\ncleanup_uncertain="<<cleanup_uncertain<<"\nassign_present="<<assign_present<<"\nquota_present="<<quota_present<<"\ntcb_enabled="<<tcb_enabled<<"\nsource_session="<<source.session<<"\nsource_logon_high="<<source.logon.HighPart<<"\nsource_logon_low="<<source.logon.LowPart<<"\nos_b=false\nfull_acceptance=false\nscm_removal_verified=false\n";
  o<<"source_sid="<<source.sid<<"\nchild_sid="<<observed_child.sid<<"\nchild_session="<<observed_child.session<<"\njob_member="<<job_member<<"\nworker_volume="<<worker_file.dwVolumeSerialNumber<<"\nworker_index_high="<<worker_file.nFileIndexHigh<<"\nworker_index_low="<<worker_file.nFileIndexLow<<"\nplan_sha256="<<OSBS_PLAN_SHA256<<"\nworker_sha256="<<worker_hash<<"\n";
  auto text=o.str();DWORD written=0;win(WriteFile(f.h,text.data(),static_cast<DWORD>(text.size()),&written,nullptr)!=0);require(written==text.size());win(FlushFileBuffers(f.h)!=0);require(bytes(f.h)==text);
  DWORD size=static_cast<DWORD>(sizeof(FILE_RENAME_INFO)+final.size()*sizeof(wchar_t));std::vector<BYTE>b(size);auto r=reinterpret_cast<FILE_RENAME_INFO*>(b.data());r->ReplaceIfExists=FALSE;r->RootDirectory=nullptr;r->FileNameLength=static_cast<DWORD>(final.size()*sizeof(wchar_t));memcpy(r->FileName,final.data(),r->FileNameLength);win(SetFileInformationByHandle(f.h,FileRenameInfo,r,size)!=0);validate(f.h,false,false,final);
 }
 bool assign_present=false,quota_present=false,tcb_enabled=false;
 bool authority(){return run("authority",[&]{
  HANDLE t=nullptr;win(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&t)!=0);Handle token(t);auto id=identity(t);require(id.sid=="S-1-5-18"&&id.session==0);
  assign_present=privilege(t,SE_ASSIGNPRIMARYTOKEN_NAME,false);quota_present=privilege(t,SE_INCREASE_QUOTA_NAME,false);tcb_enabled=privilege(t,SE_TCB_NAME,true);
  require(assign_present&&quota_present&&tcb_enabled);checkpoint();
 });}
 bool protect(){return run("protect",[&]{
  require(valid_nonce(OSBS_NONCE_A));require(root==L"C:\\Program Files\\OrangeSpace-OSB-Admission-" OSBS_NONCE);
  held.push_back(open(L"C:\\",true,true));held.push_back(open(L"C:\\Program Files",true,true));held.push_back(open(root,true));
  wchar_t module[32768]{};DWORD n=GetModuleFileNameW(nullptr,module,32768);require(n>0&&n<32768);require(_wcsicmp(module,(root+L"\\"+service_leaf).c_str())==0);
  held.push_back(open(root+L"\\"+service_leaf,false));held.push_back(open(root+L"\\phase1_osb_system_plan.txt",false));
  std::string plan=bytes(held.back().h);require(sha256(plan)==OSBS_PLAN_SHA256);
  Plan approved{};require(parse_plan(plan,OSBS_NONCE_A,approved));sid=approved.sid;worker_hash=approved.worker_hash;
  held.push_back(open(root+L"\\"+worker_leaf,false));require(sha256(bytes(held.back().h))==worker_hash);win(GetFileInformationByHandle(held.back().h,&worker_file)!=0);
  WIN32_FIND_DATAW d{};HANDLE find=FindFirstFileW((root+L"\\*").c_str(),&d);require(find!=INVALID_HANDLE_VALUE);std::set<std::wstring> leaves;
  do {std::wstring leaf=d.cFileName;if(leaf!=L"."&&leaf!=L"..")leaves.insert(leaf);}while(FindNextFileW(find,&d));DWORD last=GetLastError();FindClose(find);require(last==ERROR_NO_MORE_FILES);
  require(leaves==std::set<std::wstring>{service_leaf,worker_leaf,L"phase1_osb_system_plan.txt"});checkpoint();
 });}
 bool receipt(){return run("intent",[&]{record(L"phase1_osb_system_00_intent.txt","intent-before-token-and-process");receipt_ready=true;});}
 bool token(){return run("wts_token",[&]{
  checkpoint();HANDLE t=nullptr;win(WTSQueryUserToken(2,&t)!=0);wt.reset(t);source=identity(t);require(admission_identity(source.sid,sid,source.session,source.limited));
  // WTS identity is independently resolved through OS authority, not UI metadata.
  LPWSTR user=nullptr,domain=nullptr;DWORD u=0,d=0;
  BOOL a=WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,2,WTSUserName,&user,&u);DWORD ae=a?ERROR_SUCCESS:GetLastError();
  BOOL b=WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,2,WTSDomainName,&domain,&d);DWORD be=b?ERROR_SUCCESS:GetLastError();
  std::wstring account;if(a&&b&&user&&domain&&u>=2&&d>=2)account=std::wstring(domain)+L"\\"+user;
  if(user){WTSFreeMemory(user);}
  if(domain){WTSFreeMemory(domain);}
  if(!a){throw ae;}
  if(!b){throw be;}
  require(!account.empty());
  DWORD sn=0,dn=0;SID_NAME_USE use{};LookupAccountNameW(nullptr,account.c_str(),nullptr,&sn,nullptr,&dn,&use);require(sn>0&&sn<65536&&dn<32768);std::vector<BYTE>s(sn);std::vector<wchar_t>dom(dn+1);win(LookupAccountNameW(nullptr,account.c_str(),s.data(),&sn,dom.data(),&dn,&use)!=0);require(use==SidTypeUser&&sid_text(s.data())==source.sid);
  record(L"phase1_osb_system_01_token.txt","existing-limited-A-token-observed");checkpoint();
 });}
 bool atomic_create(){return run("atomic_create",[&]{
  checkpoint();job.reset(CreateJobObjectW(nullptr,nullptr));win(bool(job));win(SetHandleInformation(job.h,HANDLE_FLAG_INHERIT,0)!=0);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limit{};limit.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_ACTIVE_PROCESS;limit.BasicLimitInformation.ActiveProcessLimit=1;win(SetInformationJobObject(job.h,JobObjectExtendedLimitInformation,&limit,sizeof(limit))!=0);
  SIZE_T size=0;InitializeProcThreadAttributeList(nullptr,1,0,&size);require(size>0);std::vector<BYTE>storage(size);auto list=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());win(InitializeProcThreadAttributeList(list,1,0,&size)!=0);
  if(!UpdateProcThreadAttribute(list,0,PROC_THREAD_ATTRIBUTE_JOB_LIST,&job.h,sizeof(HANDLE),nullptr,nullptr)){DWORD e=GetLastError();DeleteProcThreadAttributeList(list);throw e;}
  STARTUPINFOEXW si{};si.StartupInfo.cb=sizeof(si);si.lpAttributeList=list;PROCESS_INFORMATION pi{};
  std::wstring app=root+L"\\"+worker_leaf;std::wstring cmd=L"\""+app+L"\" "+wide(sid)+L" 2 " OSBS_NONCE;
  wchar_t windows[32768]{};UINT n=GetWindowsDirectoryW(windows,32768);require(n>0&&n<32768);std::wstring env=L"SystemRoot="+std::wstring(windows);env.push_back(0);env.push_back(0);
  BOOL created=CreateProcessAsUserW(wt.h,app.c_str(),cmd.data(),nullptr,nullptr,FALSE,EXTENDED_STARTUPINFO_PRESENT|CREATE_SUSPENDED|CREATE_UNICODE_ENVIRONMENT|CREATE_NO_WINDOW,env.data(),root.c_str(),&si.StartupInfo,&pi);
  DWORD e=GetLastError();DeleteProcThreadAttributeList(list);if(!created)throw e;
  // Capture exact kernel objects immediately, while child is still suspended.
  process.reset(pi.hProcess);thread.reset(pi.hThread);pid=pi.dwProcessId;child_created=true;
  FILETIME ex{},k{},u{};win(GetProcessTimes(process.h,&creation,&ex,&k,&u)!=0);BOOL member=FALSE;win(IsProcessInJob(process.h,job.h,&member)!=0);require(member!=FALSE);job_member=member!=FALSE;
  record(L"phase1_osb_system_02_created.txt","held-suspended-child-atomic-job-member");checkpoint();
 });}
 bool child_identity(){return run("child_identity",[&]{
  HANDLE t=nullptr;win(OpenProcessToken(process.h,TOKEN_QUERY,&t)!=0);child_token.reset(t);auto child=identity(t);observed_child=child;require(admission_identity(child.sid,sid,child.session,child.limited));require(child.logon.LowPart==source.logon.LowPart&&child.logon.HighPart==source.logon.HighPart);
  wchar_t image[32768]{};DWORD n=32768;win(QueryFullProcessImageNameW(process.h,0,image,&n)!=0);require(_wcsicmp(image,(root+L"\\"+worker_leaf).c_str())==0);
  record(L"phase1_osb_system_03_identity.txt","actual-child-token-and-image-verified");checkpoint();
 });}
 bool resume_wait(){return run("resume_wait",[&]{
  checkpoint();DWORD resumed=ResumeThread(thread.h);win(resumed!=DWORD(-1));require(resumed==1);HANDLE waits[]{stop_event.h,process.h};DWORD r=WaitForMultipleObjects(2,waits,FALSE,10000);if(r==WAIT_FAILED)win(false);if(r==WAIT_TIMEOUT)throw DWORD(WAIT_TIMEOUT);if(r==WAIT_OBJECT_0)throw DWORD(ERROR_CANCELLED);require(r==WAIT_OBJECT_0+1);child_reaped=true;win(GetExitCodeProcess(process.h,&exit_code)!=0);
  auto final_identity=identity(child_token.h);observed_child=final_identity;
  // job_member is the exact suspended-child OS query. A terminated process need
  // not remain a running job member; worker independently checked it while live.
  FILETIME created{},ex{},k{},u{};win(GetProcessTimes(process.h,&created,&ex,&k,&u)!=0);
  require(child_proof(created.dwLowDateTime==creation.dwLowDateTime&&created.dwHighDateTime==creation.dwHighDateTime,admission_identity(final_identity.sid,sid,final_identity.session,final_identity.limited),job_member,exit_code));
  record(L"phase1_osb_system_04_exited.txt","fixed-worker-executed-own-identity-checks");
 });}
 bool cleanup(){
  // Only creator owns job. Closing it kills suspended/running child; never reopen a PID.
  bool ok=true;
  if(job){HANDLE owned_job=job.h;job.h=nullptr;if(!CloseHandle(owned_job)){if(!error)error=GetLastError();cleanup_uncertain=true;ok=false;}}
  if(process){DWORD w=WaitForSingleObject(process.h,10000);child_reaped=w==WAIT_OBJECT_0;cleanup_uncertain=cleanup_uncertain||!child_reaped;if(!child_reaped){if(!error)error=w==WAIT_TIMEOUT?WAIT_TIMEOUT:GetLastError();ok=false;}else if(!GetExitCodeProcess(process.h,&exit_code)){if(!error)error=GetLastError();ok=false;}}
  if(receipt_ready){try{record(L"phase1_osb_system_05_result.txt",error?"failed-at-"+stage:"admission-only-complete");}catch(DWORD e){if(!error)error=e;ok=false;}catch(...){if(!error)error=ERROR_UNHANDLED_EXCEPTION;ok=false;}}
  return ok;
 }
};
void WINAPI service_main(DWORD argc,LPWSTR* argv){
 if(argc!=1||!argv||_wcsicmp(argv[0],service_name.c_str())!=0)return;
 stop_event.reset(CreateEventW(nullptr,TRUE,FALSE,nullptr));if(!stop_event)return;
 status_handle=RegisterServiceCtrlHandlerExW(service_name.c_str(),control,nullptr);if(!status_handle)return;
 status(SERVICE_RUNNING);Adapter a;bool ok=admit(a);status(SERVICE_STOPPED,ok?NO_ERROR:(a.error?a.error:ERROR_GEN_FAILURE));
}
}
int wmain(int argc,wchar_t**){
 // No console fallback and no CLI parameters, SID or paths.
 if(argc!=1)return ERROR_INVALID_PARAMETER;
 SERVICE_TABLE_ENTRYW table[]={{const_cast<LPWSTR>(service_name.c_str()),service_main},{nullptr,nullptr}};
 if(!StartServiceCtrlDispatcherW(table)){return static_cast<int>(GetLastError());}
 return 0;
}
