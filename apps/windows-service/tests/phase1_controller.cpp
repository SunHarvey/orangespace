// Opt-in acceptance controller. Only exact fixed fixture service/binaries.
#include "phase1_native.hpp"
#include "phase1_contract.hpp"
#include <sddl.h>
#include <userenv.h>
#include <tlhelp32.h>
#include <memory>
using namespace phase1;
namespace nd=orangespace::node_session::detail;
namespace {
constexpr auto service_name=L"OrangeSpaceFoundation";
struct ScHandle {SC_HANDLE h=nullptr;~ScHandle(){if(h)CloseServiceHandle(h);}};
std::wstring image(HANDLE p){std::vector<wchar_t>b(32768);DWORD n=DWORD(b.size());need(QueryFullProcessImageNameW(p,0,b.data(),&n),"process_image");return {b.data(),n};}
ULONGLONG created(HANDLE p){FILETIME c,e,k,u;need(GetProcessTimes(p,&c,&e,&k,&u),"process_creation_time");return (ULONGLONG(c.dwHighDateTime)<<32)|c.dwLowDateTime;}
std::wstring sid(HANDLE token){DWORD n=0;GetTokenInformation(token,TokenUser,nullptr,0,&n);std::vector<BYTE>b(n);need(GetTokenInformation(token,TokenUser,b.data(),n,&n),"token_sid");LPWSTR p=nullptr;need(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(b.data())->User.Sid,&p),"sid_text");std::wstring s=p;LocalFree(p);return s;}
DWORD session(HANDLE token){DWORD n=0,id=0;need(GetTokenInformation(token,TokenSessionId,&id,sizeof(id),&n),"token_session");return id;}
void validate_root(const std::wstring& root){
 const std::wstring prefix=L"C:\\Program Files\\OrangeSpace-phase1-";
 need(root.starts_with(prefix)&&root.size()==prefix.size()+32,"fixture_root");
 for(auto c:root.substr(prefix.size()))need((c>=L'0'&&c<=L'9')||(c>=L'a'&&c<=L'f'),"fixture_root_nonce");
 wchar_t own[32768];need(GetModuleFileNameW(nullptr,own,32768)>0,"controller_module");need(root+L"\\phase1_controller.exe"==own,"exact_controller_path");
 // The production loader validates protected file and complete ancestor ACLs.
 (void)orangespace::node_session::TrustedCatalog::load(root+L"\\nodes.json");
}
class OwnedService {
 ScHandle manager_,service_;std::wstring exe_;bool removed_=false;
 SERVICE_STATUS_PROCESS status(){SERVICE_STATUS_PROCESS s{};DWORD n=0;need(QueryServiceStatusEx(service_.h,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE*>(&s),sizeof(s),&n),"service_status");return s;}
 void config(){DWORD n=0;QueryServiceConfigW(service_.h,nullptr,0,&n);std::vector<BYTE>b(n);need(n>0&&QueryServiceConfigW(service_.h,reinterpret_cast<QUERY_SERVICE_CONFIGW*>(b.data()),n,&n),"service_config");auto*q=reinterpret_cast<QUERY_SERVICE_CONFIGW*>(b.data());need(q->dwServiceType==SERVICE_WIN32_OWN_PROCESS&&q->dwStartType==SERVICE_DEMAND_START&&std::wstring(q->lpServiceStartName)==L"LocalSystem"&&std::wstring(q->lpBinaryPathName)==L"\""+exe_+L"\"","exact_service_config");}
 void wait(DWORD wanted,DWORD timeout){const auto end=GetTickCount64()+timeout;while(status().dwCurrentState!=wanted){if(GetTickCount64()>=end)throw Failure{"service_timeout",WAIT_TIMEOUT};Sleep(100);}}
 public:
 explicit OwnedService(const std::wstring& root):exe_(root+L"\\OrangeSpaceFoundation.exe"){
  manager_.h=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT|SC_MANAGER_CREATE_SERVICE);need(manager_.h,"scm_open");
  SC_HANDLE old=OpenServiceW(manager_.h,service_name,SERVICE_QUERY_CONFIG);if(old){CloseServiceHandle(old);throw Failure{"existing_service_never_overwrite",ERROR_ALREADY_EXISTS};}need(GetLastError()==ERROR_SERVICE_DOES_NOT_EXIST,"service_absence");
  std::wstring cmd=L"\""+exe_+L"\"";
  service_.h=CreateServiceW(manager_.h,service_name,service_name,SERVICE_QUERY_STATUS|SERVICE_QUERY_CONFIG|SERVICE_START|SERVICE_STOP|DELETE,SERVICE_WIN32_OWN_PROCESS,SERVICE_DEMAND_START,SERVICE_ERROR_NORMAL,cmd.c_str(),nullptr,nullptr,nullptr,L"LocalSystem",nullptr);
  need(service_.h,"service_create");
 }
 void start(){config();need(StartServiceW(service_.h,0,nullptr),"service_start");wait(SERVICE_RUNNING,20000);Sleep(1000);}
 Handle process(){config();const auto s=status();need(s.dwCurrentState==SERVICE_RUNNING&&s.dwProcessId!=0,"service_running");Handle p(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE|PROCESS_TERMINATE,FALSE,s.dwProcessId));need(p.h,"service_process");need(image(p.h)==exe_&&WaitForSingleObject(p.h,0)==WAIT_TIMEOUT,"service_process_identity");need(status().dwProcessId==s.dwProcessId,"service_pid_readback");return p;}
 std::vector<Handle> helpers(const std::wstring& root,HANDLE service){
  const auto pid=GetProcessId(service);const auto start=created(service);std::vector<Handle> result;
  Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0));need(snapshot.h!=INVALID_HANDLE_VALUE,"process_snapshot");
  PROCESSENTRY32W e{};e.dwSize=sizeof(e);need(Process32FirstW(snapshot.h,&e),"process_first");
  do{if(e.th32ParentProcessID!=pid||std::wstring(e.szExeFile)!=L"sing-box.exe")continue;
   Handle h(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE|PROCESS_TERMINATE,FALSE,e.th32ProcessID));need(h.h,"helper_process");
   need(image(h.h)==root+L"\\sing-box.exe"&&created(h.h)>=start&&WaitForSingleObject(h.h,0)==WAIT_TIMEOUT,"owned_helper_identity");result.push_back(std::move(h));
  }while(Process32NextW(snapshot.h,&e));
  need(WaitForSingleObject(service,0)==WAIT_TIMEOUT,"service_lifetime_held");return result;
 }
 void kill_helper(const std::wstring& root){auto p=process();auto children=helpers(root,p.h);need(children.size()==2,"two_owned_helpers_before_fault");need(TerminateProcess(children.front().h,91),"terminate_owned_helper");need(WaitForSingleObject(children.front().h,10000)==WAIT_OBJECT_0,"helper_exit_observed");}
 void crash_restart(const std::wstring& root){auto p=process();auto children=helpers(root,p.h);need(children.size()==2,"two_helpers_before_service_crash");
  // Aggregate sharing-denial probe only; does not attribute a handle to the
  // service (a helper, controller, antivirus or another reader may hold it).
  Handle probe(CreateFileW((root+L"\\sing-box.exe").c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,0,nullptr));DWORD lock_error=GetLastError();need(probe.h==INVALID_HANDLE_VALUE&&lock_error==ERROR_SHARING_VIOLATION,"aggregate_helper_file_sharing_denial");
  need(TerminateProcess(p.h,92),"terminate_owned_service");need(WaitForSingleObject(p.h,10000)==WAIT_OBJECT_0,"service_exit_observed");
  for(auto& h:children)need(WaitForSingleObject(h.h,10000)==WAIT_OBJECT_0,"held_helper_exit_after_service_crash");
  wait(SERVICE_STOPPED,10000);
  probe.reset(CreateFileW((root+L"\\sing-box.exe").c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,0,nullptr));need(probe.h!=INVALID_HANDLE_VALUE,"aggregate_helper_file_write_open_after_exit");probe.reset();start();
 }
 bool cleanup()noexcept{
  if(removed_)return true;
  try{config();auto s=status();Handle p;if(s.dwCurrentState!=SERVICE_STOPPED){p=process();SERVICE_STATUS stopped{};if(!ControlService(service_.h,SERVICE_CONTROL_STOP,&stopped)&&GetLastError()!=ERROR_SERVICE_NOT_ACTIVE)need(false,"service_stop");
    try{wait(SERVICE_STOPPED,25000);}catch(...){need(TerminateProcess(p.h,93),"cleanup_owned_service_terminate");need(WaitForSingleObject(p.h,10000)==WAIT_OBJECT_0,"cleanup_service_exit");wait(SERVICE_STOPPED,10000);}}
   need(DeleteService(service_.h),"delete_owned_service");CloseServiceHandle(service_.h);service_.h=nullptr;
   for(unsigned i=0;i<100;++i){SC_HANDLE old=OpenServiceW(manager_.h,service_name,SERVICE_QUERY_STATUS);if(!old&&GetLastError()==ERROR_SERVICE_DOES_NOT_EXIST){removed_=true;return true;}if(old)CloseServiceHandle(old);Sleep(50);}return false;
  }catch(...){return false;}
 }
 ~OwnedService(){cleanup();}
};
struct Child {
 Handle process,thread,input,output,job;bool exited=false;
 ~Child(){if(process.h&&!exited)terminate_owned(job.h,process.h,10000);}
 void launch(const std::wstring& root,bool selftest,HANDLE linked){
  SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};Handle child_in,child_out;
  need(CreatePipe(&child_in.h,&input.h,&sa,65536),"stdin_pipe");need(CreatePipe(&output.h,&child_out.h,&sa,65536),"stdout_pipe");
  need(SetHandleInformation(input.h,HANDLE_FLAG_INHERIT,0)&&SetHandleInformation(output.h,HANDLE_FLAG_INHERIT,0),"parent_handles_not_inherited");
  job.reset(CreateJobObjectW(nullptr,nullptr));need(job.h,"child_job");JOBOBJECT_EXTENDED_LIMIT_INFORMATION j{};j.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;need(SetInformationJobObject(job.h,JobObjectExtendedLimitInformation,&j,sizeof(j)),"child_kill_on_close");
  SIZE_T bytes=0;InitializeProcThreadAttributeList(nullptr,2,0,&bytes);std::vector<BYTE> attributes(bytes);auto*list=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());need(InitializeProcThreadAttributeList(list,2,0,&bytes),"attribute_list");
  struct Attr{LPPROC_THREAD_ATTRIBUTE_LIST p;~Attr(){DeleteProcThreadAttributeList(p);}}attr{list};HANDLE handles[]={child_in.h,child_out.h};
  need(UpdateProcThreadAttribute(list,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,handles,sizeof(handles),nullptr,nullptr),"explicit_inherit_list");
  // Admission is part of CreateProcess, never a post-creation assignment.
  // Unsupported JOB_LIST or incompatible nested Jobs fail before credentials.
  HANDLE jobs[]={job.h};
  need(UpdateProcThreadAttribute(list,0,PROC_THREAD_ATTRIBUTE_JOB_LIST,jobs,sizeof(jobs),nullptr,nullptr),"atomic_job_list");
  STARTUPINFOEXW si{};si.StartupInfo.cb=sizeof(si);si.StartupInfo.dwFlags=STARTF_USESTDHANDLES;si.StartupInfo.hStdInput=child_in.h;si.StartupInfo.hStdOutput=child_out.h;si.StartupInfo.hStdError=child_out.h;si.lpAttributeList=list;
  const auto exe=root+L"\\phase1_client.exe";std::wstring cmd=L"\""+exe+L"\" \""+(selftest?L"--selftest":root+L"\\nodes.json")+L"\" 2";LPVOID env=nullptr;need(CreateEnvironmentBlock(&env,linked,FALSE),"linked_environment");
  PROCESS_INFORMATION pi{};BOOL ok=CreateProcessAsUserW(linked,exe.c_str(),cmd.data(),nullptr,nullptr,TRUE,CREATE_SUSPENDED|CREATE_NO_WINDOW|CREATE_UNICODE_ENVIRONMENT|EXTENDED_STARTUPINFO_PRESENT,env,root.c_str(),&si.StartupInfo,&pi);DWORD error=GetLastError();DestroyEnvironmentBlock(env);SetLastError(error);need(ok,"create_limited_client");
  process.reset(pi.hProcess);thread.reset(pi.hThread);BOOL admitted=FALSE;need(IsProcessInJob(process.h,job.h,&admitted)&&admitted,"client_atomic_job_admitted");need(image(process.h)==exe,"client_process_image");
  Handle actual;need(OpenProcessToken(process.h,TOKEN_QUERY,&actual.h),"actual_child_token");need(sid(actual.h)==sid(linked)&&session(actual.h)==2,"actual_child_identity");
  TOKEN_ELEVATION elevation{};DWORD n=0;need(GetTokenInformation(actual.h,TokenElevation,&elevation,sizeof(elevation),&n)&&!elevation.TokenIsElevated,"actual_child_limited");
  need(ResumeThread(thread.h)!=DWORD(-1),"resume_limited_client");
 }
 DWORD finish(){need(WaitForSingleObject(process.h,10000)==WAIT_OBJECT_0,"client_exit_timeout");exited=true;DWORD code=0;need(GetExitCodeProcess(process.h,&code),"native_client_exit_code");return code;}
};
Handle bootstrap_pipe(const std::wstring& name,HANDLE token){
 need(name.starts_with(L"OrangeSpace-phase1-")&&name.size()==51,"private_pipe_name");for(auto c:name.substr(19))need((c>=L'0'&&c<=L'9')||(c>=L'a'&&c<=L'f'),"private_pipe_nonce");
 const auto dacl=L"D:P(A;;GA;;;SY)(A;;GA;;;"+sid(token)+L")";PSECURITY_DESCRIPTOR sd=nullptr;
 need(ConvertStringSecurityDescriptorToSecurityDescriptorW(dacl.c_str(),SDDL_REVISION_1,&sd,nullptr),"private_pipe_sd");SECURITY_ATTRIBUTES sa{sizeof(sa),sd,FALSE};
 Handle p(CreateNamedPipeW((L"\\\\.\\pipe\\"+name).c_str(),PIPE_ACCESS_DUPLEX|FILE_FLAG_FIRST_PIPE_INSTANCE,PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_NOWAIT|PIPE_REJECT_REMOTE_CLIENTS,1,65536,65536,0,&sa));DWORD error=GetLastError();LocalFree(sd);SetLastError(error);need(p.h!=INVALID_HANDLE_VALUE,"private_pipe_create");
 const auto end=GetTickCount64()+20000;while(!ConnectNamedPipe(p.h,nullptr)){const auto e=GetLastError();if(e==ERROR_PIPE_CONNECTED)break;need(e==ERROR_PIPE_LISTENING||e==ERROR_NO_DATA,"private_pipe_connect");if(GetTickCount64()>=end)throw Failure{"bootstrap_connect_timeout",WAIT_TIMEOUT};Sleep(25);}
 ULONG pid=0;need(GetNamedPipeClientProcessId(p.h,&pid),"bootstrap_peer_pid");Handle peer(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid));need(peer.h,"bootstrap_peer_process");Handle peer_token;need(OpenProcessToken(peer.h,TOKEN_QUERY,&peer_token.h),"bootstrap_peer_token");need(sid(peer_token.h)==sid(token),"bootstrap_same_os_sid");
 DWORD mode=PIPE_READMODE_BYTE|PIPE_WAIT;need(SetNamedPipeHandleState(p.h,&mode,nullptr,nullptr),"private_pipe_wait_mode");return p;
}
}
int wmain(int argc,wchar_t**argv){
 return ERROR_ACCESS_DISABLED_BY_POLICY; // phase1 fixture quarantine; no override
 Handle external;bool success=false,service_removed=true;DWORD error=0,native_code=DWORD(-1);const char*stage="arguments";
 std::unique_ptr<OwnedService> service;
 try{need(argc==4,"arguments");const std::wstring root=argv[1],mode=argv[3];need(mode==L"--selftest"||mode==L"--accept","explicit_mode");const bool selftest=mode==L"--selftest";
  validate_root(root);Handle token;need(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_DUPLICATE,&token.h),"controller_token");need(session(token.h)==2,"controller_existing_session_2");
  TOKEN_ELEVATION_TYPE type{};DWORD n=0;need(GetTokenInformation(token.h,TokenElevationType,&type,sizeof(type),&n)&&type==TokenElevationTypeFull,"highest_split_token_controller");
  TOKEN_LINKED_TOKEN linked{};need(GetTokenInformation(token.h,TokenLinkedToken,&linked,sizeof(linked),&n),"linked_limited_token");Handle limited(linked.LinkedToken);need(sid(limited.h)==sid(token.h)&&session(limited.h)==2,"linked_token_identity");
  external=bootstrap_pipe(argv[2],token.h);stage="bootstrap";auto raw=read_frame(external.h,15000);struct Wipe{std::string&s;~Wipe(){nd::wipe(s.data(),s.size());}}wipe{raw};(void)parse_bootstrap(raw);
  if(!selftest){stage="service_create";service=std::make_unique<OwnedService>(root);service_removed=false;service->start();}
  stage="limited_launch";Child child;child.launch(root,selftest,limited.h);send_frame(child.input.h,raw);nd::wipe(raw.data(),raw.size());raw.clear();
  bool result=false;unsigned controls=0;const auto deadline=GetTickCount64()+480000;
  while(!result){need(GetTickCount64()<deadline,"fixture_deadline");auto message=read_frame(child.output.h,270000);nd::JsonGuard doc(message);const auto&v=doc.value;need(nd::integer(nd::field(v,"schema"))==1,"event_schema");const auto kind=nd::text(nd::field(v,"kind"));
   if(kind=="control"){
    nd::object(v,3);need(!selftest&&service!=nullptr,"no_selftest_scm");const auto action=nd::text(nd::field(v,"action"));
    if(controls==0&&action=="kill_one_owned_helper")service->kill_helper(root);
    else if(controls==1&&action=="crash_restart_owned_service")service->crash_restart(root);
    else throw Failure{"control_order",ERROR_INVALID_DATA};
    ++controls;send_frame(child.input.h,"{\"schema\":1,\"kind\":\"ack\",\"ok\":true}");
    send_frame(external.h,std::string("{\"schema\":1,\"kind\":\"controller_fault\",\"action\":\"")+action+"\",\"ok\":true}");
   }else{
    need(kind=="pass"||kind=="wait"||kind=="client_result"||kind=="bootstrap_result","known_event_kind");send_frame(external.h,message);
    if(kind=="client_result"||kind=="bootstrap_result"){result=true;success=nd::field(v,"ok").is_true()&&(selftest?kind=="bootstrap_result":kind=="client_result"&&controls==2);}
   }
  }
  native_code=child.finish();need(native_code==0&&success,"client_acceptance");stage="complete";
 }catch(Failure f){stage=f.stage;error=f.code;}catch(...){error=ERROR_INVALID_DATA;}
 if(service)service_removed=service->cleanup();
 success=success&&error==0&&service_removed;
 const auto output=std::string("{\"schema\":1,\"kind\":\"controller_result\",\"ok\":")+(success?"true":"false")+",\"stage\":\""+stage+"\",\"error\":"+std::to_string(error)+",\"native_client_exit\":"+std::to_string(native_code)+",\"owned_service_removed\":"+(service_removed?"true":"false")+",\"full_acceptance\":false,\"os_b_covered\":false}";
 if(external.h)try{send_frame(external.h,output);}catch(...){return 3;}
 return success?0:1;
}
