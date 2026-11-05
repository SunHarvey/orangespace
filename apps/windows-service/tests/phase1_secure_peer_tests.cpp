// Same-token/session0 sentinel only. No elevation, accounts, Tasks, SCM or API.
// Own self-child is atomically admitted to an independently held fallback Job.
#include "phase1_secure_channel.hpp"
#include <iostream>
#include <vector>
using namespace phase1::secure;
class OwnedChild {
 Handle job_,process_,thread_;
public:
 OwnedChild(const std::wstring& pipe,const wchar_t* mode){
  job_=Handle(CreateJobObjectW(nullptr,nullptr));require(bool(job_),"fallback_job");
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_ACTIVE_PROCESS;limits.BasicLimitInformation.ActiveProcessLimit=1;
  require(SetInformationJobObject(job_.get(),JobObjectExtendedLimitInformation,&limits,sizeof(limits)),"fallback_job_limits");
  HANDLE parent_raw{};require(DuplicateHandle(GetCurrentProcess(),GetCurrentProcess(),GetCurrentProcess(),&parent_raw,PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,TRUE,0),"inherited_exact_parent");Handle parent(parent_raw);
  SIZE_T bytes{};InitializeProcThreadAttributeList(nullptr,2,0,&bytes);std::vector<BYTE> storage(bytes);auto list=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
  require(InitializeProcThreadAttributeList(list,2,0,&bytes),"attribute_list");struct Attributes{LPPROC_THREAD_ATTRIBUTE_LIST p;~Attributes(){DeleteProcThreadAttributeList(p);}} attributes{list};
  HANDLE jobs[]{job_.get()},inherited[]{parent.get()};
  require(UpdateProcThreadAttribute(list,0,PROC_THREAD_ATTRIBUTE_JOB_LIST,jobs,sizeof(jobs),nullptr,nullptr),"atomic_job_required");
  require(UpdateProcThreadAttribute(list,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,inherited,sizeof(inherited),nullptr,nullptr),"parent_only_allowlist");
  wchar_t exe[32768]{};auto n=GetModuleFileNameW(nullptr,exe,32768);require(n&&n<32768,"self_image");
  std::wstring command=L"\""+std::wstring(exe)+L"\" --child \""+pipe+L"\" "+std::to_wstring(reinterpret_cast<std::uintptr_t>(parent.get()))+L" "+mode;
  STARTUPINFOEXW si{};si.StartupInfo.cb=sizeof(si);si.lpAttributeList=list;PROCESS_INFORMATION pi{};
  require(CreateProcessW(exe,command.data(),nullptr,nullptr,TRUE,CREATE_SUSPENDED|CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT,nullptr,nullptr,&si.StartupInfo,&pi),"own_atomic_child");
  process_=Handle(pi.hProcess);thread_=Handle(pi.hThread);
  // No fallible construction work after owning process; test checks admission.
 }
 ~OwnedChild(){
  if(!process_)return;
  if(WaitForSingleObject(process_.get(),0)!=WAIT_OBJECT_0){
   TerminateJobObject(job_.get(),95);
   if(WaitForSingleObject(process_.get(),5000)!=WAIT_OBJECT_0){
    TerminateProcess(process_.get(),95);
    if(WaitForSingleObject(process_.get(),5000)!=WAIT_OBJECT_0)std::terminate();
   }
  }
  // Destruction/release only after exact held process signal was observed.
 }
 HANDLE process() const{return process_.get();}
 void resume(){BOOL admitted{};require(IsProcessInJob(process_.get(),job_.get(),&admitted)&&admitted,"already_admitted");require(ResumeThread(thread_.get())!=MAXDWORD,"resume_owned");}
 DWORD wait(){require(WaitForSingleObject(process_.get(),5000)==WAIT_OBJECT_0,"exact_child_exit");DWORD code{};require(GetExitCodeProcess(process_.get(),&code),"child_exit_code");return code;}
};
static int child(int argc,wchar_t** argv){
 if(argc!=5)return 80;
 try{
  wchar_t* end{};auto number=std::wcstoull(argv[3],&end,10);require(end&&!*end&&number,"parent_handle_argument");Handle parent(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(number)));
  auto expected=HeldPeer::capture(parent.get());
  require(expected.identity()==HeldPeer::capture(GetCurrentProcess()).identity(),"same_token_sentinel_only");
  const bool wrong_server=std::wstring_view(argv[4])==L"wrong-server";
  auto channel=SecureChannel::client(open_client(argv[2]),wrong_server?HeldPeer::capture(GetCurrentProcess()):std::move(expected),Deadline(2000));
  if(wrong_server)return 81;
  SecretBuffer marker;marker.assign("NONSECRET_EXACT_CHILD");channel.send(marker,Deadline(2000));
  require(channel.receive(Deadline(2000)).view()==marker.view(),"child_reply");return 0;
 }catch(const Failure& f){return std::string_view(f.stage)=="exact_live_process"?84:82;}catch(...){return 83;}
}
static void run(const wchar_t* mode,unsigned serial){
 auto self=HeldPeer::capture(GetCurrentProcess());
 auto name=L"\\\\.\\pipe\\OrangeSpace-secure-peer-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(serial);
 auto pipe=create_server(name,self.identity().sid);OwnedChild owned(name,mode);
 auto expected=HeldPeer::capture(owned.process()); // BEFORE child executes any code.
 require(expected.identity()==self.identity(),"test_same_sid_session_luid_role");
 owned.resume();connect(pipe.get(),Deadline(2000));
 bool rejected=false;const char* stage="none";DWORD error{};
 try{
  auto channel=SecureChannel::server(std::move(pipe),std::wstring_view(mode)==L"wrong-client"?HeldPeer::capture(GetCurrentProcess()):std::move(expected),Deadline(2000));
  auto marker=channel.receive(Deadline(2000));require(marker.view()=="NONSECRET_EXACT_CHILD","parent_marker");channel.send(marker,Deadline(2000));
 }catch(const Failure& f){rejected=true;stage=f.stage;error=f.code;}
 auto exit=owned.wait();
 if(std::wstring_view(mode)==L"good")require(!rejected&&exit==0,"good_exact_process_duplex");
 else if(std::wstring_view(mode)==L"wrong-client")require(rejected&&std::string_view(stage)=="exact_live_process"&&exit==82,"typed_wrong_client_pid_rejection");
 else require(rejected&&error==ERROR_BROKEN_PIPE&&exit==84,"typed_wrong_server_pid_rejection");
}
int wmain(int argc,wchar_t** argv){
 if(argc>1&&std::wstring_view(argv[1])==L"--child")return child(argc,argv);
 try{
  require(argc==1,"no_external_modes");
  run(L"good",1);run(L"wrong-client",2);run(L"wrong-server",3);
  std::cout<<"{\"kind\":\"isolated_exact_peer\",\"ok\":true,\"owned_children_signaled\":3,\"same_sid_logon_wrong_pid_denied\":true,\"reciprocal_wrong_pid_denied\":true,\"session0_to_session2\":false,\"protected_role_provenance\":false}\n";return 0;
 }catch(const Failure& f){std::cout<<"{\"ok\":false,\"stage\":\""<<f.stage<<"\",\"code\":"<<f.code<<"}\n";return 1;}
 catch(...){std::cout<<"{\"ok\":false,\"unexpected\":true}\n";return 2;}
}
