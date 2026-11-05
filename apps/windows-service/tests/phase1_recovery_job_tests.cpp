// Isolated native primitive TEST: no tokens, SCM, API, profiles or credentials.
// Cross-compilation is NOT a native pass. Parent must review before running.
#include "phase1_native.hpp"
#include <iostream>
using namespace phase1;
int wmain(int argc,wchar_t** argv){
 if(argc==2 && std::wstring_view(argv[1])==L"--atomic-owned-child"){Sleep(INFINITE);return 99;}
 Handle process,thread,job;
 try{
  need(argc==1,"arguments");
  job.reset(CreateJobObjectW(nullptr,nullptr));need(job.h,"job_create");
  DWORD flags=0;need(GetHandleInformation(job.h,&flags)&&!(flags&HANDLE_FLAG_INHERIT),"job_not_inherited");
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  need(SetInformationJobObject(job.h,JobObjectExtendedLimitInformation,&limits,sizeof(limits)),"job_kill_on_close_no_breakaway");
  SIZE_T size=0;InitializeProcThreadAttributeList(nullptr,1,0,&size);
  std::vector<BYTE> storage(size);auto* list=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
  need(InitializeProcThreadAttributeList(list,1,0,&size),"attributes_init");
  struct Attributes{LPPROC_THREAD_ATTRIBUTE_LIST list;~Attributes(){DeleteProcThreadAttributeList(list);}} attributes{list};
  HANDLE jobs[]={job.h};
  need(UpdateProcThreadAttribute(list,0,PROC_THREAD_ATTRIBUTE_JOB_LIST,jobs,sizeof(jobs),nullptr,nullptr),"job_list_required_no_fallback");
  wchar_t exe[32768];need(GetModuleFileNameW(nullptr,exe,32768)>0,"module_path");
  std::wstring command=L"\""+std::wstring(exe)+L"\" --atomic-owned-child";
  STARTUPINFOEXW si{};si.StartupInfo.cb=sizeof(si);si.lpAttributeList=list;
  PROCESS_INFORMATION pi{};
  need(CreateProcessW(exe,command.data(),nullptr,nullptr,FALSE,CREATE_SUSPENDED|CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT,nullptr,nullptr,&si.StartupInfo,&pi),"create_atomic_suspended_child");
  process.reset(pi.hProcess);thread.reset(pi.hThread);
  BOOL admitted=FALSE;need(IsProcessInJob(process.h,job.h,&admitted)&&admitted,"atomic_child_already_admitted");
  need(WaitForSingleObject(process.h,0)==WAIT_TIMEOUT,"child_object_alive");
  // Never resume: kill-on-close must cover even a suspended child.
  job.reset();need(WaitForSingleObject(process.h,5000)==WAIT_OBJECT_0,"job_close_reaps_suspended_child");
  std::cout<<"{\"schema\":1,\"kind\":\"isolated_atomic_job_primitive\",\"ok\":true,\"suspended_admission\":true,\"job_close_exit_observed\":true,\"linked_token_createprocessasuser\":false,\"controller_hardloss\":false,\"scm_recovery\":false,\"full_acceptance\":false}\n";
  return 0;
 }catch(Failure f){
  const bool cleanup=terminate_owned(job.h,process.h,5000);
  std::cout<<"{\"schema\":1,\"kind\":\"isolated_atomic_job_primitive\",\"ok\":false,\"error\":"<<f.code<<",\"owned_child_cleanup\":"<<(cleanup?"true":"false")<<",\"full_acceptance\":false}\n";
  return 1;
 }catch(...){
  const bool cleanup=terminate_owned(job.h,process.h,5000);
  std::cout<<"{\"schema\":1,\"kind\":\"isolated_atomic_job_primitive\",\"ok\":false,\"allocation_or_local_error\":true,\"owned_child_cleanup\":"<<(cleanup?"true":"false")<<",\"full_acceptance\":false}\n";
  return 2;
 }
}
