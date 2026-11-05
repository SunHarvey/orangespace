// Non-destructive native acceptance tests; no accounts, services or network.
#include "phase1_os_b_win.hpp"
#include "phase1_os_b_integration.hpp"
#include "phase1_os_b_capture.hpp"
int wmain(int argc,wchar_t** argv){try{
 using namespace phase1_os_b;
 Handle r,w;
 auto name=L"\\\\.\\pipe\\OrangeSpace.Phase1.OSB.Unit."+wide(random_hex(16));
 auto sid=current_identity().sid;auto sd=descriptor(L"O:"+sid+L"D:P(A;;0x12019b;;;SY)(A;;0x12019b;;;"+sid+L")");SECURITY_ATTRIBUTES sa{sizeof(sa),sd.get(),FALSE};
 const bool stalled=argc==2&&std::wstring_view(argv[1])==L"--stalled-write";
 r.reset(CreateNamedPipeW(name.c_str(),PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED|FILE_FLAG_FIRST_PIPE_INSTANCE,PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_REJECT_REMOTE_CLIENTS,1,stalled?64:131072,stalled?64:131072,0,&sa));need(r.h!=INVALID_HANDLE_VALUE,"unit_server");
 Handle forbidden(CreateFileW(name.c_str(),FILE_CREATE_PIPE_INSTANCE,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,nullptr));auto denied=GetLastError();need(forbidden.h==INVALID_HANDLE_VALUE&&denied==ERROR_ACCESS_DENIED,"unit_no_instance_right");
 w.reset(CreateFileW(name.c_str(),0x12019b,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,nullptr));need(w.h!=INVALID_HANDLE_VALUE,"unit_client");
 if(argc==2){
  const std::wstring_view mode(argv[1]);
  if(mode==L"--pending-budget"){
   IoLease held(r.h,4);bool denied_budget=false;try{send_private(w.h,"x",25);}catch(Failure f){denied_budget=f.code==ERROR_BUSY;}
   need(denied_budget,"unit_budget_before_issue");return 0;
  }
  need(mode==L"--partial-header"||mode==L"--partial-body"||stalled,"unit_known_mode");
  if(!stalled){std::string partial;if(mode==L"--partial-header")partial.assign(2,'\0');else{put32(partial,10);partial+="abc";}
   transfer_until(w.h,partial.data(),DWORD(partial.size()),true,GetTickCount64()+1000);
  }
  const auto start=GetTickCount64();bool timed_out=false;
  try{if(stalled)send_private(w.h,std::string(max_frame,'s'),25);else(void)read_private(r.h,25);}catch(Failure f){timed_out=f.code==WAIT_TIMEOUT;}
  need(timed_out&&GetTickCount64()-start<2000,"unit_absolute_partial_or_stalled_timeout");
  // Any framing failure closes the endpoint; never reuse a partial frame.
  w.reset();r.reset();need(private_io_budget.reap_retained(),"unit_completion_after_close");return 0;
 }
 std::string text="OSB1-unit";send_private(w.h,text,1000);
 need(read_private(r.h,1000)==text,"unit_private_roundtrip");
 bool timeout=false;try{(void)read_private(r.h,25);}catch(Failure f){timeout=f.code==WAIT_TIMEOUT;}need(timeout,"unit_timeout_cancel_drain");
 send_private(w.h,text,1000);need(read_private(r.h,1000)==text,"unit_reuse_after_cancel");
 w.reset();bool closed=false;try{(void)read_private(r.h,1000);}catch(Failure f){closed=f.code==ERROR_BROKEN_PIPE||f.code==ERROR_PIPE_NOT_CONNECTED;}need(closed,"unit_closed_pipe");
 struct Probe {Handle job,process,thread;~Probe(){job.reset();if(process.h)WaitForSingleObject(process.h,10000);}} probe;
 probe.job.reset(CreateJobObjectW(nullptr,nullptr));need(probe.job.h!=nullptr,"unit_job");JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_ACTIVE_PROCESS;limits.BasicLimitInformation.ActiveProcessLimit=1;
 need(SetInformationJobObject(probe.job.h,JobObjectExtendedLimitInformation,&limits,sizeof(limits)),"unit_job_limits");JobAdmission attributes(probe.job.h);
 STARTUPINFOEXW startup{};startup.StartupInfo.cb=sizeof(startup);startup.lpAttributeList=attributes.list;
 wchar_t executable[32768];auto count=GetModuleFileNameW(nullptr,executable,32768);need(count>0&&count<32768,"unit_executable");std::wstring command=L"\""+std::wstring(executable)+L"\" --never-resume";PROCESS_INFORMATION child{};
 need(CreateProcessW(executable,command.data(),nullptr,nullptr,FALSE,CREATE_SUSPENDED|EXTENDED_STARTUPINFO_PRESENT|CREATE_NO_WINDOW,nullptr,nullptr,&startup.StartupInfo,&child),"unit_atomic_create_same_user");probe.process.reset(child.hProcess);probe.thread.reset(child.hThread);
 BOOL member=FALSE;need(IsProcessInJob(probe.process.h,probe.job.h,&member)&&member,"unit_atomic_membership");probe.job.reset();need(WaitForSingleObject(probe.process.h,10000)==WAIT_OBJECT_0,"unit_job_close_reaps_suspended_child");
 auto* volatile actual_capture=&capture_input;need(actual_capture!=nullptr,"unit_real_capture_linkage");
 ControllerRun opted_out;need(!opted_out.execute(L"",{},nullptr,false,{},{}),"unit_optin_guard");need(!opted_out.receipt().account_created,"unit_no_account_without_approval");
 auto id=current_identity();need(!id.sid.empty()&&id.luid!=0,"unit_identity");
 return 0;
}catch(...){return 1;}}
