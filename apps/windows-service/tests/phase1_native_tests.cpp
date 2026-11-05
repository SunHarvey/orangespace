#include "phase1_native.hpp"
#include <iostream>
using namespace phase1;
int wmain(int argc,wchar_t**) {
 if(argc==2){Sleep(30000);return 99;}
 try {
  for(bool assign:{false,true}){
   wchar_t exe[32768];need(GetModuleFileNameW(nullptr,exe,32768)>0,"self_exe");
   std::wstring cmd=L"\""+std::wstring(exe)+L"\" --owned-wait";STARTUPINFOW si{};si.cb=sizeof(si);PROCESS_INFORMATION pi{};
   need(CreateProcessW(exe,cmd.data(),nullptr,nullptr,FALSE,CREATE_SUSPENDED|CREATE_NO_WINDOW,nullptr,nullptr,&si,&pi),"owned_test_process");
   Handle p(pi.hProcess),t(pi.hThread),job(CreateJobObjectW(nullptr,nullptr));
   bool assigned=!assign||AssignProcessToJobObject(job.h,p.h);
   bool cleaned=assigned&&terminate_owned(job.h,p.h,1000);
   bool signaled=WaitForSingleObject(p.h,0)==WAIT_OBJECT_0;
   // Even RED must leave no suspended process behind.
   if(!signaled){TerminateProcess(p.h,98);WaitForSingleObject(p.h,5000);}
   need(cleaned&&signaled,"owned_process_cleanup_assigned_and_unassigned");
  }

  SetLastError(ERROR_SUCCESS);bool caught=false;
  try { need(false,"predicate"); } catch(Failure f) {caught=f.code!=0;} need(caught,"zero_error_rejected");
  Handle read,write; SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,FALSE};
  need(CreatePipe(&read.h,&write.h,&sa,4096),"pipe");
  send_frame(write.h,"{\"schema\":1}");need(read_frame(read.h,1000)=="{\"schema\":1}","frame_roundtrip");
  const auto started=GetTickCount64();caught=false;
  try {(void)read_frame(read.h,60);}catch(Failure f){caught=f.code==WAIT_TIMEOUT;}
  need(caught&&GetTickCount64()-started<2000,"bounded_timeout");
  write.reset();caught=false;try{(void)read_frame(read.h,1000);}catch(Failure){caught=true;}need(caught,"closed_pipe_rejected");
  std::cout<<"{\"schema\":1,\"kind\":\"selftest\",\"ok\":true,\"zero_last_error\":true,\"framing\":true,\"timeout\":true,\"closed_pipe\":true,\"owned_process_cleanup\":true}\n";return 0;
 }catch(Failure f){std::cout<<"{\"schema\":1,\"kind\":\"selftest\",\"ok\":false,\"error\":"<<f.code<<"}\n";return 1;}
}
