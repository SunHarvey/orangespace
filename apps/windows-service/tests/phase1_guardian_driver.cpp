#include "phase1_guardian_win.hpp"
#include <cwchar>
using namespace phase1_guardian;
using namespace phase1_guardian::win;
namespace {
HANDLE inherited(const wchar_t*s){need(s&&*s);wchar_t*end=nullptr;auto value=wcstoull(s,&end,10);need(end&&!*end&&value&&std::to_wstring(value)==s);return(HANDLE)(UINT_PTR)value;}
int run(const std::wstring&nonce,HANDLE controller_raw,HANDLE input_raw){
 BOOL in_job=TRUE;need(IsProcessInJob(GetCurrentProcess(),nullptr,&in_job)&&!in_job);
 Handle token;need(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,token.put()));TOKEN_ELEVATION elevation{};DWORD n=0;need(GetTokenInformation(token.get(),TokenElevation,&elevation,sizeof(elevation),&n)&&elevation.TokenIsElevated);
 Handle controller(controller_raw),input(input_raw);need(controller.get()!=input.get());
 need(SetHandleInformation(controller.get(),HANDLE_FLAG_INHERIT,0)&&SetHandleInformation(input.get(),HANDLE_FLAG_INHERIT,0));
 Scope scope(nonce);need(equal_path(module_path(),scope.guardian_exe)&&scope.approval.expected_helpers==0);
 need(scope.approval.controller.pid!=GetCurrentProcessId()&&same(scope.approval.controller,describe(controller.get())));
 need(WaitForSingleObject(controller.get(),0)==WAIT_TIMEOUT&&GetFileType(input.get())==FILE_TYPE_PIPE);
 DWORD flags=0;need(GetNamedPipeInfo(input.get(),&flags,nullptr,nullptr,nullptr)&&!(flags&PIPE_TYPE_MESSAGE));
 // No stdout/pipe writes on the guardian critical path. Reports use only the guarded journal.
 Journal journal(scope);WinAdapter adapter(scope,journal,controller.get());bool failed=false;unsigned reason=0,acquisition_polls=0;State previous=State::unknown;
 ULONGLONG deadline=GetTickCount64()+scope.approval.lease_ms;
 try{
  need(adapter.provision());
  while(true){
   DWORD controller_wait=WaitForSingleObject(controller.get(),0);
   if(controller_wait==WAIT_OBJECT_0){reason=1;break;}
   if(controller_wait!=WAIT_TIMEOUT){reason=10;failed=true;break;}
   if(GetTickCount64()>=deadline){reason=2;break;}
   auto status=adapter.query();if(status.state==State::unknown){reason=3;failed=true;break;}
   if(status.state!=previous){need(journal.append(service_status,adapter.generation(),{},0,(unsigned)status.state));previous=status.state;}
   if(adapter.start_attempted()&&!adapter.has_root()&&!adapter.capture(status.pid)){
    if(acquisition_polls++==0)need(adapter.record(Code::capture_failed));
    if(acquisition_polls>=40){reason=11;failed=true;break;}
   }
   // An unexpected actual root exit also triggers independent cleanup.
   if(adapter.has_root()&&adapter.root_exited()){reason=4;break;}
   DWORD available=0;if(!PeekNamedPipe(input.get(),nullptr,0,nullptr,&available,nullptr)){reason=5;failed=GetLastError()!=ERROR_BROKEN_PIPE;break;}
   if(available){char command=0;DWORD read=0;if(!ReadFile(input.get(),&command,1,&read,nullptr)||read!=1){reason=5;break;}
    if(command=='S'){reason=6;break;}
    if(command=='A'){need(adapter.start());acquisition_polls=0;}
    else if(command=='Q'){need(journal.append(service_status,adapter.generation(),{},0,(unsigned)status.state));}
    else if(command=='C'){
     need(adapter.has_root()&&adapter.valid_root()&&adapter.before(Action::terminate_root)&&adapter.terminate_root());reason=7;break;
    }else if(command=='R'){
     auto stopped=cleanup(adapter,20,false);need(stopped.quiesced&&stopped.errors.empty());need(adapter.next_generation()&&adapter.start());acquisition_polls=0;previous=State::unknown;
    }else if(command!='A'){reason=8;failed=true;break;}
   }
   Sleep(50);
  }
 }catch(...){failed=true;reason=9;}
 // Reporting cannot prevent cleanup, and one failed cleanup step cannot suppress others.
 bool reason_written=journal.append(watch_reason,adapter.generation(),{},0,reason);
 Report result;if(adapter.owned())result=cleanup(adapter,20);
 bool final_written=journal.append(final_report,adapter.generation(),{},(unsigned)result.errors.size(),result.removed?0:1);
 return(!failed&&reason_written&&final_written&&result.removed&&result.errors.empty())?0:20;
}
}
int wmain(int argc,wchar_t**argv){
 // Deliberately no automatic provisioning or arbitrary service/executable/path selection.
 if(argc!=5||std::wstring(argv[1])!=L"--guard")return 64;
 try{return run(argv[2],inherited(argv[3]),inherited(argv[4]));}catch(...){return 21;}
}
