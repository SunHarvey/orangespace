// Opt-in isolated dummy fixture ONLY. This is not the production service.
#include "phase1_guardian_win.hpp"
#include <atomic>
using namespace phase1_guardian::win;
namespace {
SERVICE_STATUS_HANDLE status_handle=nullptr;
SERVICE_STATUS status{};
Handle stop_event;
std::atomic<int> service_result{0};
void state(DWORD value,DWORD controls,DWORD wait_hint=0){
 status.dwServiceType=SERVICE_WIN32_OWN_PROCESS;status.dwCurrentState=value;status.dwControlsAccepted=controls;status.dwWin32ExitCode=NO_ERROR;status.dwWaitHint=wait_hint;
 status.dwCheckPoint=(value==SERVICE_START_PENDING||value==SERVICE_STOP_PENDING)?status.dwCheckPoint+1:0;
 need(SetServiceStatus(status_handle,&status)!=FALSE);
}
DWORD WINAPI control(DWORD code,DWORD,void*,void*){
 // No status writes here: one ServiceMain writer avoids handler/main data races.
 if(code==SERVICE_CONTROL_STOP){return SetEvent(stop_event.get())?NO_ERROR:ERROR_GEN_FAILURE;}
 return code==SERVICE_CONTROL_INTERROGATE?NO_ERROR:ERROR_CALL_NOT_IMPLEMENTED;
}
void WINAPI service_main(DWORD argc,LPWSTR*argv){
 try{
  status_handle=RegisterServiceCtrlHandlerExW(L"OrangeSpaceFoundation",control,nullptr);need(status_handle!=nullptr);
  state(SERVICE_START_PENDING,0,2000);
  need(argc==2&&argv&&argv[1]);wchar_t* end=nullptr;unsigned long g=wcstoul(argv[1],&end,10);need(end&&!*end&&g<16&&std::to_wstring(g)==argv[1]);
  auto own=module_path();auto prefix=program_files()+L"\\OrangeSpacePhase1Guardian-";need(own.size()>prefix.size()+32&&equal_path(own.substr(0,prefix.size()),prefix));
  std::wstring nonce=own.substr(prefix.size(),32);Scope s(nonce);need(equal_path(own,s.service_exe)&&s.approval.expected_helpers==0);
  auto identity=describe(GetCurrentProcess());need(identity.system);

  // This evidence originates INSIDE SCM ServiceMain, not a potentially invalid pending PID.
  s.recheck();SelfClaim claim{};std::memcpy(claim.magic,"OSGRT001",8);claim.generation=(unsigned)g;std::string ascii(nonce.begin(),nonce.end());std::memcpy(claim.nonce,ascii.data(),32);claim.process=identity;
  {auto file=new_protected_file(s.claim_name((unsigned)g));DWORD n=0;need(WriteFile(file.get(),&claim,sizeof(claim),&n,nullptr)&&n==sizeof(claim)&&FlushFileBuffers(file.get()));}
  Sleep(750);state(SERVICE_RUNNING,SERVICE_ACCEPT_STOP);
  DWORD wait=WaitForSingleObject(stop_event.get(),30000);need(wait==WAIT_OBJECT_0||wait==WAIT_TIMEOUT);
  state(SERVICE_STOP_PENDING,0,2000);Sleep(750);state(SERVICE_STOPPED,0);
 }catch(...){service_result.store(10);if(status_handle){status.dwWin32ExitCode=ERROR_GEN_FAILURE;status.dwCurrentState=SERVICE_STOPPED;status.dwControlsAccepted=0;if(!SetServiceStatus(status_handle,&status))service_result.store(11);}}
}
}
int wmain(){stop_event.reset(CreateEventW(nullptr,TRUE,FALSE,nullptr));if(!stop_event)return 10;
 SERVICE_TABLE_ENTRYW table[]={{const_cast<LPWSTR>(L"OrangeSpaceFoundation"),service_main},{nullptr,nullptr}};
 if(!StartServiceCtrlDispatcherW(table))return 10;
 // Deliberately make SCM STOPPED precede the actual process exit.
 Sleep(250);return service_result.load();
}
