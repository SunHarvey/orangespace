#include "admission_client_win.hpp"
#include "admission_protocol.hpp"
#include <windows.h>
#include <bcrypt.h>
#include <thread>
#include <array>
#include <cstdio>
#include <string>
namespace orangespace::prototype {
namespace {
thread_local AdmissionStage stage = AdmissionStage::none;
struct Handle { HANDLE h=nullptr; ~Handle(){if(h && h!=INVALID_HANDLE_VALUE) CloseHandle(h);} };
struct Sc { SC_HANDLE h=nullptr; ~Sc(){if(h) CloseServiceHandle(h);} };
bool Alive(HANDLE h){return WaitForSingleObject(h,0)==WAIT_TIMEOUT;}
std::uint64_t Birth(HANDLE h) {
 FILETIME a{},b{},c{},d{}; if(!GetProcessTimes(h,&a,&b,&c,&d)) return 0;
 return (static_cast<std::uint64_t>(a.dwHighDateTime)<<32)|a.dwLowDateTime;
}
bool ScmBound(SC_HANDLE s,HANDLE process,HANDLE pipe,DWORD pid) {
 DWORD bytes=0; QueryServiceConfigW(s,nullptr,0,&bytes);
 if(GetLastError()!=ERROR_INSUFFICIENT_BUFFER || bytes<sizeof(QUERY_SERVICE_CONFIGW) || bytes>65536) return false;
 alignas(QUERY_SERVICE_CONFIGW) std::array<unsigned char,65536> storage{};
 auto* c=reinterpret_cast<QUERY_SERVICE_CONFIGW*>(storage.data());
 if(!QueryServiceConfigW(s,c,bytes,&bytes) || c->dwServiceType!=SERVICE_WIN32_OWN_PROCESS ||
    !c->lpServiceStartName || wcscmp(c->lpServiceStartName,L"LocalSystem")) return false;
 SERVICE_STATUS_PROCESS p{}; ULONG peer=0;
 return QueryServiceStatusEx(s,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE*>(&p),sizeof(p),&bytes) &&
 p.dwServiceType==SERVICE_WIN32_OWN_PROCESS && p.dwCurrentState==SERVICE_RUNNING && p.dwProcessId==pid &&
 GetNamedPipeServerProcessId(pipe,&peer) && peer==pid && Alive(process);
}
bool SystemToken(HANDLE process) {
 Handle token; if(!OpenProcessToken(process,TOKEN_QUERY,&token.h)) return false;
 alignas(TOKEN_USER) BYTE data[512]{}; DWORD bytes=0;
 if(!GetTokenInformation(token.h,TokenUser,data,sizeof(data),&bytes)) return false;
 BYTE sid[SECURITY_MAX_SID_SIZE]{}; DWORD size=sizeof(sid);
 return CreateWellKnownSid(WinLocalSystemSid,nullptr,sid,&size) &&
 EqualSid(reinterpret_cast<TOKEN_USER*>(data)->User.Sid,sid);
}
bool Transfer(HANDLE pipe,HANDLE process,void* data,DWORD size,bool write,HANDLE event,DWORD timeout=1500) {
 if(!ResetEvent(event)) return false;
 OVERLAPPED ov{}; ov.hEvent=event; DWORD n=0;
 BOOL ok=write?WriteFile(pipe,data,size,&n,&ov):ReadFile(pipe,data,size,&n,&ov);
 if(!ok) {
  if(GetLastError()!=ERROR_IO_PENDING) return false;
  HANDLE waits[]{process,event};
  if(WaitForMultipleObjects(2,waits,FALSE,timeout)!=WAIT_OBJECT_0+1) {
   CancelIoEx(pipe,&ov); GetOverlappedResult(pipe,&ov,&n,TRUE); return false;
  }
  ok=GetOverlappedResult(pipe,&ov,&n,FALSE);
 }
 return ok && n==size && Alive(process);
}
}
struct Admission::State {
 Handle process,pipe,stop,start,read_event,transfer_event;
 std::thread monitor;
 std::unique_ptr<PrivateOwner> private_owner;
 ~State(){if(stop.h) SetEvent(stop.h); if(monitor.joinable()) monitor.join();}
};
Admission::Admission():state_(std::make_unique<State>()){}
Admission::~Admission()=default;
const PrivateOwner* Admission::private_channel() const noexcept {return state_->private_owner.get();}
AdmissionStage Admission::LastFailureStage() noexcept { return stage; }
std::unique_ptr<Admission> Admission::Acquire() noexcept {
 try {
  stage = AdmissionStage::allocation;
  auto a=std::unique_ptr<Admission>(new Admission); auto& st=*a->state_;
  // No caller-selected service/pipe, no command-line process-type exception.
  stage = AdmissionStage::open_thread_token;
  Handle thread_token;
  const BOOL has_thread=OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&thread_token.h);
  const DWORD thread_error=has_thread?ERROR_SUCCESS:GetLastError();
  if(has_thread || thread_error!=ERROR_NO_TOKEN){
   HANDLE query=thread_token.h;Handle extra,primary;
   if(!query&&OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,FALSE,&extra.h))query=extra.h;
   DWORD ac=0,caps=0,n=0;bool caps_valid=false;BOOL same_user=FALSE,same_app=FALSE,same_session=FALSE,same_logon=FALSE;
   if(query&&OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&primary.h)){
    GetTokenInformation(query,TokenIsAppContainer,&ac,sizeof(ac),&n);
    alignas(TOKEN_GROUPS) BYTE groups[4096]{};if(GetTokenInformation(query,TokenCapabilities,groups,sizeof(groups),&n)){caps=reinterpret_cast<TOKEN_GROUPS*>(groups)->GroupCount;caps_valid=true;}
    alignas(TOKEN_USER) BYTE u[512]{},p[512]{};if(GetTokenInformation(query,TokenUser,u,sizeof(u),&n)&&GetTokenInformation(primary.h,TokenUser,p,sizeof(p),&n))same_user=EqualSid(reinterpret_cast<TOKEN_USER*>(u)->User.Sid,reinterpret_cast<TOKEN_USER*>(p)->User.Sid);
    alignas(TOKEN_APPCONTAINER_INFORMATION) BYTE a1[512]{},a2[512]{};if(GetTokenInformation(query,TokenAppContainerSid,a1,sizeof(a1),&n)&&GetTokenInformation(primary.h,TokenAppContainerSid,a2,sizeof(a2),&n)){auto s1=reinterpret_cast<TOKEN_APPCONTAINER_INFORMATION*>(a1)->TokenAppContainer;auto s2=reinterpret_cast<TOKEN_APPCONTAINER_INFORMATION*>(a2)->TokenAppContainer;same_app=s1&&s2&&EqualSid(s1,s2);}
    DWORD s1{},s2{};if(GetTokenInformation(query,TokenSessionId,&s1,sizeof(s1),&n)&&GetTokenInformation(primary.h,TokenSessionId,&s2,sizeof(s2),&n))same_session=s1==s2;
    TOKEN_STATISTICS t1{},t2{};if(GetTokenInformation(query,TokenStatistics,&t1,sizeof(t1),&n)&&GetTokenInformation(primary.h,TokenStatistics,&t2,sizeof(t2),&n))same_logon=t1.AuthenticationId.LowPart==t2.AuthenticationId.LowPart&&t1.AuthenticationId.HighPart==t2.AuthenticationId.HighPart;
   }
   wchar_t temp[32768]{};DWORD len=GetTempPathW(32768,temp);if(len&&len<32768){std::wstring path(temp,len);path+=L"orangespace-cef-early.log";Handle out{CreateFileW(path.c_str(),FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr)};if(out.h!=INVALID_HANDLE_VALUE){char text[256]{};int size=std::snprintf(text,sizeof(text),"admission-thread pid=%lu original_error=%lu query=%d ac=%lu caps=%lu same_user=%d same_app=%d same_session=%d same_logon=%d\n",GetCurrentProcessId(),thread_error,query!=nullptr,ac,caps,same_user,same_app,same_session,same_logon);if(size>0&&size<static_cast<int>(sizeof(text))){DWORD written{};WriteFile(out.h,text,static_cast<DWORD>(size),&written,nullptr);}}}
   // Chromium startup can retain a same-owner warm-up impersonation token.
   // Accept only the identical zero-capability AppContainer/session/logon;
   // a different, unqueryable or network-capable effective token stays denied.
   if(!has_thread||!caps_valid||ac!=1||caps!=0||!same_user||!same_app||!same_session||!same_logon)return {};
  }
  stage = AdmissionStage::open_sc_manager;
  Sc scm{OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT)}; if(!scm.h) return {};
  stage = AdmissionStage::open_service;
  Sc service{OpenServiceW(scm.h,kService,SERVICE_QUERY_CONFIG|SERVICE_QUERY_STATUS)}; if(!service.h) return {};
  stage = AdmissionStage::query_service_status;
  SERVICE_STATUS_PROCESS status{}; DWORD bytes=0;
  if(!QueryServiceStatusEx(service.h,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE*>(&status),sizeof(status),&bytes) ||
      status.dwCurrentState!=SERVICE_RUNNING || !status.dwProcessId) return {};
  stage = AdmissionStage::open_process;
  st.process.h=OpenProcess(SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,status.dwProcessId);
  if(!st.process.h || (stage = AdmissionStage::system_token, !SystemToken(st.process.h))) return {};
  stage = AdmissionStage::process_birth;
  const auto server_birth=Birth(st.process.h); if(!server_birth) return {};
  // Individual rights exclude FILE_CREATE_PIPE_INSTANCE. Identification is
  // sufficient for server token validation; never allow SYSTEM impersonation.
  stage = AdmissionStage::pipe_open;
  // A busy instance is contention, not admission denial. Retry only that
  // error within one fixed open budget; every success still authenticates SCM.
  const ULONGLONG open_started=GetTickCount64();
  st.pipe.h=INVALID_HANDLE_VALUE;
  while(Alive(st.process.h)) {
   if(GetTickCount64()-open_started>=1500) {SetLastError(ERROR_SEM_TIMEOUT);break;}
   st.pipe.h=CreateFileW(kPipe,0x12019b,0,nullptr,OPEN_EXISTING,
     FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,nullptr);
   if(st.pipe.h!=INVALID_HANDLE_VALUE) {
    if(GetTickCount64()-open_started>=1500) {
     CloseHandle(st.pipe.h);st.pipe.h=INVALID_HANDLE_VALUE;
     SetLastError(ERROR_SEM_TIMEOUT);
    }
    break;
   }
   if(GetLastError()!=ERROR_PIPE_BUSY) break;
   const ULONGLONG elapsed=GetTickCount64()-open_started;
   if(elapsed>=1500) {SetLastError(ERROR_SEM_TIMEOUT);break;}
   // The instance may be taken by another child after the wait: reopen/retry.
   const DWORD slice=static_cast<DWORD>((1500-elapsed)<50?(1500-elapsed):50);
   if(!WaitNamedPipeW(kPipe,slice)) {
    const DWORD error=GetLastError();
    if(error!=ERROR_SEM_TIMEOUT && error!=ERROR_PIPE_BUSY) break;
   }
  }
  if(st.pipe.h==INVALID_HANDLE_VALUE){
   const DWORD error=GetLastError();wchar_t temp[32768]{};const DWORD n=GetTempPathW(32768,temp);
   if(n&&n<32768){std::wstring path(temp,n);path+=L"orangespace-cef-early.log";Handle out{CreateFileW(path.c_str(),FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr)};if(out.h!=INVALID_HANDLE_VALUE){char text[96]{};const int len=std::snprintf(text,sizeof(text),"admission-pipe-open pid=%lu win32=%lu\n",GetCurrentProcessId(),error);if(len>0&&len<static_cast<int>(sizeof(text))){DWORD written{};WriteFile(out.h,text,static_cast<DWORD>(len),&written,nullptr);}}}
   return {};
  }
  stage = AdmissionStage::pipe_mode_scm_bound;
  DWORD mode=PIPE_READMODE_MESSAGE;
  if(!SetNamedPipeHandleState(st.pipe.h,&mode,nullptr,nullptr) ||
     !ScmBound(service.h,st.process.h,st.pipe.h,status.dwProcessId)) return {};
  stage = AdmissionStage::nonce;
  Request q{}; q.pid=GetCurrentProcessId(); q.created=Birth(GetCurrentProcess());
  DWORD session=0;
  if(!q.created || !ProcessIdToSessionId(q.pid,&session) || !session ||
     BCryptGenRandom(nullptr,q.nonce.data(),static_cast<ULONG>(q.nonce.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG)!=0) return {};
  q.session=static_cast<std::uint32_t>(session);
  stage = AdmissionStage::provisional_write;
  st.transfer_event.h=CreateEventW(nullptr,TRUE,FALSE,nullptr);
  if(!st.transfer_event.h) return {};
  Reply r{};
  if(!Transfer(st.pipe.h,st.process.h,&q,sizeof(q),true,st.transfer_event.h) || (stage = AdmissionStage::provisional_read, !Transfer(st.pipe.h,st.process.h,&r,sizeof(r),false,st.transfer_event.h)) ||
     (stage = AdmissionStage::provisional_validation, !ScmBound(service.h,st.process.h,st.pipe.h,status.dwProcessId) ||
     !ValidProvisionalReply(r,q,status.dwProcessId,server_birth))) return {};
  stage = AdmissionStage::own_job;
  BOOL job=FALSE; if(!IsProcessInJob(GetCurrentProcess(),nullptr,&job) || !job) return {};
  stage = AdmissionStage::pre_ack_storage_thread;
  st.stop.h=CreateEventW(nullptr,TRUE,FALSE,nullptr); if(!st.stop.h) return {};
  st.start.h=CreateEventW(nullptr,TRUE,FALSE,nullptr);
  st.read_event.h=CreateEventW(nullptr,TRUE,FALSE,nullptr);
  if(!st.start.h || !st.read_event.h) return {};
  // Precreate all storage/events/thread, but commit transfer remains sole reader.
  st.monitor=std::thread([&st]{
   HANDLE startup[]{st.stop.h,st.start.h};
   const DWORD started=WaitForMultipleObjects(2,startup,FALSE,INFINITE);
   if(started==WAIT_OBJECT_0) return;
   if(started!=WAIT_OBJECT_0+1) {TerminateProcess(GetCurrentProcess(),71); return;}
   if(st.private_owner) {
    std::uint64_t sequence=0;
    while(Alive(st.process.h)&&WaitForSingleObject(st.stop.h,0)==WAIT_TIMEOUT) {
     BrowserFrame command{};
     if(!Transfer(st.pipe.h,st.process.h,&command,sizeof(command),false,st.read_event.h)||!ValidBrowserFrame(command)||command.sequence!=++sequence)break;
     auto state=st.private_owner->exchange(command);
     if(!ValidBrowserFrame(state)||!Transfer(st.pipe.h,st.process.h,&state,sizeof(state),true,st.read_event.h))break;
     if(command.command==5){if(WaitForSingleObject(st.stop.h,5000)==WAIT_OBJECT_0)return;break;}
    }
    if(WaitForSingleObject(st.stop.h,0)==WAIT_OBJECT_0)return;
    TerminateProcess(GetCurrentProcess(),71);return;
   }
   OVERLAPPED ov{}; ov.hEvent=st.read_event.h; BYTE revoke=0; DWORD n=0;
   BOOL ok=ReadFile(st.pipe.h,&revoke,1,&n,&ov);
   if(!ok && GetLastError()==ERROR_IO_PENDING) {
    HANDLE waits[]{st.stop.h,st.process.h,st.read_event.h};
    DWORD w=WaitForMultipleObjects(3,waits,FALSE,INFINITE);
    CancelIoEx(st.pipe.h,&ov); GetOverlappedResult(st.pipe.h,&ov,&n,TRUE);
    if(w==WAIT_OBJECT_0) return;
   }
   TerminateProcess(GetCurrentProcess(),71);
  });
  Reply committed{};
  BYTE ack=6;
  stage = AdmissionStage::ack_write;
  if(!Transfer(st.pipe.h,st.process.h,&ack,1,true,st.transfer_event.h) ||
     (stage = AdmissionStage::committed_read, !Transfer(st.pipe.h,st.process.h,&committed,sizeof(committed),false,st.transfer_event.h)) ||
     (stage = AdmissionStage::committed_validation, !ValidReply(r,q,status.dwProcessId,server_birth,&committed)) ||
     (stage = AdmissionStage::postcommit_live_checks, Birth(st.process.h)!=server_birth) || !SystemToken(st.process.h) ||
     !ScmBound(service.h,st.process.h,st.pipe.h,status.dwProcessId) ||
     !IsProcessInJob(GetCurrentProcess(),nullptr,&job) || !job) return {};
  // Only actual root identity from authenticated public COMMITTED receives secrets.
  if(committed.pid==committed.root_pid && committed.created==committed.root_created) {
   st.private_owner=std::make_unique<PrivateOwner>(); // final owner BEFORE private ACK
   auto& offer=st.private_owner->offer;
   // The Service performs a fresh forwarding probe before offering credentials.
   // The wait is bounded independently of the unmodified lease and proof checks.
   stage=AdmissionStage::private_offer_read;
   if(!Transfer(st.pipe.h,st.process.h,&offer,sizeof(offer),false,st.transfer_event.h,5000))return {};
   stage=AdmissionStage::private_offer_validate;
   if(!ValidPrivateOffer(offer,committed,static_cast<std::int64_t>(GetTickCount64())))return {};
   PrivateReceipt expected{};expected.base=committed;expected.nonce=offer.nonce;
   BCRYPT_ALG_HANDLE algorithm{};
   if(BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,nullptr,0)!=0)return {};
   const auto hashed=BCryptHash(algorithm,nullptr,0,reinterpret_cast<PUCHAR>(&offer),sizeof(offer),expected.digest.data(),32);
   BCryptCloseAlgorithmProvider(algorithm,0);if(hashed!=0)return {};
   auto private_ack=expected;private_ack.phase=6;PrivateReceipt private_committed{};
   stage=AdmissionStage::private_commit;
   if(!Transfer(st.pipe.h,st.process.h,&private_ack,sizeof(private_ack),true,st.transfer_event.h)||
      !Transfer(st.pipe.h,st.process.h,&private_committed,sizeof(private_committed),false,st.transfer_event.h)||
      !ValidPrivateReceipt(expected,private_committed,2)||
      !ValidPrivateOffer(offer,committed,static_cast<std::int64_t>(GetTickCount64()))||
      !ScmBound(service.h,st.process.h,st.pipe.h,status.dwProcessId))return {};
  }
  // No competing revocation ReadFile until both authenticated receipts are consumed.
  stage = AdmissionStage::monitor_release;
  if(!SetEvent(st.start.h)) return {};
  return a;
 } catch(...) {return {};}
}
}
