// Opt-in controller library. No main, no implicit account/service changes.
#include "phase1_os_b_integration.hpp"
#include "phase1_os_b_win.hpp"
#include <lm.h>
namespace phase1_os_b {
namespace {
struct Password {
 wchar_t value[69]{};
 Password(){BYTE b[32];need(BCryptGenRandom(nullptr,b,sizeof(b),BCRYPT_USE_SYSTEM_PREFERRED_RNG)==0,"password_random");for(unsigned i=0;i<32;++i){value[2*i]=L"0123456789abcdef"[b[i]>>4];value[2*i+1]=L"0123456789abcdef"[b[i]&15];}value[64]=L'A';value[65]=L'a';value[66]=L'9';value[67]=L'!';SecureZeroMemory(b,sizeof(b));}
 ~Password(){SecureZeroMemory(value,sizeof(value));}
};
struct Privileges {
 Handle token;TOKEN_PRIVILEGES old[2]{};bool changed[2]{};
 void restore()noexcept{for(int i=1;i>=0;--i)if(changed[i]){AdjustTokenPrivileges(token.h,FALSE,&old[i],0,nullptr,nullptr);changed[i]=false;}}
 Privileges(){
  try{need(OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&token.h),"privileges_token");
   const wchar_t* names[]={SE_BACKUP_NAME,SE_RESTORE_NAME};for(unsigned i=0;i<2;++i){TOKEN_PRIVILEGES p{};p.PrivilegeCount=1;need(LookupPrivilegeValueW(nullptr,names[i],&p.Privileges[0].Luid),"privilege_lookup");p.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;DWORD n=sizeof(old[i]);SetLastError(0);BOOL ok=AdjustTokenPrivileges(token.h,FALSE,&p,n,&old[i],&n);auto error=GetLastError();changed[i]=ok;need(ok&&error==ERROR_SUCCESS,"privilege_enable");}
  }catch(...){restore();throw;}
 }
 ~Privileges(){restore();}
};
std::wstring account_sid(const std::wstring& name){
 LPBYTE raw=nullptr;const auto rc=NetUserGetInfo(nullptr,name.c_str(),4,&raw);
 struct Free {LPBYTE p;~Free(){if(p)NetApiBufferFree(p);}} free{raw};SetLastError(rc);need(rc==NERR_Success&&raw,"account_readback");
 auto* user=reinterpret_cast<USER_INFO_4*>(raw);need(user->usri4_priv==USER_PRIV_USER&&!(user->usri4_flags&UF_ACCOUNTDISABLE),"account_ordinary");
 wchar_t* sid=nullptr;need(ConvertSidToStringSidW(user->usri4_user_sid,&sid),"account_sid");Local memory(sid);return sid;
}
bool missing_account(const std::wstring& name){LPBYTE p=nullptr;auto e=NetUserGetInfo(nullptr,name.c_str(),0,&p);if(p)NetApiBufferFree(p);return e==NERR_UserNotFound;}

std::wstring module_path(){wchar_t s[32768];auto n=GetModuleFileNameW(nullptr,s,32768);need(n>0&&n<32768,"controller_module");return {s,n};}
}
struct ControllerRun::Impl {
 Receipt r;Handle token,process,thread,job,pipe;HANDLE profile=nullptr;
 bool attempted=false,job_assigned=false;DWORD pid=0;
 bool reap(){
  if(process.h){
   if(WaitForSingleObject(process.h,0)!=WAIT_OBJECT_0){if(job_assigned)TerminateJobObject(job.h,94);if(WaitForSingleObject(process.h,0)!=WAIT_OBJECT_0)TerminateProcess(process.h,94);}
   if(WaitForSingleObject(process.h,10000)!=WAIT_OBJECT_0)return false;
   r.process_reaped=true;
  }
  else r.process_reaped=true;
  r.io_quarantined=private_io_budget.has_retained();
  if(!private_io_budget.reap_retained())return false;
  r.io_quarantined=false;thread.reset();process.reset();job.reset();pipe.reset();r.handles_closed=true;return true;
 }
 bool unload(){
  if(r.profile_unloaded)return true;
  Privileges p;if(!UnloadUserProfile(token.h,profile))return false;profile=nullptr;r.profile_unloaded=true;r.profile_loaded=false;return true;
 }
 bool erase_profile(){
  if(r.profile_deleted)return true;
  // Token is not required by DeleteProfile. Close it only after successful unload.
  token.reset();Privileges p;BOOL ok=DeleteProfileW(r.sid.c_str(),r.profile_path.c_str(),nullptr);if(ok){r.profile_deleted=true;r.profile_state=ProfileState::owned_removed;}return ok!=FALSE;
 }
 bool profile_absent(){
  const auto deadline=GetTickCount64()+5000;
  do{if(registry_absent(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\"+r.sid)&&registry_absent(HKEY_USERS,r.sid)&&path_absent(r.profile_path)){r.profile_absence_verified=true;return true;}Sleep(50);}while(GetTickCount64()<deadline);return false;
 }
 bool no_profile(){
  const auto list=registry_presence(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\"+r.sid);
  const auto hive=registry_presence(HKEY_USERS,r.sid);r.profile_state=profile_probe(list,hive);
  return r.profile_state==ProfileState::verified_no_profile;
 }
 bool account_matches(){if(r.account_deleted)return missing_account(r.account);return !r.account.empty()&&!r.sid.empty()&&r.account.starts_with(L"OSB1_")&&account_sid(r.account)==r.sid;}
 bool erase_account(){token.reset();if(r.account_deleted)return true;auto rc=NetUserDel(nullptr,r.account.c_str());if(rc==NERR_Success)r.account_deleted=true;return rc==NERR_Success;}
 bool account_absent(){r.account_absence_verified=missing_account(r.account);return r.account_absence_verified;}
 bool clear()noexcept{
  if(!attempted)return true;
  if(r.cleanup_ok)return true;
  try{
   // Facts describe the original allocation even after individual successful
   // cleanup steps; operations are receipt-idempotent for parent retry.
   CleanupFacts f{r.account_created,r.sid_recorded,r.profile_attempted,r.profile_loaded||r.profile_unloaded,r.profile_path_recorded,r.profile_state};
   SetLastError(ERROR_SUCCESS);r.cleanup_ok=phase1_os_b::cleanup(f,*this);if(!r.cleanup_ok){auto error=GetLastError();r.cleanup_error=error?error:ERROR_INVALID_DATA;}return r.cleanup_ok;
  }catch(Failure f){r.cleanup_error=f.code;return false;}catch(...){r.cleanup_error=ERROR_INVALID_DATA;return false;}
 }
 void execute(const std::wstring& root,std::string_view body,HANDLE held_a_process,const std::function<bool(ControlPoint)>& still_live,const std::function<bool(const Receipt&)>& record){
  auto fields=decode(body);need(valid_fields(fields),"controller_input");const auto a=current_identity();
  need(a.session==2&&narrow(a.sid)==fields[sid_a],"controller_a_identity");
  need(held_a_process&&held_a_process!=INVALID_HANDLE_VALUE&&WaitForSingleObject(held_a_process,0)==WAIT_TIMEOUT,"held_limited_a_process");Handle limited_a_token;need(OpenProcessToken(held_a_process,TOKEN_QUERY,&limited_a_token.h),"held_limited_a_token");const auto limited_a=identity(limited_a_token.h);
  std::uint64_t luid=0;need(decimal(fields[luid_a],luid)&&luid==limited_a.luid&&limited_a.sid==a.sid&&limited_a.session==2,"held_limited_a_actual_identity");
  TOKEN_ELEVATION limited_elevation{};DWORD limited_size=0;need(GetTokenInformation(limited_a_token.h,TokenElevation,&limited_elevation,sizeof(limited_elevation),&limited_size)&&!limited_elevation.TokenIsElevated,"held_a_not_elevated");
  wchar_t a_image[32768];DWORD a_length=32768;need(QueryFullProcessImageNameW(held_a_process,0,a_image,&a_length)&&std::wstring_view(a_image,a_length)==root+L"\\phase1_client.exe","held_limited_a_image");
  Handle own;need(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&own.h),"controller_token");TOKEN_ELEVATION elevation{};DWORD bytes=0;need(GetTokenInformation(own.h,TokenElevation,&elevation,sizeof(elevation),&bytes)&&elevation.TokenIsElevated,"controller_highest");
  need(ns::detail::explicit_local_path(root)&&root.starts_with(L"C:\\Program Files\\OrangeSpace-phase1-")&&module_path()==root+L"\\phase1_controller.exe","protected_fixture_root");
  r.launch_privileges_present=launch_privileges(own.h);if(!r.launch_privileges_present)throw Failure{"atomic_launch_requires_assignprimarytoken_increasequota",ERROR_PRIVILEGE_NOT_HELD};
  Password password;r.account=L"OSB1_"+wide(random_hex(6));need(missing_account(r.account),"fresh_account_name");need(record(r),"recovery_account_intent");
  USER_INFO_1 ui{};ui.usri1_name=r.account.data();ui.usri1_password=password.value;ui.usri1_priv=USER_PRIV_USER;ui.usri1_flags=UF_SCRIPT;DWORD parameter=0;
  auto rc=NetUserAdd(nullptr,1,reinterpret_cast<LPBYTE>(&ui),&parameter);SetLastError(rc);need(rc==NERR_Success,"ordinary_account_add");r.account_created=true;
  r.sid=account_sid(r.account);r.sid_recorded=true;need(r.sid!=a.sid,"ordinary_account_distinct_sid");need(record(r),"recovery_account_sid");
  need(no_profile(),"fresh_profile_sid");need(record(r),"recovery_verified_no_profile");
  need(LogonUserW(r.account.c_str(),L".",password.value,LOGON32_LOGON_INTERACTIVE,LOGON32_PROVIDER_DEFAULT,&token.h),"b_profile_logon");const auto logged_on=identity(token.h);need(logged_on.sid==r.sid,"b_profile_token_sid");
  r.b_token_session2=logged_on.session==2;if(!r.b_token_session2)throw Failure{"atomic_launch_requires_b_primary_token_session2_no_token_mutation",ERROR_BAD_TOKEN_TYPE};
  PROFILEINFOW info{};info.dwSize=sizeof(info);info.dwFlags=PI_NOUI;info.lpUserName=r.account.data();r.profile_attempted=true;r.profile_state=ProfileState::attempted;need(record(r),"recovery_profile_intent");
  {Privileges p;need(LoadUserProfileW(token.h,&info),"b_load_profile");}profile=info.hProfile;r.profile_loaded=true;
  wchar_t path[32768];DWORD size=32768;need(GetUserProfileDirectoryW(token.h,path,&size),"b_profile_path");r.profile_path=path;
  need(ns::detail::explicit_local_path(r.profile_path)&&!path_absent(r.profile_path),"b_actual_profile_path");
  // Bind recorded path to SID registry value, not C:\Users\<guessed name>.
  HKEY key=nullptr;auto keyname=L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\"+r.sid;
  need(RegOpenKeyExW(HKEY_LOCAL_MACHINE,keyname.c_str(),0,KEY_READ,&key)==ERROR_SUCCESS,"b_profile_registry");
  wchar_t registered[32768];DWORD length=sizeof(registered),type=0;auto query=RegQueryValueExW(key,L"ProfileImagePath",nullptr,&type,reinterpret_cast<BYTE*>(registered),&length);RegCloseKey(key);
  need(query==ERROR_SUCCESS&&(type==REG_SZ||type==REG_EXPAND_SZ)&&length>=sizeof(wchar_t)&&length<=sizeof(registered)&&length%sizeof(wchar_t)==0&&registered[length/sizeof(wchar_t)-1]==0,"b_profile_registry_path");
  // Refuse expandable paths rather than trusting A's environment to expand B.
  need(std::wstring(registered)==r.profile_path,"b_sid_path_match");r.profile_path_recorded=true;r.profile_state=ProfileState::owned_loaded;need(record(r),"recovery_profile_sid_path");
  auto private_name=L"\\\\.\\pipe\\OrangeSpace.Phase1.OSB."+wide(random_hex(16));
  auto sd=descriptor(L"O:"+a.sid+L"D:P(A;;0x12019b;;;SY)(A;;0x12019b;;;"+a.sid+L")(A;;0x12019b;;;"+r.sid+L")");SECURITY_ATTRIBUTES sa{sizeof(sa),sd.get(),FALSE};
  pipe.reset(CreateNamedPipeW(private_name.c_str(),PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED|FILE_FLAG_FIRST_PIPE_INSTANCE,PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,131072,131072,0,&sa));need(pipe.h!=INVALID_HANDLE_VALUE,"private_pipe_create");
  job.reset(CreateJobObjectW(nullptr,nullptr));need(job.h!=nullptr,"b_job");JOBOBJECT_EXTENDED_LIMIT_INFORMATION limit{};limit.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_ACTIVE_PROCESS;limit.BasicLimitInformation.ActiveProcessLimit=1;
  need(SetInformationJobObject(job.h,JobObjectExtendedLimitInformation,&limit,sizeof(limit)),"b_job_policy");
  const auto exe=root+L"\\phase1_os_b_worker.exe";std::wstring cmd=L"\""+exe+L"\" \""+root+L"\\nodes.json\" \""+private_name+L"\" "+std::to_wstring(GetCurrentProcessId());
  void* environment=nullptr;need(CreateEnvironmentBlock(&environment,token.h,FALSE),"b_environment");struct Env {void* p;~Env(){if(p)DestroyEnvironmentBlock(p);}} env{environment};
  STARTUPINFOEXW startup{};startup.StartupInfo.cb=sizeof(startup);wchar_t private_desktop[]=L"";startup.StartupInfo.lpDesktop=private_desktop;JobAdmission admission(job.h);startup.lpAttributeList=admission.list;r.atomic_job_attribute_set=true;PROCESS_INFORMATION pi{};
  // No CreateProcessWithLogonW compatibility assumption and NO post-create
  // AssignProcessToJobObject fallback. Kernel admission uses JOB_LIST.
  need(CreateProcessAsUserW(token.h,exe.c_str(),cmd.data(),nullptr,nullptr,FALSE,CREATE_SUSPENDED|CREATE_NO_WINDOW|CREATE_UNICODE_ENVIRONMENT|EXTENDED_STARTUPINFO_PRESENT,environment,root.c_str(),&startup.StartupInfo,&pi),"b_atomic_create_process_as_user");
  process.reset(pi.hProcess);thread.reset(pi.hThread);pid=pi.dwProcessId;r.process_created=true;job_assigned=true;r.atomic_launch_created=true;r.process_id=pid;FILETIME creation{},exit_time{},kernel{},user{};need(GetProcessTimes(process.h,&creation,&exit_time,&kernel,&user),"b_creation_identity");r.creation_low=creation.dwLowDateTime;r.creation_high=creation.dwHighDateTime;need(record(r),"recovery_owned_child");SecureZeroMemory(password.value,sizeof(password.value));
  BOOL in_job=FALSE;need(IsProcessInJob(process.h,job.h,&in_job)&&in_job,"b_actual_atomic_job_membership");
  Handle child_token;need(OpenProcessToken(process.h,TOKEN_QUERY,&child_token.h),"b_child_token");const auto b=identity(child_token.h);
  need(b.sid==r.sid&&b.sid!=a.sid&&b.luid!=limited_a.luid&&b.luid!=a.luid&&b.session==a.session,"b_actual_independent_logon");
  wchar_t image[32768];size=32768;need(QueryFullProcessImageNameW(process.h,0,image,&size)&&std::wstring_view(image,size)==exe,"b_held_process_image");
  // Assignment was already atomic at creation; never introduce a suspended gap.
  need(ResumeThread(thread.h)!=DWORD(-1),"b_resume");connect_owned_private(pipe.h,15000);
  ULONG peer=0;need(GetNamedPipeClientProcessId(pipe.h,&peer)&&peer==pid&&WaitForSingleObject(process.h,0)==WAIT_TIMEOUT,"private_exact_child_peer");
  need(read_private(pipe.h,5000)=="OSB_HELLO1","private_hello");
  need(ImpersonateNamedPipeClient(pipe.h),"private_actual_peer_impersonate");
  struct Revert{bool active=true;~Revert(){if(active&&!RevertToSelf()){TerminateProcess(GetCurrentProcess(),95);std::terminate();}}} revert;
  Handle actual_peer;need(OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&actual_peer.h),"private_actual_peer_token");const auto peer_identity=identity(actual_peer.h);
  if(!RevertToSelf()){TerminateProcess(GetCurrentProcess(),95);std::terminate();}
  revert.active=false;
  need(peer_identity.sid==b.sid&&peer_identity.luid==b.luid&&peer_identity.session==b.session,"private_actual_sid_luid_session");
  // Actual named-pipe client token + held created process authorize bootstrap.
  send_private(pipe.h,body,5000);
  AuditSequence sequence;auto response=read_private(pipe.h,90000);
  if(response=="OSB_BEFORE_COPY1"){need(sequence.copy_begin(),"copy_audit_order");
   need(still_live&&still_live(ControlPoint::before_a_load),"a_api_negative_audit_begin");send_private(pipe.h,"OSB_ACK_COPY1",3000);response=read_private(pipe.h,30000);
  }
  if(response=="OSB_READY_RAW1"){need(sequence.raw_begin(),"raw_audit_order");
   need(still_live&&still_live(ControlPoint::before_raw),"a_live_control_prerequisite");send_private(pipe.h,"OSB_ACK_RAW1",3000);response=read_private(pipe.h,15000);
  }
  r.observations=Observations::decode(response);
  need(WaitForSingleObject(process.h,15000)==WAIT_OBJECT_0,"b_worker_exit");DWORD exit=0;need(GetExitCodeProcess(process.h,&exit),"b_worker_exit_code");r.worker_exit=exit;r.worker_exit_observed=true;
  need(exit==0&&r.observations.complete()&&sequence.complete_allowed(),"b_worker_observations");
 }
};
ControllerRun::ControllerRun():p_(std::make_unique<Impl>()){}
ControllerRun::~ControllerRun(){p_->clear();}
const Receipt& ControllerRun::receipt()const noexcept{return p_->r;}
bool ControllerRun::cleanup()noexcept{return p_->clear();}
bool ControllerRun::execute(const std::wstring& root,std::string_view body,void* held_a_process,bool approved,const std::function<bool(ControlPoint)>& still_live,const std::function<bool(const Receipt&)>& record)noexcept{
 if(!approved||p_->attempted||!record||!still_live)return false;
 p_->attempted=true;bool ok=false;
 try{p_->execute(root,body,held_a_process,still_live,record);ok=true;}catch(Failure f){p_->r.error=f.code;}catch(...){p_->r.error=ERROR_INVALID_DATA;}
 const bool cleaned=p_->clear();bool recorded=false;try{recorded=record(p_->r);}catch(...){}return cleaned&&recorded&&ok;
}
}
