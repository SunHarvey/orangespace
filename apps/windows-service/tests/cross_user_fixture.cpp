// Standalone native fixture. No production executable or secret-bearing args.
#ifndef UNICODE
#define UNICODE
#endif
#define _UNICODE
#include <windows.h>
#include <userenv.h>
#include <lm.h>
#include <sddl.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <cstring>

struct Failure { const char* stage; DWORD error; };
void require(bool b,const char* stage){if(!b){const DWORD error=GetLastError();throw Failure{stage,error==ERROR_SUCCESS?ERROR_INVALID_DATA:error};}}
struct Handle { HANDLE h=nullptr; ~Handle(){if(h&&h!=INVALID_HANDLE_VALUE)CloseHandle(h);} };
struct Identity {std::wstring sid; LUID logon{}; DWORD session=0;};
Identity identity(HANDLE token){
 DWORD n=0; GetTokenInformation(token,TokenUser,nullptr,0,&n); std::vector<BYTE>b(n);
 require(GetTokenInformation(token,TokenUser,b.data(),n,&n),"token_user");
 LPWSTR p=nullptr;require(ConvertSidToStringSidW(((TOKEN_USER*)b.data())->User.Sid,&p),"sid_string");
 Identity id;id.sid=p;LocalFree(p);TOKEN_STATISTICS s{};
 require(GetTokenInformation(token,TokenStatistics,&s,sizeof(s),&n),"token_statistics");id.logon=s.AuthenticationId;
 require(GetTokenInformation(token,TokenSessionId,&id.session,sizeof(id.session),&n),"token_session");return id;
}
std::string ascii(const std::wstring&s){return std::string(s.begin(),s.end());}
std::string quote(const std::wstring&s){std::string r="\"";for(auto c:s){if(c=='\\'||c=='\"')r+='\\';r+=char(c);}return r+'\"';}
void writefile(const std::wstring&p,const void*data,DWORD size,DWORD disposition=CREATE_NEW){Handle h;h.h=CreateFileW(p.c_str(),GENERIC_WRITE,0,nullptr,disposition,FILE_ATTRIBUTE_NORMAL,nullptr);require(h.h!=INVALID_HANDLE_VALUE,"create_file");DWORD n=0;require(WriteFile(h.h,data,size,&n,nullptr)&&n==size,"write_file");}
std::vector<BYTE> readfile(const std::wstring&p){Handle h;h.h=CreateFileW(p.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);require(h.h!=INVALID_HANDLE_VALUE,"read_open");DWORD n=GetFileSize(h.h,nullptr);require(n<65536,"read_size");std::vector<BYTE>b(n);DWORD got=0;require(ReadFile(h.h,b.data(),n,&got,nullptr)&&got==n,"read_file");return b;}
void dacl(const std::wstring&p,const std::wstring&s){PSECURITY_DESCRIPTOR sd=nullptr;require(ConvertStringSecurityDescriptorToSecurityDescriptorW(s.c_str(),SDDL_REVISION_1,&sd,nullptr),"sddl");BOOL ok=SetFileSecurityW(p.c_str(),DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,sd);DWORD e=GetLastError();LocalFree(sd);SetLastError(e);require(ok,"set_dacl");}
const BYTE entropy_bytes[]={0x4f,0x53,0x50,0x32,0x2d,0x63,0x72,0x6f,0x73,0x73,0x2d,0x75,0x73,0x65,0x72};
DATA_BLOB entropy(){return {sizeof(entropy_bytes),const_cast<BYTE*>(entropy_bytes)};}
std::vector<BYTE> protect(){BYTE plain[32];require(BCryptGenRandom(nullptr,plain,sizeof(plain),BCRYPT_USE_SYSTEM_PREFERRED_RNG)==0,"random_plain");DATA_BLOB in{sizeof(plain),plain},out{},ent=entropy();require(CryptProtectData(&in,L"cross_user_fixture",&ent,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&out),"dpapi_protect");std::vector<BYTE>v(out.pbData,out.pbData+out.cbData);LocalFree(out.pbData);DATA_BLOB check{};DATA_BLOB enc{DWORD(v.size()),v.data()};require(CryptUnprotectData(&enc,nullptr,&ent,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&check),"dpapi_roundtrip");bool same=check.cbData==sizeof(plain)&&memcmp(plain,check.pbData,sizeof(plain))==0;SecureZeroMemory(plain,sizeof(plain));SecureZeroMemory(check.pbData,check.cbData);LocalFree(check.pbData);require(same,"dpapi_plaintext_match");return v;}
struct Privileges {Handle token; TOKEN_PRIVILEGES old[2]{};bool changed[2]{}; Privileges(){require(OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&token.h),"privilege_token");const wchar_t* names[]={SE_BACKUP_NAME,SE_RESTORE_NAME};for(int i=0;i<2;i++){TOKEN_PRIVILEGES p{};p.PrivilegeCount=1;require(LookupPrivilegeValueW(nullptr,names[i],&p.Privileges[0].Luid),"lookup_privilege");p.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;DWORD n=sizeof(old[i]);SetLastError(0);require(AdjustTokenPrivileges(token.h,FALSE,&p,n,&old[i],&n)&&GetLastError()!=ERROR_NOT_ALL_ASSIGNED,"enable_privilege");changed[i]=true;}}~Privileges(){for(int i=1;i>=0;i--)if(changed[i])AdjustTokenPrivileges(token.h,FALSE,&old[i],0,nullptr,nullptr);}};
int child(const std::wstring&root){
 std::string result;DWORD error=0;const char* stage="child_complete";bool own=false,denied=false,acl=false,loaded=false,notadmin=false;
 try{Handle token;require(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token.h),"child_token");auto id=identity(token.h);
 SID_IDENTIFIER_AUTHORITY nt=SECURITY_NT_AUTHORITY;PSID admin=nullptr;require(AllocateAndInitializeSid(&nt,2,SECURITY_BUILTIN_DOMAIN_RID,DOMAIN_ALIAS_RID_ADMINS,0,0,0,0,0,0,&admin),"admin_sid");BOOL member=TRUE;BOOL checked=CheckTokenMembership(nullptr,admin,&member);FreeSid(admin);require(checked,"admin_check");notadmin=!member;require(notadmin,"child_must_be_ordinary");
 DWORD n=32768;std::vector<wchar_t>path(n);require(GetUserProfileDirectoryW(token.h,path.data(),&n),"child_profile_path");wchar_t env[32768];DWORD en=GetEnvironmentVariableW(L"USERPROFILE",env,32768);HKEY hive=nullptr;LSTATUS rc=RegOpenKeyExW(HKEY_USERS,id.sid.c_str(),0,KEY_READ,&hive);if(rc==ERROR_SUCCESS)RegCloseKey(hive);loaded=rc==ERROR_SUCCESS&&en>0&&_wcsicmp(path.data(),env)==0;require(loaded,"child_profile_loaded");
 auto ownblob=protect();own=!ownblob.empty();auto copied=readfile(root+L"\\cipher.bin");DATA_BLOB in{DWORD(copied.size()),copied.data()},out{},ent=entropy();BOOL decrypted=CryptUnprotectData(&in,nullptr,&ent,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&out);DWORD dp=GetLastError();if(decrypted){SecureZeroMemory(out.pbData,out.cbData);LocalFree(out.pbData);}denied=!decrypted;require(denied,"cross_user_dpapi_should_fail");
 HANDLE f=CreateFileW((root+L"\\private_a\\cipher.bin").c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);DWORD ae=GetLastError();if(f!=INVALID_HANDLE_VALUE)CloseHandle(f);acl=f==INVALID_HANDLE_VALUE&&ae==ERROR_ACCESS_DENIED;require(acl,"cross_user_acl_should_deny");
 std::ostringstream s;s<<"{\"b_roundtrip\":true,\"b_cannot_decrypt_a\":true,\"b_acl_denied\":true,\"profile_loaded\":true,\"b_not_admin\":true,\"dpapi_error\":"<<dp<<",\"acl_error\":"<<ae<<"}";result=s.str();
 }catch(Failure f){stage=f.stage;error=f.error;}
 if(result.empty()){std::ostringstream s;s<<"{\"stage\":\""<<stage<<"\",\"error\":"<<error<<"}";result=s.str();}
 try{writefile(root+L"\\child.json",result.data(),DWORD(result.size()),TRUNCATE_EXISTING);}catch(...){return 2;}return error?1:(own&&denied&&acl&&loaded&&notadmin?0:1);
}
int wmain(int argc,wchar_t**argv){
 if(argc==3&&std::wstring(argv[1])==L"--child")return child(argv[2]);
 if(argc!=2)return 2;
 std::wstring root=argv[1];if(root.rfind(L"C:\\Program Files\\OrangeSpace-cross-user-",0)!=0)return 2;
 bool account=false,profile=false,account_removed=false,profile_removed=false,exited=false,a_round=false,sid_diff=false,logon_diff=false,same_session=false;
 std::wstring username,sid,profilepath;Handle tokenA,tokenB,process,thread;PROFILEINFOW pi{};Identity a,b;const char*stage="complete";DWORD error=0,cleanup_error=0,pid=0;std::string child_json="{}";wchar_t password[65]{};
 try{
 require(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&tokenA.h),"parent_token");a=identity(tokenA.h);require(a.session!=0,"parent_interactive_session");
 BYTE random[16];require(BCryptGenRandom(nullptr,random,sizeof(random),BCRYPT_USE_SYSTEM_PREFERRED_RNG)==0,"account_random");const wchar_t hex[]=L"0123456789abcdef";username=L"OSCu_";for(int i=0;i<6;i++){username+=hex[random[i]>>4];username+=hex[random[i]&15];}
 require(BCryptGenRandom(nullptr,(PUCHAR)password,64,BCRYPT_USE_SYSTEM_PREFERRED_RNG)==0,"password_random");for(int i=0;i<32;i++)password[i]=L'a'+(unsigned(password[i])%26);password[32]=L'A';password[33]=L'9';password[34]=L'!';password[35]=0;
 USER_INFO_1 ui{};ui.usri1_name=username.data();ui.usri1_password=password;ui.usri1_priv=USER_PRIV_USER;ui.usri1_flags=UF_SCRIPT|UF_DONT_EXPIRE_PASSWD;DWORD parm=0;NET_API_STATUS ns=NetUserAdd(nullptr,1,(LPBYTE)&ui,&parm);SetLastError(ns);require(ns==NERR_Success,"net_user_add");account=true;
 LPBYTE account_info=nullptr;ns=NetUserGetInfo(nullptr,username.c_str(),4,&account_info);SetLastError(ns);require(ns==NERR_Success,"new_account_sid");LPWSTR account_sid=nullptr;BOOL sid_ok=ConvertSidToStringSidW(((USER_INFO_4*)account_info)->usri4_user_sid,&account_sid);DWORD sid_error=GetLastError();if(sid_ok){sid=account_sid;LocalFree(account_sid);}NetApiBufferFree(account_info);SetLastError(sid_error);require(sid_ok,"new_account_sid_string");
 require(LogonUserW(username.c_str(),L".",password,LOGON32_LOGON_INTERACTIVE,LOGON32_PROVIDER_DEFAULT,&tokenB.h),"logon_user");sid=identity(tokenB.h).sid;
 {Privileges privileges;pi.dwSize=sizeof(pi);pi.dwFlags=PI_NOUI;pi.lpUserName=username.data();require(LoadUserProfileW(tokenB.h,&pi),"load_user_profile");profile=true;}
 DWORD size=32768;std::vector<wchar_t> pp(size);require(GetUserProfileDirectoryW(tokenB.h,pp.data(),&size),"profile_directory");profilepath=pp.data();require(profilepath.rfind(L"C:\\Users\\"+username,0)==0,"profile_path_owned");
 auto cipher=protect();a_round=true;writefile(root+L"\\cipher.bin",cipher.data(),DWORD(cipher.size()));
 require(CreateDirectoryW((root+L"\\private_a").c_str(),nullptr),"private_directory");dacl(root+L"\\private_a",L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;"+a.sid+L")");writefile(root+L"\\private_a\\cipher.bin",cipher.data(),DWORD(cipher.size()));
 const char empty[]="{}";writefile(root+L"\\child.json",empty,2);dacl(root+L"\\child.json",L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFW;;;"+sid+L")");
 wchar_t exe[32768];require(GetModuleFileNameW(nullptr,exe,32768)>0,"module_path");require(std::wstring(exe)==root+L"\\cross_user_fixture.exe","exact_self_path");std::wstring cmd=L"\""+std::wstring(exe)+L"\" --child \""+root+L"\"";STARTUPINFOW startup{};startup.cb=sizeof(startup);PROCESS_INFORMATION cp{};
 require(CreateProcessWithLogonW(username.c_str(),L".",password,LOGON_WITH_PROFILE,exe,cmd.data(),CREATE_SUSPENDED|CREATE_NO_WINDOW,nullptr,root.c_str(),&startup,&cp),"create_process_with_logon");SecureZeroMemory(password,sizeof(password));process.h=cp.hProcess;thread.h=cp.hThread;pid=cp.dwProcessId;
 Handle childtoken;require(OpenProcessToken(process.h,TOKEN_QUERY,&childtoken.h),"child_process_token");b=identity(childtoken.h);sid_diff=a.sid!=b.sid;require(b.sid==sid&&sid_diff,"actual_child_sid");logon_diff=a.logon.LowPart!=b.logon.LowPart||a.logon.HighPart!=b.logon.HighPart;require(logon_diff,"actual_child_logon");same_session=a.session==b.session;require(same_session,"actual_child_session");require(ResumeThread(thread.h)!=DWORD(-1),"resume_child");
 require(WaitForSingleObject(process.h,60000)==WAIT_OBJECT_0,"child_timeout");exited=true;DWORD code=0;require(GetExitCodeProcess(process.h,&code),"child_exit_code");auto bytes=readfile(root+L"\\child.json");child_json=std::string(bytes.begin(),bytes.end());SetLastError(code);require(code==0,"child_acceptance");
 }catch(Failure f){stage=f.stage;error=f.error;}catch(...){stage="unexpected_exception";error=ERROR_UNHANDLED_EXCEPTION;}
 SecureZeroMemory(password,sizeof(password));
 if(process.h&&!exited){if(WaitForSingleObject(process.h,0)!=WAIT_OBJECT_0)TerminateProcess(process.h,99);exited=WaitForSingleObject(process.h,10000)==WAIT_OBJECT_0;if(!exited)cleanup_error=GetLastError();}
 if(thread.h){CloseHandle(thread.h);thread.h=nullptr;}if(process.h){CloseHandle(process.h);process.h=nullptr;}
 if(profile){try{Privileges privileges;if(!UnloadUserProfile(tokenB.h,pi.hProfile))cleanup_error=GetLastError();else {profile=false; // Delete only the recorded, freshly created SID/path.
 if(profilepath.empty()){DWORD n=32768;std::vector<wchar_t>p(n);if(GetUserProfileDirectoryW(tokenB.h,p.data(),&n))profilepath=p.data();}
 if(!profilepath.empty()&&profilepath.rfind(L"C:\\Users\\"+username,0)==0){BOOL deleted=DeleteProfileW(sid.c_str(),profilepath.c_str(),nullptr);if(!deleted)cleanup_error=GetLastError();std::wstring key=L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\"+sid;HKEY k=nullptr;LSTATUS rc=RegOpenKeyExW(HKEY_LOCAL_MACHINE,key.c_str(),0,KEY_READ,&k);if(k)RegCloseKey(k);HKEY hive=nullptr;LSTATUS hr=RegOpenKeyExW(HKEY_USERS,sid.c_str(),0,KEY_READ,&hive);if(hive)RegCloseKey(hive);profile_removed=deleted&&rc==ERROR_FILE_NOT_FOUND&&hr==ERROR_FILE_NOT_FOUND&&GetFileAttributesW(profilepath.c_str())==INVALID_FILE_ATTRIBUTES;}else cleanup_error=ERROR_INVALID_NAME;
 }}catch(Failure f){cleanup_error=f.error;}}
 else profile_removed=!account;
 if(tokenB.h){CloseHandle(tokenB.h);tokenB.h=nullptr;}
 if(account&&username.rfind(L"OSCu_",0)==0&&!sid.empty()){LPBYTE info=nullptr;NET_API_STATUS ns=NetUserGetInfo(nullptr,username.c_str(),4,&info);bool match=false;if(ns==NERR_Success){LPWSTR current=nullptr;if(ConvertSidToStringSidW(((USER_INFO_4*)info)->usri4_user_sid,&current)){match=sid==current;LocalFree(current);}NetApiBufferFree(info);}if(match){ns=NetUserDel(nullptr,username.c_str());if(ns!=NERR_Success)cleanup_error=ns;info=nullptr;account_removed=NetUserGetInfo(nullptr,username.c_str(),0,&info)==NERR_UserNotFound;if(info)NetApiBufferFree(info);}else cleanup_error=ERROR_INVALID_SID;}
 else account_removed=!account;
 bool ok=error==0&&cleanup_error==0&&account_removed&&profile_removed&&exited;
 std::ostringstream out;out<<"{\"ok\":"<<(ok?"true":"false")<<",\"stage\":\""<<stage<<"\",\"error\":"<<error<<",\"cleanup_error\":"<<cleanup_error<<",\"account\":"<<quote(username)<<",\"profile_path\":"<<quote(profilepath)<<",\"a_sid\":"<<quote(a.sid)<<",\"b_sid\":"<<quote(b.sid)<<",\"a_logon_low\":"<<a.logon.LowPart<<",\"a_logon_high\":"<<a.logon.HighPart<<",\"b_logon_low\":"<<b.logon.LowPart<<",\"b_logon_high\":"<<b.logon.HighPart<<",\"a_session\":"<<a.session<<",\"b_session\":"<<b.session<<",\"child_pid\":"<<pid;
 auto flag=[&](const char*k,bool v){out<<",\""<<k<<"\":"<<(v?"true":"false");};flag("sid_different",sid_diff);flag("logon_different",logon_diff);flag("same_session",same_session);flag("a_roundtrip",a_round);flag("profile_removed",profile_removed);flag("account_removed",account_removed);flag("child_exited",exited);
 // Copy only known boolean flags out of the child's nonsecret JSON.
 for(const char*k:{"b_not_admin","profile_loaded","b_roundtrip","b_cannot_decrypt_a","b_acl_denied"})flag(k,child_json.find(std::string("\"")+k+"\":true")!=std::string::npos);
 out<<",\"child_result\":"<<child_json<<"}";auto json=out.str();try{writefile(root+L"\\result.json",json.data(),DWORD(json.size()));}catch(...){return 3;}return ok?0:1;
}
