#include "bootstrap_policy.hpp"
#include "admission_client_win.hpp"
#include "offline_app.hpp"
#include "online_app.hpp"
#include "cef_pin.hpp"

#include "include/base/cef_logging.h"
#include "include/cef_api_hash.h"
#include "include/cef_sandbox_win.h"
#include "include/wrapper/cef_library_loader.h"
#include "include/wrapper/cef_util_win.h"

#include <cstring>
#include <cstdio>
#include <vector>
#include <aclapi.h>
#include <string>
#include <string_view>
#include <type_traits>
#include <sddl.h>
#include <userenv.h>
#include <filesystem>
#pragma comment(lib,"userenv.lib")

namespace orangespace::cef_host {
static_assert(CEF_API_VERSION == pin::api_version);
static_assert(std::string_view(CEF_VERSION) == pin::version);
static_assert(std::string_view(CEF_COMMIT_HASH) == pin::commit);
static_assert(std::string_view(CEF_API_HASH_PLATFORM) == pin::api_hash);
static_assert(std::string_view(CEF_SANDBOX_COMPAT_HASH) == pin::sandbox_hash);

namespace {
std::wstring OfflineLogPath(const wchar_t* leaf) {
  wchar_t temp[32768]{};const DWORD n=GetTempPathW(32768,temp);
  return n&&n<32768?std::wstring(temp,n)+leaf:std::wstring{};
}
bool OfflineEarlyLog(const char* text) {
  const auto path=OfflineLogPath(L"orangespace-cef-early.log");
  if(path.empty()||!text)return false;
  HANDLE h=CreateFileW(path.c_str(),FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,
                       nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
  if(h==INVALID_HANDLE_VALUE)return false;
  DWORD written{};const DWORD size=static_cast<DWORD>(strlen(text));
  const bool ok=WriteFile(h,text,size,&written,nullptr)&&written==size;
  CloseHandle(h);return ok;
}
void ProfilePathFailure(LPCWSTR path,DWORD depth,DWORD attributes_error) noexcept {
 const DWORD saved=GetLastError();try {
  DWORD open_error=0,info_error=0,attributes=INVALID_FILE_ATTRIBUTES;
  HANDLE h=CreateFileW(path,0,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
  if(h==INVALID_HANDLE_VALUE)open_error=GetLastError();else {BY_HANDLE_FILE_INFORMATION info{};if(GetFileInformationByHandle(h,&info))attributes=info.dwFileAttributes;else info_error=GetLastError();CloseHandle(h);}
  char text[224]{};std::snprintf(text,sizeof(text),"profile-path depth=%lu attributes-error=%lu open-error=%lu info-error=%lu handle-attributes=%lu\n",depth,attributes_error,open_error,info_error,attributes);OfflineEarlyLog(text);
 }catch(...){}SetLastError(saved);
}
void WindowFailureContext() {
  const auto note=[](const char* label,DWORD value){char b[128]{};std::snprintf(b,sizeof(b),"window-context %s=%lu\n",label,static_cast<unsigned long>(value));OfflineEarlyLog(b);};
  note("pid",GetCurrentProcessId());DWORD session{};ProcessIdToSessionId(GetCurrentProcessId(),&session);note("session",session);
  HANDLE token{};
  if(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)){
    DWORD ac{},n{};GetTokenInformation(token,TokenIsAppContainer,&ac,sizeof(ac),&n);note("appcontainer",ac);
    BYTE sid[SECURITY_MAX_SID_SIZE]{};DWORD size=sizeof(sid);CreateWellKnownSid(WinRestrictedCodeSid,nullptr,sid,&size);
    for(auto kind:{TokenGroups,TokenRestrictedSids}){std::vector<BYTE> data(16384);DWORD used{};DWORD rc=0;if(GetTokenInformation(token,kind,data.data(),static_cast<DWORD>(data.size()),&used)){auto*g=reinterpret_cast<TOKEN_GROUPS*>(data.data());for(DWORD i=0;i<g->GroupCount;i++)if(EqualSid(sid,g->Groups[i].Sid))rc|=g->Groups[i].Attributes;}note(kind==TokenGroups?"restricted-code-group":"restricted-code-restricting-sid",rc);}
    CloseHandle(token);
  }
  const auto security=[](HANDLE h,std::vector<BYTE>& out){DWORD info=DACL_SECURITY_INFORMATION,n{};GetUserObjectSecurity(h,&info,nullptr,0,&n);if(!n||n>65536)return false;out.resize(n);return GetUserObjectSecurity(h,&info,out.data(),n,&n)!=FALSE;};
  HWINSTA original=GetProcessWindowStation();HDESK desktop=GetThreadDesktop(GetCurrentThreadId());
  std::vector<BYTE> ws,ds;
  if(!security(original,ws)){note("read-station-dacl-error",GetLastError());return;}
  if(!security(desktop,ds)){note("read-desktop-dacl-error",GetLastError());return;}
  PACL wa{},da{};BOOL present{},def{};
  GetSecurityDescriptorDacl(ws.data(),&present,&wa,&def);GetSecurityDescriptorDacl(ds.data(),&present,&da,&def);
  SECURITY_DESCRIPTOR wabs{},dabs{};InitializeSecurityDescriptor(&wabs,SECURITY_DESCRIPTOR_REVISION);SetSecurityDescriptorDacl(&wabs,TRUE,wa,FALSE);
  // Test the minimum missing right on this newly created private station only.
  HANDLE own_token{};std::vector<BYTE> app_sid(1024);DWORD app_used{};PACL station_acl{};
  if(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&own_token)){
    if(GetTokenInformation(own_token,TokenAppContainerSid,app_sid.data(),static_cast<DWORD>(app_sid.size()),&app_used)){
      auto sid=reinterpret_cast<TOKEN_APPCONTAINER_INFORMATION*>(app_sid.data())->TokenAppContainer;
      EXPLICIT_ACCESSW add{};add.grfAccessPermissions=WINSTA_CREATEDESKTOP;add.grfAccessMode=GRANT_ACCESS;add.Trustee.TrusteeForm=TRUSTEE_IS_SID;add.Trustee.ptstrName=reinterpret_cast<LPWSTR>(sid);
      if(SetEntriesInAclW(1,&add,wa,&station_acl)==ERROR_SUCCESS){SetSecurityDescriptorDacl(&wabs,TRUE,station_acl,FALSE);note("private-station-own-package-create-right",1);}
    }
    CloseHandle(own_token);
  }
  SECURITY_ATTRIBUTES sa{sizeof(sa),&wabs,FALSE};
  HWINSTA own=CreateWindowStationW(nullptr,0,GENERIC_READ|WINSTA_CREATEDESKTOP,&sa);
  if(!own&&GetLastError()==ERROR_ACCESS_DENIED)own=CreateWindowStationW(nullptr,0,WINSTA_READATTRIBUTES|WINSTA_CREATEDESKTOP,&sa);
  const DWORD station_error=own?ERROR_SUCCESS:GetLastError();if(station_acl)LocalFree(station_acl);
  if(!own){note("create-station-error",station_error);return;}
  BYTE rc[SECURITY_MAX_SID_SIZE]{};DWORD rcn=sizeof(rc);CreateWellKnownSid(WinRestrictedCodeSid,nullptr,rc,&rcn);
  EXPLICIT_ACCESSW deny{};deny.grfAccessPermissions=WRITE_DAC|WRITE_OWNER|DELETE|DESKTOP_CREATEMENU|DESKTOP_CREATEWINDOW|DESKTOP_HOOKCONTROL|DESKTOP_JOURNALPLAYBACK|DESKTOP_JOURNALRECORD|DESKTOP_SWITCHDESKTOP;deny.grfAccessMode=DENY_ACCESS;deny.Trustee.TrusteeForm=TRUSTEE_IS_SID;deny.Trustee.ptstrName=reinterpret_cast<LPWSTR>(rc);
  PACL reduced{};DWORD err=SetEntriesInAclW(1,&deny,da,&reduced);
  if(err){CloseWindowStation(own);note("desktop-dacl-error",err);return;}
  InitializeSecurityDescriptor(&dabs,SECURITY_DESCRIPTOR_REVISION);SetSecurityDescriptorDacl(&dabs,TRUE,reduced,FALSE);sa.lpSecurityDescriptor=&dabs;
  if(!SetProcessWindowStation(own)){err=GetLastError();LocalFree(reduced);CloseWindowStation(own);note("switch-station-error",err);return;}
  HDESK created=CreateDesktopW(L"OrangeSpace.ContextOnly",nullptr,nullptr,0,DESKTOP_CREATEWINDOW|DESKTOP_READOBJECTS|READ_CONTROL|WRITE_DAC|WRITE_OWNER,&sa);
  err=created?ERROR_SUCCESS:GetLastError();
  const BOOL restored=SetProcessWindowStation(original);
  if(created)CloseDesktop(created);LocalFree(reduced);CloseWindowStation(own);
  note("create-desktop-error",err);note("station-restored",restored!=FALSE);
  if(!restored)TerminateProcess(GetCurrentProcess(),25);
}
LONG CALLBACK OfflineNativeFailure(EXCEPTION_POINTERS* e) {
  const DWORD native_error=GetLastError();
  if(e&&e->ExceptionRecord&&e->ContextRecord&&
     e->ExceptionRecord->ExceptionCode==EXCEPTION_BREAKPOINT){
    char text[160]{};
    std::snprintf(text,sizeof(text),"native-breakpoint win32=%lu\n",
        static_cast<unsigned long>(native_error));
    OfflineEarlyLog(text);
  }
  return EXCEPTION_CONTINUE_SEARCH;
}
BootstrapVersion Snapshot(const cef_version_info_t& info) {
  return {{{info.cef_version_major, info.cef_version_minor,
            info.cef_version_patch, info.cef_commit_number,
            info.chrome_version_major, info.chrome_version_minor,
            info.chrome_version_build, info.chrome_version_patch}},
          std::string_view(info.sandbox_compat_hash, 16)};
}
}  // namespace
}  // namespace orangespace::cef_host

// Exactly the CEF header's C-linkage, cdecl ABI, NOT WINAPI/wWinMain.
// The sandbox is owned by the matching official bootstrap; never substitute
// a locally allocated object, null pointer, or a sandbox-disabling setting.
CEF_BOOTSTRAP_EXPORT int RunWinMain(HINSTANCE instance, LPWSTR, int,
                                   void* sandbox_info,
                                   cef_version_info_t* version_info) {
  using namespace orangespace::cef_host;
  if (!sandbox_info) return static_cast<int>(StartupResult::invalid_sandbox);
  if (!version_info || version_info->size != sizeof(cef_version_info_t) ||
      version_info->sandbox_compat_hash[16] != '\0')
    return static_cast<int>(StartupResult::invalid_bootstrap);

  cef_version_info_t expected_info = {};
  CEF_POPULATE_VERSION_INFO(&expected_info);
  const auto expected = Snapshot(expected_info);
  const auto actual = Snapshot(*version_info);
  auto result = CheckBootstrap(sandbox_info, &actual, expected);
  if (result != StartupResult::compatible) return static_cast<int>(result);

  // No installer/CDN resolution, machine-wide runtime, or fallback discovery.
  // Prototype stages runtime only from the exact verified distribution.
  if (version_info->installer_error_code || version_info->libcef_path)
    return static_cast<int>(StartupResult::invalid_bootstrap);

  // Root AND every subprocess must receive a fresh COMMITTED OS-bound admission
  // before loading libcef.dll. The Service retains the complete hash-verified
  // protected runtime and installed Offline policy for this exact process/Job.
  auto admission = orangespace::prototype::Admission::Acquire();
  if (!admission) {
    const int code=orangespace::prototype::AdmissionFailureExitCode(orangespace::prototype::Admission::LastFailureStage());
    char text[96]{};std::snprintf(text,sizeof(text),"admission-denied pid=%lu exit=%d\n",GetCurrentProcessId(),code);OfflineEarlyLog(text);
    return code;
  }
  OfflineEarlyLog("native-authorized-runtime-start\n");
  WindowFailureContext();
  struct FailureLog {
    PVOID handle=AddVectoredExceptionHandler(1,OfflineNativeFailure);
    ~FailureLog(){if(handle)RemoveVectoredExceptionHandler(handle);}
  } failure_log;
  CefScopedLibraryLoader loader;
  {
    cef::logging::ScopedEarlySupport::Config log_config;
    log_config.formatted_log_handler=OfflineEarlyLog;
    cef::logging::ScopedEarlySupport early_logging(log_config);
    const auto executable = cef_util::GetExePath();
    const auto separator = executable.find_last_of(L"/\\");
    if (separator == std::wstring::npos)
      return static_cast<int>(StartupResult::invalid_runtime);
    const std::wstring library = executable.substr(0, separator + 1) + L"libcef.dll";
    // User-authorized exception ONLY for this fixed offline diagnostic target:
    // an unsigned official DLL is accepted after the real retained admission.
    // Upstream still rejects invalid signatures/version/load failures. No PATH
    // search, downloader, runtime-config switch or fallback is introduced.
    if (!loader.LoadInMainAssert(library.c_str(), nullptr,
                                 static_cast<bool>(admission), &expected_info))
      return static_cast<int>(StartupResult::invalid_runtime);
  }

  result = CheckRuntime(cef_api_hash(CEF_API_VERSION, 0),
                        cef_api_hash(CEF_API_VERSION, 2),
                        cef_api_hash(CEF_API_VERSION, 3), cef_version_full(),
                        {pin::api_hash, pin::commit, pin::sandbox_hash, pin::version});
  if (result != StartupResult::compatible) return static_cast<int>(result);

  auto command_line = CefCommandLine::CreateCommandLine();
  command_line->InitFromString(GetCommandLineW());
  for (const char* forbidden : {"no-sandbox", "disable-gpu-sandbox",
                               "disable-setuid-sandbox", "single-process",
                               "in-process-gpu"}) {
    if (command_line->HasSwitch(forbidden))
      return static_cast<int>(StartupResult::launch_denied);
  }
  CefMainArgs args(instance);
  CefRefPtr<CefApp> app = new orangespace::prototype::OnlineApp(admission->private_channel());
  const int child_result = CefExecuteProcess(args, app, sandbox_info);
  if (child_result >= 0) return child_result;
  CefSettings settings;
  settings.no_sandbox = false;
  settings.command_line_args_disabled = true;
  settings.persist_session_cookies = true;
  // Resolve only the OS-selected cap0 package's private persistent folder.
  HANDLE token{};if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))return 240;
  alignas(TOKEN_APPCONTAINER_INFORMATION) BYTE package[1024]{};DWORD size{};
  const BOOL queried=GetTokenInformation(token,TokenAppContainerSid,package,sizeof(package),&size);CloseHandle(token);if(!queried)return 241;
  LPWSTR sid{},folder{};auto actual_sid=reinterpret_cast<TOKEN_APPCONTAINER_INFORMATION*>(package)->TokenAppContainer;
  if(!actual_sid||!ConvertSidToStringSidW(actual_sid,&sid))return 242;
  const HRESULT located=GetAppContainerFolderPath(sid,&folder);LocalFree(sid);if(located!=S_OK)return 243;
  const std::filesystem::path package_root(folder);CoTaskMemFree(folder);
  std::filesystem::path cache=package_root/L"BrowserCache";
  DWORD profile_depth=0;
  // Service validates the full non-root ancestry as the WTS user before launch.
  // In cap0, query only this actual token's OS-selected package and fixed cache.
  for(const auto& path:{package_root}){
    const auto attributes=GetFileAttributesW(path.c_str());if(package_root.empty()||package_root==package_root.root_path()||cache.parent_path()!=package_root||attributes==INVALID_FILE_ATTRIBUTES||(attributes&FILE_ATTRIBUTE_REPARSE_POINT)||!(attributes&FILE_ATTRIBUTE_DIRECTORY)){ProfilePathFailure(path.c_str(),profile_depth,attributes==INVALID_FILE_ATTRIBUTES?GetLastError():0);return 244;}
  }
  if(!CreateDirectoryW(cache.c_str(),nullptr)&&GetLastError()!=ERROR_ALREADY_EXISTS)return 245;
  for(const auto& path:{cache,package_root}){
    const auto attributes=GetFileAttributesW(path.c_str());if(attributes==INVALID_FILE_ATTRIBUTES||(attributes&FILE_ATTRIBUTE_REPARSE_POINT)||!(attributes&FILE_ATTRIBUTE_DIRECTORY))return 246;
  }
  CefString(&settings.root_cache_path)=cache.wstring();CefString(&settings.cache_path)=cache.wstring();
  CefString(&settings.log_file)=OfflineLogPath(L"orangespace-cef.log");
  settings.log_severity=LOGSEVERITY_DISABLE;
  // Persistent cache remains in this exact OS package, not another sandbox.
  if (!CefInitialize(args, settings, app, sandbox_info)) return 247;
  CefRunMessageLoop();
  CefShutdown();
  return 0;
}

using BootstrapEntry = int (*)(HINSTANCE, LPWSTR, int, void*, cef_version_info_t*);
static_assert(std::is_same_v<decltype(&RunWinMain), BootstrapEntry>);
