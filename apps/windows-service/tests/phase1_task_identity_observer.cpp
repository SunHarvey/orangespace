// NONSECRET fixed-role diagnostic candidate; NOT a guardian or an admission gate.
// Existing-admin trusted-foreground fixture only; NOT hostile same-SID protection.
// External bootstrap authentication is a prerequisite, NOT established by this EXE.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <taskschd.h>
#include <shlobj.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <cstdio>
#include <stdexcept>
#include <utility>
#include "phase1_task_identity_config.hpp"
#include "phase1_task_identity_policy.hpp"
namespace cfg = phase1_task_identity_config;
namespace {
[[noreturn]] void fail(const char* m) { throw std::runtime_error(m); }
void yes(bool b, const char* m) { if (!b) fail(m); }
void ok(HRESULT h, const char* m) { yes(h == S_OK, m); }
struct Handle {
  HANDLE h = INVALID_HANDLE_VALUE;
  Handle() = default;
  explicit Handle(HANDLE v): h(v) {}
  ~Handle() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  Handle(Handle&& x) noexcept: h(std::exchange(x.h, INVALID_HANDLE_VALUE)) {}
};
template<class T> struct Com {
  T* p{};
  ~Com() { if (p) p->Release(); }
  T** out() { yes(!p, "COM output already owned"); return &p; }
  T* operator->() const { yes(p != nullptr, "missing COM object"); return p; }
};
struct Bstr {
  BSTR p{};
  Bstr() = default;
  explicit Bstr(const wchar_t* v): p(SysAllocString(v)) { yes(p != nullptr, "BSTR allocation"); }
  ~Bstr() { SysFreeString(p); }
  Bstr(const Bstr&) = delete;
  BSTR* out() { yes(!p, "BSTR output already owned"); return &p; }
  std::wstring str() const { return p ? std::wstring(p, SysStringLen(p)) : std::wstring(); }
};
struct Variant {
  VARIANT v{};
  explicit Variant(const wchar_t* s) { v.vt = VT_BSTR; v.bstrVal = SysAllocString(s); yes(v.bstrVal != nullptr, "VARIANT allocation"); }
  ~Variant() { VariantClear(&v); }
};
struct Local {
  void* p{};
  ~Local() { LocalFree(p); }
};
std::string utf8(const std::wstring& s) {
  yes(s.size() < 2048, "string bound");
  int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
  yes(n > 0, "UTF8 conversion");
  std::string r(static_cast<size_t>(n), '\0');
  yes(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), r.data(), n, nullptr, nullptr) == n, "UTF8 conversion");
  return r;
}
std::wstring sid_text(PSID sid) {
  yes(IsValidSid(sid) != FALSE, "invalid OS SID");
  LPWSTR s{}; yes(ConvertSidToStringSidW(sid, &s) != FALSE, "SID stringify");
  Local a; a.p = s; return s;
}
bool privileged_sid(PSID sid, bool ancestor) {
  const auto s = sid_text(sid);
  return s == L"S-1-5-18" || s == L"S-1-5-32-544" ||
    (ancestor && s == L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
}
void check_sd(PSECURITY_DESCRIPTOR sd, bool ancestor, bool task = false) {
  yes(sd && IsValidSecurityDescriptor(sd), "unknown security descriptor");
  PSID owner{}; BOOL def{};
  yes(GetSecurityDescriptorOwner(sd, &owner, &def) && owner && privileged_sid(owner, ancestor), "unprotected owner");
  SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision{};
  yes(GetSecurityDescriptorControl(sd, &control, &revision) != FALSE, "SD control");
  yes(ancestor || (control & SE_DACL_PROTECTED), "leaf DACL not protected");
  PACL acl{}; BOOL present{};
  yes(GetSecurityDescriptorDacl(sd, &present, &acl, &def) && present && acl && IsValidAcl(acl), "missing DACL");
  const DWORD mutation = DELETE | WRITE_DAC | WRITE_OWNER | FILE_WRITE_DATA |
    FILE_APPEND_DATA | FILE_WRITE_EA | FILE_DELETE_CHILD | FILE_WRITE_ATTRIBUTES;
  GENERIC_MAPPING map{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
  for (DWORD i = 0; i < acl->AceCount; ++i) {
    void* raw{}; yes(GetAce(acl, i, &raw) != FALSE, "ACE read");
    auto* head = static_cast<ACE_HEADER*>(raw);
    yes(head->AceType == ACCESS_ALLOWED_ACE_TYPE || head->AceType == ACCESS_DENIED_ACE_TYPE, "unsupported ACE type");
    // Inherit-only entries do not authorize access to this held ancestor itself.
    if ((head->AceFlags & INHERIT_ONLY_ACE) || head->AceType == ACCESS_DENIED_ACE_TYPE) continue;
    auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
    DWORD mask = ace->Mask; MapGenericMask(&mask, &map);
    yes(phase1_task_identity::conservative_ace(privileged_sid(&ace->SidStart, ancestor), false, false, true,
          mask, task ? 0xffffffffUL : mutation), "nonprivileged mutation/replacement authority");
  }
}
void check_acl(HANDLE h, bool ancestor) {
  PSECURITY_DESCRIPTOR sd{};
  DWORD e = GetSecurityInfo(h, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                           nullptr, nullptr, nullptr, nullptr, &sd);
  Local own; own.p = sd; yes(e == ERROR_SUCCESS, "held ACL query"); check_sd(sd, ancestor);
}
unsigned long long identity(HANDLE h, DWORD* volume = nullptr) {
  BY_HANDLE_FILE_INFORMATION i{};
  yes(GetFileInformationByHandle(h, &i) != FALSE, "held file identity");
  yes(!(i.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT), "reparse point");
  if (volume) *volume = i.dwVolumeSerialNumber;
  return (static_cast<unsigned long long>(i.nFileIndexHigh) << 32) | i.nFileIndexLow;
}
std::wstring final_path(HANDLE h) {
  wchar_t b[2048]{};
  DWORD n = GetFinalPathNameByHandleW(h, b, 2048, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  yes(n && n < 2048, "held canonical path");
  std::wstring s(b, n); yes(s.rfind(L"\\\\?\\", 0) == 0, "nonlocal final path"); return s.substr(4);
}
Handle open_fixed(const std::wstring& path, bool directory, bool ancestor = false) {
  Handle h(CreateFileW(path.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES | GENERIC_READ,
    FILE_SHARE_READ, nullptr, OPEN_EXISTING,
    FILE_FLAG_OPEN_REPARSE_POINT | (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0), nullptr));
  yes(h.h != INVALID_HANDLE_VALUE && GetFileType(h.h) == FILE_TYPE_DISK, "cannot hold fixed disk object without write/delete sharing");
  FILE_ATTRIBUTE_TAG_INFO a{};
  yes(GetFileInformationByHandleEx(h.h, FileAttributeTagInfo, &a, sizeof(a)) != FALSE, "file attributes");
  yes(!(a.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
      bool(a.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == directory, "wrong object type/reparse");
  yes(_wcsicmp(final_path(h.h).c_str(), path.c_str()) == 0, "canonical path mismatch");
  check_acl(h.h, ancestor); return h;
}
std::string hash_file(HANDLE file, unsigned long long bound) {
  LARGE_INTEGER size{}; yes(GetFileSizeEx(file, &size) && size.QuadPart > 0 && static_cast<unsigned long long>(size.QuadPart) <= bound, "file size bound");
  LARGE_INTEGER zero{}; yes(SetFilePointerEx(file, zero, nullptr, FILE_BEGIN) != FALSE, "file rewind");
  BCRYPT_ALG_HANDLE alg{}; BCRYPT_HASH_HANDLE hash{};
  yes(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0, "SHA256 provider");
  struct AlgClose { BCRYPT_ALG_HANDLE h; ~AlgClose() { BCryptCloseAlgorithmProvider(h, 0); } } ac{alg};
  yes(BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) == 0, "SHA256 hash");
  struct HashClose { BCRYPT_HASH_HANDLE h; ~HashClose() { BCryptDestroyHash(h); } } hc{hash};
  unsigned char b[16384]{}; unsigned long long total{};
  for (;;) { DWORD n{}; yes(ReadFile(file, b, sizeof(b), &n, nullptr) != FALSE, "held file read"); if (!n) break;
    total += n; yes(total <= bound && BCryptHashData(hash, b, n, 0) == 0, "SHA256 data/bound"); }
  yes(total == static_cast<unsigned long long>(size.QuadPart), "file size drift");
  unsigned char digest[32]{}; yes(BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0, "SHA256 final");
  const char* hex = "0123456789abcdef"; std::string out; out.reserve(64);
  for (auto v: digest) { out += hex[v >> 4]; out += hex[v & 15]; } return out;
}
std::vector<unsigned char> token_info(HANDLE token, TOKEN_INFORMATION_CLASS c) {
  DWORD n{}; GetTokenInformation(token, c, nullptr, 0, &n);
  yes(GetLastError() == ERROR_INSUFFICIENT_BUFFER && n && n <= 65536, "token information bound");
  std::vector<unsigned char> b(n); yes(GetTokenInformation(token, c, b.data(), n, &n) != FALSE, "OS token query"); return b;
}
struct Token {
  std::wstring sid;
  DWORD session{}, integrity{}, elevation_type{}, elevated{}, restricted{}, has_restrictions{}, appcontainer{};
  unsigned long long luid{};
  bool admin{};
  std::string privileges;
};
Token describe(HANDLE process) {
  HANDLE raw{}; yes(OpenProcessToken(process, TOKEN_QUERY, &raw) != FALSE, "actual process token"); Handle t(raw);
  Token out;
  auto u = token_info(t.h, TokenUser); out.sid = sid_text(reinterpret_cast<TOKEN_USER*>(u.data())->User.Sid);
  auto s = token_info(t.h, TokenSessionId); out.session = *reinterpret_cast<DWORD*>(s.data());
  auto st = token_info(t.h, TokenStatistics); auto stats = *reinterpret_cast<TOKEN_STATISTICS*>(st.data());
  out.luid = (static_cast<unsigned long long>(static_cast<DWORD>(stats.AuthenticationId.HighPart)) << 32) | stats.AuthenticationId.LowPart;
  auto il = token_info(t.h, TokenIntegrityLevel); auto sid = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(il.data())->Label.Sid;
  yes(IsValidSid(sid) && *GetSidSubAuthorityCount(sid), "integrity SID");
  out.integrity = *GetSidSubAuthority(sid, *GetSidSubAuthorityCount(sid) - 1);
  auto et = token_info(t.h, TokenElevationType); out.elevation_type = *reinterpret_cast<DWORD*>(et.data());
  auto el = token_info(t.h, TokenElevation); out.elevated = reinterpret_cast<TOKEN_ELEVATION*>(el.data())->TokenIsElevated;
  auto rs = token_info(t.h, TokenRestrictedSids);
  out.restricted = reinterpret_cast<TOKEN_GROUPS*>(rs.data())->GroupCount != 0;
  auto hr = token_info(t.h, TokenHasRestrictions); out.has_restrictions = *reinterpret_cast<DWORD*>(hr.data());
  auto app = token_info(t.h, TokenIsAppContainer); out.appcontainer = *reinterpret_cast<DWORD*>(app.data());
  auto g = token_info(t.h, TokenGroups); auto* groups = reinterpret_cast<TOKEN_GROUPS*>(g.data());
  for (DWORD i = 0; i < groups->GroupCount; ++i)
    if (sid_text(groups->Groups[i].Sid) == L"S-1-5-32-544" &&
        (groups->Groups[i].Attributes & SE_GROUP_ENABLED) && !(groups->Groups[i].Attributes & SE_GROUP_USE_FOR_DENY_ONLY)) out.admin = true;
  auto pr = token_info(t.h, TokenPrivileges); auto* privileges = reinterpret_cast<TOKEN_PRIVILEGES*>(pr.data());
  yes(privileges->PrivilegeCount <= 128, "privilege observation bound");
  for (DWORD i = 0; i < privileges->PrivilegeCount; ++i) {
    const auto& x = privileges->Privileges[i];
    out.privileges += std::to_string(static_cast<DWORD>(x.Luid.HighPart)) + ":" +
      std::to_string(x.Luid.LowPart) + ":" + std::to_string(x.Attributes) + ",";
  }
  return out;
}
std::string token_record(const Token& t) {
  return "sid=" + utf8(t.sid) + ";session=" + std::to_string(t.session) + ";luid=" + std::to_string(t.luid) +
    ";integrity=" + std::to_string(t.integrity) + ";elevation_type=" + std::to_string(t.elevation_type) +
    ";elevated=" + std::to_string(t.elevated) + ";restricted=" + std::to_string(t.restricted) +
    ";has_restrictions=" + std::to_string(t.has_restrictions) + ";appcontainer=" + std::to_string(t.appcontainer) + ";privilege-LUID-attributes=" + t.privileges + "\n";
}
void expected_token(const Token& t, bool observer) {
  yes(t.sid == cfg::sid && !t.restricted && !t.appcontainer, "actual SID/restriction mismatch");
  yes(t.session == (observer ? cfg::observer_session : cfg::probe_session) &&
      t.luid == (observer ? cfg::observer_luid : cfg::probe_luid), "actual session/logon identity mismatch");
  yes(t.integrity == (observer ? SECURITY_MANDATORY_HIGH_RID : SECURITY_MANDATORY_MEDIUM_RID) &&
      t.elevation_type == (observer ? TokenElevationTypeFull : TokenElevationTypeLimited) &&
      t.elevated == (observer ? 1UL : 0UL) && (!observer || t.admin), "actual elevation/administrator role mismatch");
}
struct Record {
  Handle file;
  std::wstring path;
  DWORD volume{}; unsigned long long file_id{};
  explicit Record(const std::wstring& value): file(create(value)), path(value) { file_id = identity(file.h, &volume); }
  std::string receipt() const { return "record-identity=" + std::to_string(volume) + ":" + std::to_string(file_id) + "\n"; }
  static HANDLE create(const std::wstring& path) {
    Local sd;
    yes(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)", SDDL_REVISION_1,
      reinterpret_cast<PSECURITY_DESCRIPTOR*>(&sd.p), nullptr) != FALSE, "report SD");
    SECURITY_ATTRIBUTES sa{sizeof(sa), sd.p, FALSE};
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE | READ_CONTROL, 0, &sa,
      CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, nullptr);
    yes(h != INVALID_HANDLE_VALUE, "fresh fixed protected record collision/failure"); return h;
  }
  void write(const std::string& text) {
    yes(text.size() <= 8192, "protected record bound"); check_acl(file.h, false);
    DWORD now_volume{}; yes(identity(file.h, &now_volume) == file_id && now_volume == volume &&
      _wcsicmp(final_path(file.h).c_str(), path.c_str()) == 0, "protected record object/path drift");
    LARGE_INTEGER zero{}; yes(SetFilePointerEx(file.h, zero, nullptr, FILE_BEGIN) != FALSE, "record rewind");
    DWORD n{}; yes(WriteFile(file.h, text.data(), static_cast<DWORD>(text.size()), &n, nullptr) && n == text.size() &&
      SetEndOfFile(file.h) && FlushFileBuffers(file.h), "record durable write");
    yes(SetFilePointerEx(file.h, zero, nullptr, FILE_BEGIN) != FALSE, "record readback rewind");
    char b[8193]{}; yes(ReadFile(file.h, b, sizeof(b), &n, nullptr) && n == text.size() && std::string(b, n) == text, "held protected readback");
  }
};
struct Task {
  Com<ITaskService> service;
  Com<ITaskFolder> folder;
  Com<IRegisteredTask> registered;
  Com<IRunningTask> running;
  std::wstring xml;
  bool created{}, run_attempted{}, task_absent{};
  // MinGW's installed taskschd.h omits TASK_RUN_FLAGS. These are the documented
  // TASK_RUN_USE_SESSION_ID (0x4) / TASK_RUN_USER_SID (0x8) wire/API values.
  static constexpr LONG kTASK_RUN_USE_SESSION_ID = 0x4, kTASK_RUN_USER_SID = 0x8;
  void verify_definition() {
    Com<ITaskDefinition> d; ok(registered->get_Definition(d.out()), "definition readback");
    Com<IPrincipal> p; ok(d->get_Principal(p.out()), "principal readback");
    Bstr sid, group; TASK_LOGON_TYPE logon{}; TASK_RUNLEVEL_TYPE level{};
    ok(p->get_UserId(sid.out()), "SID readback"); ok(p->get_GroupId(group.out()), "group readback");
    ok(p->get_LogonType(&logon), "logon readback"); ok(p->get_RunLevel(&level), "runlevel readback");
    yes(sid.str() == cfg::sid && group.str().empty() && logon == TASK_LOGON_INTERACTIVE_TOKEN && level == TASK_RUNLEVEL_LUA,
        "actual task principal differs from fixed role");
    Com<ITriggerCollection> triggers; ok(d->get_Triggers(triggers.out()), "triggers readback");
    LONG count{}; ok(triggers->get_Count(&count), "trigger count"); yes(count == 0, "unexpected trigger");
    Com<IActionCollection> actions; ok(d->get_Actions(actions.out()), "actions readback");
    ok(actions->get_Count(&count), "action count"); yes(count == 1, "unexpected action cardinality");
    Com<IAction> a; ok(actions->get_Item(1, a.out()), "action readback"); TASK_ACTION_TYPE type{}; Bstr aid;
    ok(a->get_Type(&type), "action type"); ok(a->get_Id(aid.out()), "action ID readback");
    yes(type == TASK_ACTION_EXEC && aid.str() == L"fixed-nonsecret-probe", "unexpected action identity");
    Com<IExecAction> x; ok(a->QueryInterface(IID_IExecAction, reinterpret_cast<void**>(x.out())), "exec readback");
    Bstr path, args, work; ok(x->get_Path(path.out()), "image readback"); ok(x->get_Arguments(args.out()), "arguments readback");
    ok(x->get_WorkingDirectory(work.out()), "working directory readback");
    yes(path.str() == std::wstring(cfg::root) + L"\\phase1_task_identity_probe.exe" && args.str().empty() && work.str() == cfg::root,
        "actual action differs from fixed protected image/no-arguments contract");
    Com<ITaskSettings> s; ok(d->get_Settings(s.out()), "settings readback");
    VARIANT_BOOL enabled{}, demand{}, idle{}, network{}, batteries{}, stop_battery{}, hard{};
    TASK_INSTANCES_POLICY policy{}; Bstr limit;
    ok(s->get_Enabled(&enabled), "enabled readback"); ok(s->get_AllowDemandStart(&demand), "demand readback");
    ok(s->get_RunOnlyIfIdle(&idle), "idle readback"); ok(s->get_RunOnlyIfNetworkAvailable(&network), "network readback");
    ok(s->get_DisallowStartIfOnBatteries(&batteries), "battery readback"); ok(s->get_StopIfGoingOnBatteries(&stop_battery), "battery stop readback");
    ok(s->get_AllowHardTerminate(&hard), "stop readback"); ok(s->get_MultipleInstances(&policy), "instance policy readback");
    ok(s->get_ExecutionTimeLimit(limit.out()), "time limit readback");
    yes(enabled == VARIANT_TRUE && demand == VARIANT_TRUE && idle == VARIANT_FALSE && network == VARIANT_FALSE &&
        batteries == VARIANT_FALSE && stop_battery == VARIANT_FALSE && hard == VARIANT_TRUE &&
        policy == TASK_INSTANCES_IGNORE_NEW && limit.str() == L"PT15S", "actual fixed task settings mismatch");
  }
  void unchanged() {
    verify_definition();
    Bstr now; ok(registered->get_Xml(now.out()), "task configuration readback");
    yes(now.str() == xml, "task configuration changed; no adoption/cleanup");
    Bstr sd; ok(registered->GetSecurityDescriptor(OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, sd.out()), "task SD readback");
    Local parsed; yes(ConvertStringSecurityDescriptorToSecurityDescriptorW(sd.p, SDDL_REVISION_1,
      reinterpret_cast<PSECURITY_DESCRIPTOR*>(&parsed.p), nullptr), "task SD parse"); check_sd(parsed.p, false, true);
  }
  void create(const std::wstring& probe, const std::wstring& root) {
    ok(CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskService,
      reinterpret_cast<void**>(service.out())), "Task Scheduler COM");
    VARIANT empty{}; ok(service->Connect(empty, empty, empty, empty), "local Task Scheduler connect");
    Bstr slash(L"\\"); ok(service->GetFolder(slash.p, folder.out()), "task root folder");
    Com<ITaskDefinition> def; ok(service->NewTask(0, def.out()), "new exact task definition");
    Com<IPrincipal> principal; ok(def->get_Principal(principal.out()), "principal");
    Bstr sid(cfg::sid); ok(principal->put_UserId(sid.p), "existing UserA SID principal");
    ok(principal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN), "interactive token only");
    ok(principal->put_RunLevel(TASK_RUNLEVEL_LUA), "limited task only");
    Com<ITaskSettings> settings; ok(def->get_Settings(settings.out()), "settings");
    ok(settings->put_Enabled(VARIANT_TRUE), "enabled"); ok(settings->put_AllowDemandStart(VARIANT_TRUE), "demand start");
    ok(settings->put_MultipleInstances(TASK_INSTANCES_IGNORE_NEW), "one instance");
    ok(settings->put_DisallowStartIfOnBatteries(VARIANT_FALSE), "battery start");
    ok(settings->put_StopIfGoingOnBatteries(VARIANT_FALSE), "battery stop");
    ok(settings->put_AllowHardTerminate(VARIANT_TRUE), "owned task stop");
    Bstr limit(L"PT15S"); ok(settings->put_ExecutionTimeLimit(limit.p), "fixed time limit");
    Com<IActionCollection> actions; ok(def->get_Actions(actions.out()), "actions");
    Com<IAction> action; ok(actions->Create(TASK_ACTION_EXEC, action.out()), "one fixed action");
    Bstr action_id(L"fixed-nonsecret-probe"); ok(action->put_Id(action_id.p), "action ID");
    Com<IExecAction> exec; ok(action->QueryInterface(IID_IExecAction, reinterpret_cast<void**>(exec.out())), "exec action");
    Bstr path(probe.c_str()), work(root.c_str()), noargs(L"");
    ok(exec->put_Path(path.p), "fixed probe path"); ok(exec->put_Arguments(noargs.p), "no arguments");
    ok(exec->put_WorkingDirectory(work.p), "fixed protected working directory");
    Bstr name(cfg::task_name); Variant user(cfg::sid), sd(L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)");
    // Success warnings can still mean registration occurred. Record ownership
    // before evaluating HRESULT; never mistake a warning for absence.
    HRESULT h = folder->RegisterTaskDefinition(name.p, def.p, TASK_CREATE | TASK_DONT_ADD_PRINCIPAL_ACE,
      user.v, empty, TASK_LOGON_INTERACTIVE_TOKEN, sd.v, registered.out());
    created = registered.p != nullptr;
    ok(h, "fresh exact task registration (warnings are incomplete)"); yes(created, "registration object missing");
    Bstr actual; ok(registered->get_Xml(actual.out()), "registered XML"); xml = actual.str(); unchanged();
  }
  void start() {
    unchanged(); VARIANT empty{}; Bstr user(cfg::sid); run_attempted = true;
    ok(registered->RunEx(empty, kTASK_RUN_USE_SESSION_ID | kTASK_RUN_USER_SID,
      static_cast<LONG>(cfg::probe_session), user.p, running.out()), "exact interactive session RunEx");
    yes(running.p != nullptr, "no exact running instance");
  }
  bool cleanup() noexcept {
    if (!created) return false; // no registration object/readback is NOT absence proof
    try {
      // A failed registration readback does not authorize guessing/adopting a name.
      yes(!xml.empty(), "task readback missing; retain recovery"); unchanged();
      if (run_attempted) {
        yes(running.p != nullptr, "unknown RunEx outcome; retain task/recovery");
        ok(running->Stop(), "stop exact running instance");
        bool none = false;
        for (unsigned i = 0; i < 40; ++i) {
          Com<IRunningTaskCollection> instances; ok(registered->GetInstances(0, instances.out()), "exact task instances cleanup readback");
          LONG count{}; ok(instances->get_Count(&count), "instances count");
          if (count == 0) { none = true; break; } Sleep(25);
        }
        yes(none, "task instances not absent; retain recovery");
      }
      unchanged(); Bstr name(cfg::task_name); ok(folder->DeleteTask(name.p, 0), "delete exact owned task");
      Com<IRegisteredTask> absent; HRESULT h = folder->GetTask(name.p, absent.out());
      yes(h == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) && !absent.p, "task absence unknown");
      task_absent = true; return true;
    } catch (...) { return false; }
  }
};
unsigned long long stamp(FILETIME x) { return (static_cast<unsigned long long>(x.dwHighDateTime) << 32) | x.dwLowDateTime; }
}
int wmain(int argc, wchar_t**) {
  // A compilation fixture cannot touch filesystem, COM, tokens or tasks.
  volatile const bool compilation_fixture = cfg::compilation_fixture;
  if (argc != 1 || compilation_fixture) { std::puts("INCOMPLETE: compilation fixture/not a native-approved input; further_admission=false"); return 77; }
  bool com_init = false;
  Task task;
  Handle engine; // retain actual OS-returned engine object through cleanup/readback
  std::vector<Handle> held;
  std::string evidence = "NONSECRET task-identity diagnostic v1\nfurther_admission=false\nexternal-bootstrap-authentication=REQUIRED-OUTSIDE-THIS-PROCESS\n";
  phase1_task_identity::Evidence e;
  int result = 2;
  try {
    HANDLE impersonation{};
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &impersonation)) { Handle reject(impersonation); fail("preexisting thread impersonation rejected"); }
    yes(GetLastError() == ERROR_NO_TOKEN, "thread-token query unknown");
    auto observer = describe(GetCurrentProcess()); evidence += "observer:" + token_record(observer); expected_token(observer, true); e.observer_token = true;
    PWSTR pf{}; ok(SHGetKnownFolderPath(FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, nullptr, &pf), "OS Program Files");
    struct FreePf { PWSTR p; ~FreePf() { CoTaskMemFree(p); } } ownpf{pf};
    yes(std::wstring(pf) == cfg::program_files, "actual Program Files differs from externally fixed input");
    const std::wstring root(cfg::root), sink(cfg::evidence_root), program_files(cfg::program_files);
    const std::wstring drive = program_files.substr(0, 3);
    yes(GetDriveTypeW(drive.c_str()) == DRIVE_FIXED, "fixed local drive required");
    held.push_back(open_fixed(drive, true, true)); held.push_back(open_fixed(program_files, true, true));
    wchar_t filesystem[32]{};
    yes(GetVolumeInformationByHandleW(held[0].h, nullptr, 0, nullptr, nullptr, nullptr, filesystem, 32) &&
      std::wstring(filesystem) == L"NTFS", "NTFS identity contract required");
    held.push_back(open_fixed(root, true)); held.push_back(open_fixed(sink, true));
    DWORD volume{}; auto id = identity(held[2].h, &volume);
    yes(volume == cfg::root_volume && id == cfg::root_file_id, "externally expected image root object mismatch");
    evidence += "image-root-volume=" + std::to_string(volume) + ";file-id=" + std::to_string(id) + "\n";
    id = identity(held[3].h, &volume); yes(volume == cfg::evidence_volume && id == cfg::evidence_file_id, "externally expected evidence root object mismatch");
    evidence += "evidence-root-volume=" + std::to_string(volume) + ";file-id=" + std::to_string(id) + "\n"; e.held_protected_roots = true;
    const auto probe = root + L"\\phase1_task_identity_probe.exe";
    held.push_back(open_fixed(root + L"\\plan.bin", false));
    yes(hash_file(held.back().h, 8192) == cfg::plan_sha256, "externally fixed plan digest mismatch");
    held.push_back(open_fixed(probe, false)); yes(hash_file(held.back().h, 32ULL * 1024 * 1024) == cfg::probe_sha256, "fixed probe digest mismatch");
    held.push_back(open_fixed(root + L"\\phase1_task_identity_observer.exe", false));
    wchar_t self[2048]{}; DWORD n = GetModuleFileNameW(nullptr, self, 2048);
    yes(n && n < 2048 && _wcsicmp(self, (root + L"\\phase1_task_identity_observer.exe").c_str()) == 0, "observer is not fixed role path");
    evidence += "observer-held-sha256=" + hash_file(held.back().h, 32ULL * 1024 * 1024) + "\n";
    evidence += "observer-digest-is-observation-not-bootstrap-authentication\n";
    e.fixed_images = true;
    // This is a conditional externally authenticated fixture, not self-authentication.
    // It can never admit work even if every subsequent observation agrees.
    e.external_authority = true;
    std::vector<std::pair<DWORD, unsigned long long>> held_identities;
    std::vector<std::wstring> held_paths;
    for (const auto& h: held) { DWORD v{}; auto f = identity(h.h, &v); held_identities.emplace_back(v, f); held_paths.push_back(final_path(h.h)); }
    const auto self_digest = hash_file(held[6].h, 32ULL * 1024 * 1024);
    auto verify_held_continuity = [&] {
      for (size_t i = 0; i < held.size(); ++i) {
        DWORD v{}; auto f = identity(held[i].h, &v);
        yes(held_identities[i] == std::make_pair(v, f) && final_path(held[i].h) == held_paths[i], "held object/path identity drift");
        check_acl(held[i].h, i < 2);
      }
      yes(hash_file(held[4].h, 8192) == cfg::plan_sha256 &&
          hash_file(held[5].h, 32ULL * 1024 * 1024) == cfg::probe_sha256 &&
          hash_file(held[6].h, 32ULL * 1024 * 1024) == self_digest, "held plan/image content drift");
    };
    Record journal(sink + L"\\recovery.bin");
    evidence += "recovery-" + journal.receipt();
    for (size_t i = 0; i < held_identities.size(); ++i) evidence += "held-object-" + std::to_string(i) + "=" +
      std::to_string(held_identities[i].first) + ":" + std::to_string(held_identities[i].second) + "\n";
    evidence += "nonce=" + std::string(cfg::nonce) + "\ntask=" + utf8(cfg::task_name) + "\nstate=BEFORE-TASK-CREATE\n";
    journal.write(evidence); // must succeed/read back BEFORE registration or RunEx
    Record report(sink + L"\\report.bin"); evidence += "report-" + report.receipt();
    journal.write(evidence); report.write(evidence);
    try {
      HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
      com_init = SUCCEEDED(initialized); ok(initialized, "COM initialization");
      // RPC security settings are explicit; no impersonation or delegation is requested.
      ok(CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IDENTIFY, nullptr, EOAC_DISABLE_AAA, nullptr), "COM security");
      verify_held_continuity();
      task.create(probe, root); evidence += "state=TASK-CONFIG-READ-BACK\n"; journal.write(evidence);
      FILETIME before{}; GetSystemTimeAsFileTime(&before);
      evidence += "state=RUN-INTENT-DURABLE\n"; journal.write(evidence); task.start();
      Bstr guid, taskpath; ok(task.running->get_InstanceGuid(guid.out()), "actual instance GUID");
      ok(task.running->get_Path(taskpath.out()), "actual running task path");
      yes(!guid.str().empty() && taskpath.str() == L"\\" + std::wstring(cfg::task_name), "running instance identity mismatch");
      evidence += "instance-guid=" + utf8(guid.str()) + "\n"; e.exact_task_instance = true; journal.write(evidence);
      DWORD pid{};
      for (unsigned i = 0; i < 40; ++i) { ok(task.running->Refresh(), "instance refresh"); ok(task.running->get_EnginePID(&pid), "actual COM EnginePID"); if (pid) break; Sleep(25); }
      yes(pid != 0, "COM engine PID unavailable");
      evidence += "actual-COM-engine-pid=" + std::to_string(pid) + "\n"; journal.write(evidence);
      // Open ONLY the OS-returned engine. No report PID, snapshot/name search,
      // parent-PID inference, worker exit-code witness, process-DACL change or kill.
      engine.h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
      Handle& process = engine;
      yes(process.h != nullptr && GetProcessId(process.h) == pid && WaitForSingleObject(process.h, 0) == WAIT_TIMEOUT, "cannot retain live actual engine object"); e.engine_process_held = true;
      FILETIME creation{}, exit{}, kernel{}, user{};
      yes(GetProcessTimes(process.h, &creation, &exit, &kernel, &user) != FALSE, "actual engine creation object");
      evidence += "engine-creation-filetime=" + std::to_string(stamp(creation)) + "\n";
      wchar_t image[2048]{}; DWORD chars = 2048;
      yes(QueryFullProcessImageNameW(process.h, 0, image, &chars) && chars && chars < 2048, "actual engine image query");
      evidence += "engine-image=" + utf8(std::wstring(image, chars)) + "\n";
      auto actual = describe(process.h); evidence += "engine-token:" + token_record(actual); journal.write(evidence);
      e.engine_image_is_fixed_probe = _wcsicmp(image, probe.c_str()) == 0;
      if (e.engine_image_is_fixed_probe) {
        // Holding the protected fixed file through launch/readback excludes
        // unprivileged path replacement; it is NOT a mapped-image/action proof.
        expected_token(actual, false); e.probe_token = true;
        e.process_creation_checked = stamp(creation) >= stamp(before);
        ok(task.running->Refresh(), "second instance refresh"); Bstr again, action;
        DWORD repeated{}; TASK_STATE state{};
        ok(task.running->get_InstanceGuid(again.out()), "second GUID"); ok(task.running->get_EnginePID(&repeated), "second EnginePID");
        ok(task.running->get_CurrentAction(action.out()), "current action"); ok(task.running->get_State(&state), "actual task state");
        e.engine_instance_rechecked = again.str() == guid.str() && repeated == pid && state == TASK_STATE_RUNNING &&
          action.str() == L"fixed-nonsecret-probe" && WaitForSingleObject(process.h, 0) == WAIT_TIMEOUT;
      }
      evidence += "classification=" + std::to_string(static_cast<unsigned>(phase1_task_identity::classify(e))) + "\n";
      evidence += e.engine_image_is_fixed_probe ?
        "INCOMPLETE: action_binding_unproved; engine/image equality is observation, not an authoritative task-action-object contract\n" :
        "INCOMPLETE: actual engine is NOT fixed probe; no authoritative engine-to-action-process acquisition route implemented\n";
      // The first slice deliberately NEVER claims task action/body execution,
      // Job independence, SYSTEM rights, cleanup of unknown action objects or admission.
      evidence += "action-process-cleanup=UNKNOWN; no PID inference/kill\n";
      journal.write(evidence);
    } catch (const std::exception& x) { evidence += std::string("INCOMPLETE: ") + x.what() + "\n"; }
    evidence += task.cleanup() ? "exact-task-cleanup=ABSENT-READBACK\n" : "exact-task-cleanup=UNKNOWN; retain recovery\n";
    evidence += "final=further_admission=false; roots-and-protected-records-retained\n";
    verify_held_continuity();
    journal.write(evidence);
    if (engine.h && engine.h != INVALID_HANDLE_VALUE) {
      DWORD signal = WaitForSingleObject(engine.h, 0);
      evidence += "retained-engine-object-wait-after-task-cleanup=" + std::to_string(signal) + "\n";
    }
    journal.write(evidence); report.write(evidence); verify_held_continuity();
    // journal/report and retained image/ancestor handles survive through readback.
  } catch (const std::exception& x) {
    // The local journal owns its handle only within the inner scope. No task
    // may be launched before its first durable intent. An interrupted final
    // report never removes the existing protected journal or guesses cleanup.
    (void)task.cleanup(); // exact retained objects/config only; never name adoption
    std::fprintf(stderr, "INCOMPLETE: %s; further_admission=false; retain any protected recovery record\n", x.what());
  }
  // Release COM interfaces before apartment teardown; no destructor mutates tasks.
  if (task.running.p) { task.running.p->Release(); task.running.p = nullptr; }
  if (task.registered.p) { task.registered.p->Release(); task.registered.p = nullptr; }
  if (task.folder.p) { task.folder.p->Release(); task.folder.p = nullptr; }
  if (task.service.p) { task.service.p->Release(); task.service.p = nullptr; }
  if (com_init) CoUninitialize();
  std::puts("INCOMPLETE: NONSECRET task identity diagnostic only; action_binding_unproved; further_admission=false");
  return result;
}
