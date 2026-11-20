// Behavioural check of per-sandbox network containment (run elevated):
//
//   sandbox-netcheck.exe            -> prints a PASS/FAIL table, exit 0 if all pass
//
// It creates two throw-away sandboxes A and B (own AppContainer each), opens a
// loopback listener for each (standing in for their proxies), installs the WFP
// proxy-only rules, then launches itself inside A's AppContainer to attempt
// connections. Expected: only A's own proxy port is reachable. The same probe is
// repeated with B's rules to show the policy is per-sandbox, and once without
// rules to record the baseline AppContainer behaviour.
#include "appcontainer_win.hpp"
#include "firewall_win.hpp"
#include "launch_win.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <sddl.h>

#include <atomic>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

namespace sb = orangespace::sandbox;

namespace {
const char* kSandboxA = "6f0e1a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b";
const char* kSandboxB = "7a1b2c3d-4e5f-4a6b-9c8d-1e2f3a4b5c6d";

// ---- child side -----------------------------------------------------------
int TcpConnect(const char* host, const char* port) {
  addrinfo hints{}, *res = nullptr;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_NUMERICHOST;
  if (getaddrinfo(host, port, &hints, &res) != 0) return -1;
  SOCKET s = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP);
  u_long nb = 1;
  ioctlsocket(s, FIONBIO, &nb);
  connect(s, res->ai_addr, static_cast<int>(res->ai_addrlen));
  int err = WSAGetLastError();
  if (err == WSAEWOULDBLOCK) {
    fd_set w, e;
    FD_ZERO(&w);
    FD_ZERO(&e);
    FD_SET(s, &w);
    FD_SET(s, &e);
    timeval tv{3, 0};
    const int n = select(0, nullptr, &w, &e, &tv);
    if (n == 0) err = WSAETIMEDOUT;
    else if (FD_ISSET(s, &e)) {
      int so = 0, len = sizeof(so);
      getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so), &len);
      err = so;
    } else err = 0;
  }
  closesocket(s);
  freeaddrinfo(res);
  return err;
}

int UdpSend(const char* host, const char* port) {
  addrinfo hints{}, *res = nullptr;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_NUMERICHOST;
  if (getaddrinfo(host, port, &hints, &res) != 0) return -1;
  SOCKET s = socket(res->ai_family, SOCK_DGRAM, IPPROTO_UDP);
  const char payload[] = "x";
  const int rc = sendto(s, payload, 1, 0, res->ai_addr, static_cast<int>(res->ai_addrlen));
  const int err = rc == SOCKET_ERROR ? WSAGetLastError() : 0;
  closesocket(s);
  freeaddrinfo(res);
  return err;
}

int Probe(const std::string& own_port, const std::string& other_port, const std::string& udp_ip,
          const std::string& udp_port) {
  WSADATA wsa{};
  WSAStartup(MAKEWORD(2, 2), &wsa);
  std::printf("own_proxy %d\n", TcpConnect("127.0.0.1", own_port.c_str()));
  std::printf("other_proxy %d\n", TcpConnect("127.0.0.1", other_port.c_str()));
  std::printf("internet_v4 %d\n", TcpConnect("1.1.1.1", "443"));
  std::printf("lan_v4 %d\n", TcpConnect("192.168.122.1", "22"));
  std::printf("internet_v6 %d\n", TcpConnect("2606:4700:4700::1111", "443"));
  std::printf("loopback_v6 %d\n", TcpConnect("::1", own_port.c_str()));
  // UDP is dropped silently by WFP, so sendto() results prove nothing; the
  // parent counts what actually arrives (loopback and a non-loopback address).
  for (int i = 0; i < 3; ++i) {
    UdpSend("127.0.0.1", own_port.c_str());
    UdpSend(udp_ip.c_str(), udp_port.c_str());
  }
  Sleep(300);
  addrinfo hints{}, *res = nullptr;
  hints.ai_socktype = SOCK_STREAM;
  const int dns = getaddrinfo("example.com", "443", &hints, &res);
  if (res) freeaddrinfo(res);
  std::printf("system_dns %d\n", dns);
  std::fflush(stdout);
  return 0;
}

// ---- parent side ----------------------------------------------------------
SOCKET Listen(std::uint16_t& port) {
  SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  int len = sizeof(a);
  bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a));
  listen(s, 16);
  getsockname(s, reinterpret_cast<sockaddr*>(&a), &len);
  port = ntohs(a.sin_port);
  return s;
}

std::atomic<int> g_udp_received{0};
std::atomic<int> g_udp_lan_received{0};
// Binds a UDP counter on addr:port (port 0 = ephemeral); returns the bound port.
std::uint16_t UdpCounter(in_addr addr, std::uint16_t port, std::atomic<int>& counter) {
  SOCKET u = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr = addr;
  a.sin_port = htons(port);
  if (bind(u, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) return 0;
  int len = sizeof(a);
  getsockname(u, reinterpret_cast<sockaddr*>(&a), &len);
  std::thread([u, &counter] {
    char b[64];
    while (recv(u, b, sizeof(b), 0) != SOCKET_ERROR) ++counter;
  }).detach();
  return ntohs(a.sin_port);
}
void UdpCounter(std::uint16_t port) {
  in_addr lo{};
  lo.s_addr = htonl(INADDR_LOOPBACK);
  UdpCounter(lo, port, g_udp_received);
}

// First non-loopback IPv4 address of this machine (the probe must not be
// allowed to reach it: remote address != 127.0.0.1).
in_addr LocalNonLoopbackV4() {
  char host[256]{};
  gethostname(host, sizeof(host));
  addrinfo hints{}, *res = nullptr;
  hints.ai_family = AF_INET;
  in_addr out{};
  if (getaddrinfo(host, nullptr, &hints, &res) == 0) {
    for (auto* r = res; r; r = r->ai_next) {
      const auto a = reinterpret_cast<sockaddr_in*>(r->ai_addr)->sin_addr;
      if ((ntohl(a.s_addr) >> 24) != 127) {
        out = a;
        break;
      }
    }
    freeaddrinfo(res);
  }
  return out;
}
std::string g_udp_target_ip;
std::uint16_t g_udp_target_port = 0;

std::vector<std::pair<std::string, int>> RunProbe(const std::wstring& self, void* sid, std::uint16_t own,
                                                  std::uint16_t other) {
  std::wstring target(g_udp_target_ip.begin(), g_udp_target_ip.end());
  sb::BrowserLaunch launch{self, sid, nullptr,
                           L"--probe " + std::to_wstring(own) + L" " + std::to_wstring(other) + L" " + target +
                               L" " + std::to_wstring(g_udp_target_port)};
  launch.no_appcontainer = sid == nullptr;  // AppId mode: identity is the image path
  auto p = sb::LaunchBrowser(launch);
  p.to_host.reset();
  std::string out;
  char buf[512];
  DWORD got = 0;
  while (ReadFile(p.from_host.get(), buf, sizeof(buf), &got, nullptr) && got) out.append(buf, got);
  WaitForSingleObject(p.process.get(), 30000);
  std::vector<std::pair<std::string, int>> r;
  // 0 = delivered (reachable), like the TCP results; otherwise "blocked".
  r.emplace_back("udp_loopback", g_udp_received.exchange(0) > 0 ? 0 : 10013);
  r.emplace_back("udp_nonloopback", g_udp_lan_received.exchange(0) > 0 ? 0 : 10013);
  std::size_t pos = 0;
  while (pos < out.size()) {
    const auto end = out.find('\n', pos);
    const auto line = out.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
    const auto sp = line.find(' ');
    if (sp != std::string::npos) r.emplace_back(line.substr(0, sp), std::atoi(line.c_str() + sp + 1));
    if (end == std::string::npos) break;
    pos = end + 1;
  }
  return r;
}

int Lookup(const std::vector<std::pair<std::string, int>>& r, const std::string& key) {
  for (const auto& [k, v] : r)
    if (k == key) return v;
  return -999;
}
}  // namespace

// --user32: does user32.dll initialise inside an AppContainer on this
// window station/desktop? (Chromium's sandboxed GPU process needs it.) Run it
// in the interactive session; prints one line per launch mode.
int User32Probe() {
  const HMODULE m = LoadLibraryW(L"user32.dll");
  std::printf("user32 %lu\n", m ? 0UL : GetLastError());
  std::fflush(stdout);
  return 0;
}

// Emulates Chromium's GPU token (USER_LIMITED [+ unique restricting SID],
// optionally low integrity) and reports whether user32 initialises.
std::string RunRestricted(const std::wstring& self, bool unique_sid, bool low, bool ui_job, bool restricted = true) {
  HANDLE self_token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &self_token)) return "OpenProcessToken failed";
  DWORD len = 0;
  GetTokenInformation(self_token, TokenGroups, nullptr, 0, &len);
  std::vector<unsigned char> gbuf(len);
  auto* groups = reinterpret_cast<TOKEN_GROUPS*>(gbuf.data());
  GetTokenInformation(self_token, TokenGroups, groups, len, &len);
  auto well_known = [](WELL_KNOWN_SID_TYPE t, std::vector<unsigned char>& out) {
    DWORD n = SECURITY_MAX_SID_SIZE;
    out.resize(n);
    CreateWellKnownSid(t, nullptr, out.data(), &n);
    return static_cast<PSID>(out.data());
  };
  std::vector<unsigned char> users, world, interactive, restricted_sid;
  PSID su = well_known(WinBuiltinUsersSid, users), sw = well_known(WinWorldSid, world),
       si = well_known(WinInteractiveSid, interactive), sr = well_known(WinRestrictedCodeSid, restricted_sid);
  std::vector<SID_AND_ATTRIBUTES> deny, restrict;
  PSID logon = nullptr;
  for (DWORD i = 0; i < groups->GroupCount; ++i) {
    const auto& g = groups->Groups[i];
    if (g.Attributes & SE_GROUP_LOGON_ID) {
      logon = g.Sid;
      continue;
    }
    if (g.Attributes & SE_GROUP_INTEGRITY) continue;
    if (EqualSid(g.Sid, su) || EqualSid(g.Sid, sw) || EqualSid(g.Sid, si)) continue;
    deny.push_back({g.Sid, 0});
  }
  restrict.push_back({su, 0});
  restrict.push_back({sw, 0});
  restrict.push_back({sr, 0});
  PSID random = nullptr;
  SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
  if (unique_sid) {
    AllocateAndInitializeSid(&nt, 5, SECURITY_NT_NON_UNIQUE, GetTickCount(), GetCurrentProcessId(), 12345, 67890, 0, 0,
                             0, &random);
    restrict.push_back({random, 0});
  }
  if (logon) restrict.push_back({logon, 0});
  HANDLE token = nullptr;
  if (!restricted) {
    if (!DuplicateTokenEx(self_token, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation, TokenPrimary, &token))
      return "DuplicateTokenEx error " + std::to_string(GetLastError());
  } else if (!CreateRestrictedToken(self_token, DISABLE_MAX_PRIVILEGE, static_cast<DWORD>(deny.size()), deny.data(), 0,
                             nullptr, static_cast<DWORD>(restrict.size()), restrict.data(), &token)) {
    CloseHandle(self_token);
    return "CreateRestrictedToken error " + std::to_string(GetLastError());
  }
  if (random) FreeSid(random);
  if (low) {
    std::vector<unsigned char> low_sid;
    TOKEN_MANDATORY_LABEL tml{};
    tml.Label.Attributes = SE_GROUP_INTEGRITY;
    tml.Label.Sid = well_known(WinLowLabelSid, low_sid);
    if (!SetTokenInformation(token, TokenIntegrityLevel, &tml, sizeof(tml) + GetLengthSid(tml.Label.Sid)))
      return "SetTokenInformation(IL) error " + std::to_string(GetLastError());
  }
  SECURITY_ATTRIBUTES inherit{sizeof(inherit), nullptr, TRUE};
  HANDLE rd = nullptr, wr = nullptr;
  CreatePipe(&rd, &wr, &inherit, 0);
  SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
  STARTUPINFOW st{};
  st.cb = sizeof(st);
  st.dwFlags = STARTF_USESTDHANDLES;
  st.hStdOutput = wr;
  st.hStdError = wr;
  std::wstring cmd = L"\"" + self + L"\" --user32-probe";
  PROCESS_INFORMATION pi{};
  std::string result;
  if (!CreateProcessAsUserW(token, self.c_str(), cmd.data(), nullptr, nullptr, TRUE, CREATE_SUSPENDED, nullptr,
                            nullptr, &st, &pi)) {
    result = "CreateProcessAsUser error " + std::to_string(GetLastError());
  } else {
    if (ui_job) {
      HANDLE job = CreateJobObjectW(nullptr, nullptr);
      JOBOBJECT_BASIC_UI_RESTRICTIONS ui{JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS | JOB_OBJECT_UILIMIT_DESKTOP |
                                         JOB_OBJECT_UILIMIT_EXITWINDOWS | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS};
      SetInformationJobObject(job, JobObjectBasicUIRestrictions, &ui, sizeof(ui));
      AssignProcessToJobObject(job, pi.hProcess);
    }
    ResumeThread(pi.hThread);
    CloseHandle(wr);
    wr = nullptr;
    char buf[256];
    DWORD got = 0;
    while (ReadFile(rd, buf, sizeof(buf), &got, nullptr) && got) result.append(buf, got);
    WaitForSingleObject(pi.hProcess, 10000);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    char hex[32];
    std::snprintf(hex, sizeof(hex), "exit=0x%08lx ", code);
    result = hex + (result.empty() ? std::string("(no output)\n") : result);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
  }
  if (wr) CloseHandle(wr);
  CloseHandle(rd);
  CloseHandle(token);
  CloseHandle(self_token);
  return result;
}

int User32Restricted(const std::wstring& self) {
  DWORD session = 0;
  ProcessIdToSessionId(GetCurrentProcessId(), &session);
  std::printf("session %lu\n", session);
  // What a low-integrity copy of our token may open on WinSta0 / Default.
  {
    HANDLE t = nullptr, imp = nullptr;
    OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &t);
    DuplicateTokenEx(t, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation, TokenImpersonation, &imp);
    std::vector<unsigned char> low_sid(SECURITY_MAX_SID_SIZE);
    DWORD n = SECURITY_MAX_SID_SIZE;
    CreateWellKnownSid(WinLowLabelSid, nullptr, low_sid.data(), &n);
    TOKEN_MANDATORY_LABEL tml{};
    tml.Label.Attributes = SE_GROUP_INTEGRITY;
    tml.Label.Sid = low_sid.data();
    SetTokenInformation(imp, TokenIntegrityLevel, &tml, sizeof(tml) + GetLengthSid(tml.Label.Sid));
    auto check = [&](HANDLE obj, const char* label, GENERIC_MAPPING map) {
      SECURITY_INFORMATION si = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
                                LABEL_SECURITY_INFORMATION;
      DWORD need = 0;
      GetUserObjectSecurity(obj, &si, nullptr, 0, &need);
      std::vector<unsigned char> sd(need);
      if (!GetUserObjectSecurity(obj, &si, sd.data(), need, &need)) {
        std::printf("%s: GetUserObjectSecurity error %lu\n", label, GetLastError());
        return;
      }
      PRIVILEGE_SET ps{};
      DWORD ps_len = sizeof(ps), granted = 0;
      BOOL status = FALSE;
      if (!AccessCheck(sd.data(), imp, MAXIMUM_ALLOWED, &map, &ps, &ps_len, &granted, &status))
        std::printf("%s: AccessCheck error %lu\n", label, GetLastError());
      else
        std::printf("%s low-IL granted=0x%08lx status=%d\n", label, granted, status);
      LPWSTR sddl = nullptr;
      ConvertSecurityDescriptorToStringSecurityDescriptorW(sd.data(), SDDL_REVISION_1, si, &sddl, nullptr);
      std::printf("%s sddl=%ls\n", label, sddl ? sddl : L"?");
      LocalFree(sddl);
    };
    check(GetProcessWindowStation(), "winsta",
          {STANDARD_RIGHTS_READ | WINSTA_ENUMDESKTOPS | WINSTA_ENUMERATE | WINSTA_READATTRIBUTES | WINSTA_READSCREEN,
           STANDARD_RIGHTS_WRITE | WINSTA_ACCESSCLIPBOARD | WINSTA_CREATEDESKTOP | WINSTA_WRITEATTRIBUTES,
           STANDARD_RIGHTS_EXECUTE | WINSTA_ACCESSGLOBALATOMS | WINSTA_EXITWINDOWS, 0x37f | STANDARD_RIGHTS_REQUIRED});
    check(GetThreadDesktop(GetCurrentThreadId()), "desktop",
          {STANDARD_RIGHTS_READ | DESKTOP_ENUMERATE | DESKTOP_READOBJECTS,
           STANDARD_RIGHTS_WRITE | DESKTOP_CREATEMENU | DESKTOP_CREATEWINDOW | DESKTOP_HOOKCONTROL |
               DESKTOP_JOURNALPLAYBACK | DESKTOP_JOURNALRECORD | DESKTOP_WRITEOBJECTS,
           STANDARD_RIGHTS_EXECUTE | DESKTOP_SWITCHDESKTOP, 0x1ff | STANDARD_RIGHTS_REQUIRED});
    CloseHandle(imp);
    CloseHandle(t);
  }
  std::printf("low only           %s", RunRestricted(self, false, true, false, false).c_str());
  std::printf("limited            %s", RunRestricted(self, false, false, false).c_str());
  std::printf("limited+unique     %s", RunRestricted(self, true, false, false).c_str());
  std::printf("limited+low        %s", RunRestricted(self, false, true, false).c_str());
  std::printf("limited+unique+low %s", RunRestricted(self, true, true, false).c_str());
  std::printf("gpu-like (+uijob)  %s", RunRestricted(self, true, true, true).c_str());
  return 0;
}

int User32Check(const std::wstring& self) {
  auto run = [&](void* sid, const char* label) {
    sb::BrowserLaunch launch{self, sid, nullptr, L"--user32-probe"};
    launch.no_appcontainer = sid == nullptr;
    auto p = sb::LaunchBrowser(launch);
    p.to_host.reset();
    std::string out;
    char buf[256];
    DWORD got = 0;
    while (ReadFile(p.from_host.get(), buf, sizeof(buf), &got, nullptr) && got) out.append(buf, got);
    WaitForSingleObject(p.process.get(), 10000);
    DWORD code = 0;
    GetExitCodeProcess(p.process.get(), &code);
    std::printf("%-14s exit=0x%08lx %s", label, code, out.empty() ? "(no output)\n" : out.c_str());
  };
  DWORD session = 0;
  ProcessIdToSessionId(GetCurrentProcessId(), &session);
  std::printf("session %lu\n", session);
  try {
    auto a = sb::EnsurePackage(kSandboxA);
    std::wstring dir(self.substr(0, self.find_last_of(L'\\')));
    sb::GrantPath(dir, a.sid.get(), GENERIC_READ | GENERIC_EXECUTE, true);
    run(nullptr, "plain");
    run(a.sid.get(), "appcontainer");
    // LPAC: like Chromium's GPU sandbox, opt out of ALL APPLICATION PACKAGES.
    {
      SECURITY_ATTRIBUTES inherit{sizeof(inherit), nullptr, TRUE};
      HANDLE rd = nullptr, wr = nullptr;
      CreatePipe(&rd, &wr, &inherit, 0);
      SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
      SIZE_T size = 0;
      InitializeProcThreadAttributeList(nullptr, 3, 0, &size);
      std::vector<unsigned char> storage(size);
      auto* attrs = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
      InitializeProcThreadAttributeList(attrs, 3, 0, &size);
      SECURITY_CAPABILITIES caps{};
      caps.AppContainerSid = static_cast<PSID>(a.sid.get());
      DWORD lpac = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
      HANDLE handles[] = {wr};
      UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &caps, sizeof(caps), nullptr,
                                nullptr);
      UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY, &lpac, sizeof(lpac),
                                nullptr, nullptr);
      UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, sizeof(handles), nullptr,
                                nullptr);
      STARTUPINFOEXW si{};
      si.StartupInfo.cb = sizeof(si);
      si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
      si.StartupInfo.hStdOutput = wr;
      si.StartupInfo.hStdError = wr;
      si.lpAttributeList = attrs;
      std::wstring cmd = L"\"" + self + L"\" --user32-probe";
      PROCESS_INFORMATION pi{};
      if (!CreateProcessW(self.c_str(), cmd.data(), nullptr, nullptr, TRUE, EXTENDED_STARTUPINFO_PRESENT, nullptr,
                          nullptr, &si.StartupInfo, &pi)) {
        std::printf("lpac           CreateProcess error %lu\n", GetLastError());
      } else {
        CloseHandle(wr);
        wr = nullptr;
        std::string out;
        char buf[256];
        DWORD got = 0;
        while (ReadFile(rd, buf, sizeof(buf), &got, nullptr) && got) out.append(buf, got);
        WaitForSingleObject(pi.hProcess, 10000);
        DWORD code = 0;
        GetExitCodeProcess(pi.hProcess, &code);
        std::printf("%-14s exit=0x%08lx %s", "lpac", code, out.empty() ? "(no output)\n" : out.c_str());
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
      }
      if (wr) CloseHandle(wr);
      CloseHandle(rd);
      DeleteProcThreadAttributeList(attrs);
    }
    sb::DeletePackage(kSandboxA);
  } catch (const std::exception& e) {
    std::printf("ERROR: %s\n", e.what());
    return 2;
  }
  return 0;
}

int wmain(int argc, wchar_t** argv) {
  if (argc == 2 && std::wstring(argv[1]) == L"--user32-probe") return User32Probe();
  if (argc == 2 && std::wstring(argv[1]) == L"--user32-restricted") {
    wchar_t me[MAX_PATH]{};
    GetModuleFileNameW(nullptr, me, MAX_PATH);
    return User32Restricted(me);
  }
  if (argc == 2 && std::wstring(argv[1]) == L"--user32") {
    wchar_t me[MAX_PATH]{};
    GetModuleFileNameW(nullptr, me, MAX_PATH);
    return User32Check(me);
  }
  if (argc == 6 && std::wstring(argv[1]) == L"--probe") {
    char a[16]{}, b[16]{}, c[64]{}, d[16]{};
    WideCharToMultiByte(CP_UTF8, 0, argv[2], -1, a, sizeof(a), nullptr, nullptr);
    WideCharToMultiByte(CP_UTF8, 0, argv[3], -1, b, sizeof(b), nullptr, nullptr);
    WideCharToMultiByte(CP_UTF8, 0, argv[4], -1, c, sizeof(c), nullptr, nullptr);
    WideCharToMultiByte(CP_UTF8, 0, argv[5], -1, d, sizeof(d), nullptr, nullptr);
    return Probe(a, b, c, d);
  }
  WSADATA wsa{};
  WSAStartup(MAKEWORD(2, 2), &wsa);
  wchar_t self[MAX_PATH]{};
  GetModuleFileNameW(nullptr, self, MAX_PATH);
  // The AppContainer needs read/execute on our own directory.
  std::wstring dir(self);
  dir = dir.substr(0, dir.find_last_of(L'\\'));

  int failures = 0;
  try {
    auto a = sb::EnsurePackage(kSandboxA);
    auto b = sb::EnsurePackage(kSandboxB);
    for (auto* p : {&a, &b}) {
      sb::GrantPath(dir, p->sid.get(), GENERIC_READ | GENERIC_EXECUTE, true);
      sb::AddLoopbackExemption(p->sid.get());
    }
    std::uint16_t port_a = 0, port_b = 0;
    SOCKET la = Listen(port_a), lb = Listen(port_b);
    UdpCounter(port_a);
    UdpCounter(port_b);
    const in_addr lan = LocalNonLoopbackV4();
    if (lan.s_addr == 0) throw std::runtime_error("no non-loopback IPv4 address for the UDP probe");
    char lan_text[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &lan, lan_text, sizeof(lan_text));
    g_udp_target_ip = lan_text;
    g_udp_target_port = UdpCounter(lan, 0, g_udp_lan_received);
    if (!g_udp_target_port) throw std::runtime_error("cannot bind the non-loopback UDP counter");
    std::thread([la] { for (;;) { SOCKET c = accept(la, nullptr, nullptr); if (c == INVALID_SOCKET) return; closesocket(c); } }).detach();
    std::thread([lb] { for (;;) { SOCKET c = accept(lb, nullptr, nullptr); if (c == INVALID_SOCKET) return; closesocket(c); } }).detach();

    struct Expect { const char* key; bool reachable; };
    const Expect contained[] = {{"own_proxy", true},   {"other_proxy", false}, {"internet_v4", false},
                                {"lan_v4", false},     {"internet_v6", false}, {"loopback_v6", false},
                                {"udp_loopback", false},  {"udp_nonloopback", false}};
    auto report = [&](const char* title, const std::vector<std::pair<std::string, int>>& r, bool enforce) {
      std::printf("\n== %s\n", title);
      for (const auto& [k, v] : r) {
        bool ok = true;
        for (const auto& e : contained)
          if (enforce && k == e.key) ok = (v == 0) == e.reachable;
        if (!ok) ++failures;
        const bool info = k == "system_dns";
        std::printf("  %-18s %-9s %s\n", k.c_str(), v == 0 ? "OPEN" : ("err " + std::to_string(v)).c_str(),
                    enforce ? (info ? "(info)" : ok ? "PASS" : "FAIL") : "(baseline)");
      }
    };

    report("baseline: A without WFP rules", RunProbe(self, a.sid.get(), port_a, port_b), false);

    sb::SandboxFirewall fw;
    fw.Apply(kSandboxA, a.sid.get(), port_a);
    fw.Apply(kSandboxB, b.sid.get(), port_b);
    if (!fw.Verify(kSandboxA) || !fw.Verify(kSandboxB)) {
      std::printf("WFP verify FAILED\n");
      ++failures;
    }
    report("sandbox A with proxy-only rules", RunProbe(self, a.sid.get(), port_a, port_b), true);
    report("sandbox B with proxy-only rules", RunProbe(self, b.sid.get(), port_b, port_a), true);

    // Rule replacement (node switch => new port) must take effect atomically.
    std::uint16_t port_a2 = 0;
    SOCKET la2 = Listen(port_a2);
    UdpCounter(port_a2);
    std::thread([la2] { for (;;) { SOCKET c = accept(la2, nullptr, nullptr); if (c == INVALID_SOCKET) return; closesocket(c); } }).detach();
    fw.Apply(kSandboxA, a.sid.get(), port_a2);
    const auto switched = RunProbe(self, a.sid.get(), port_a2, port_a);
    report("sandbox A after switching to a new proxy port", switched, true);

    fw.Block(kSandboxA, a.sid.get());
    const auto offline = RunProbe(self, a.sid.get(), port_a2, port_b);
    std::printf("\n== sandbox A offline (block all)\n  own_proxy    %s %s\n",
                Lookup(offline, "own_proxy") == 0 ? "OPEN" : "blocked",
                Lookup(offline, "own_proxy") == 0 ? "FAIL" : "PASS");
    if (Lookup(offline, "own_proxy") == 0) ++failures;

    fw.Remove(kSandboxA);
    fw.Remove(kSandboxB);

    // ---- AppId mode: identity = per-sandbox image path (production mode) ----
    const std::wstring dir_a = dir + L"\\appid-a", dir_b = dir + L"\\appid-b";
    CreateDirectoryW(dir_a.c_str(), nullptr);
    CreateDirectoryW(dir_b.c_str(), nullptr);
    const std::wstring exe_a = dir_a + L"\\probe.exe", exe_b = dir_b + L"\\probe.exe";
    if (!CopyFileW(self, exe_a.c_str(), FALSE) || !CopyFileW(self, exe_b.c_str(), FALSE))
      throw sb::Win32Error("CopyFile(probe)", GetLastError());
    // Baseline proves the UDP/TCP probes can succeed when nothing filters them.
    report("AppId baseline: sandbox A image path without rules", RunProbe(exe_a, nullptr, port_a2, port_b), false);
    fw.Apply(kSandboxA, sb::FirewallIdentity::Executable(exe_a), port_a2);
    fw.Apply(kSandboxB, sb::FirewallIdentity::Executable(exe_b), port_b);
    if (!fw.Verify(kSandboxA) || !fw.Verify(kSandboxB)) {
      std::printf("WFP verify (AppId) FAILED\n");
      ++failures;
    }
    report("AppId: sandbox A image path, proxy-only", RunProbe(exe_a, nullptr, port_a2, port_b), true);
    report("AppId: sandbox B image path, proxy-only", RunProbe(exe_b, nullptr, port_b, port_a2), true);
    fw.Remove(kSandboxA);
    fw.Remove(kSandboxB);
    for (auto* p : {&a, &b}) sb::RemoveLoopbackExemption(p->sid.get());
    sb::DeletePackage(kSandboxA);
    sb::DeletePackage(kSandboxB);
  } catch (const std::exception& e) {
    std::printf("ERROR: %s\n", e.what());
    return 2;
  }
  std::printf("\n%s (%d failures)\n", failures ? "FAILED" : "ALL PASSED", failures);
  return failures ? 1 : 0;
}
