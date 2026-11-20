// Developer harness (not shipped): N sandboxes in one window, split exactly
// like the product.
//
//  * Started elevated in the interactive session it plays the Service: it owns
//    the WFP session, one sing-box helper (authenticated HTTP proxy on its own
//    loopback port) per sandbox, and one orangespace::sandbox::SandboxBrowser
//    per opened sandbox - the same code the Service uses.
//  * It starts itself non-elevated (`--ui`) as the client: the window, one
//    container per sandbox, and only the command/event pipe ends that the
//    "Service" duplicated into it. The client never sees proxy credentials.
//    (A browser window cannot be a child of an elevated window - UIPI.)
//
// UI -> agent requests on the UI's stdout, one line each:
//   hello <ui pid>                     -> ok
//   open <sandbox-id> <container hwnd> -> ok <commands handle> <events handle>
//   close <sandbox-id>                 -> ok
//
//   devlaunch.exe C:\path\devlaunch.json
//
// {"runtime":"C:\\os-work\\bh","sing_box":"C:\\os-work\\singbox\\sing-box.exe",
//  "log_dir":"C:\\os-work\\logs","sandbox_root":"C:\\os-work\\sandboxes",
//  "sandboxes":[{"id":"<uuid>","name":"A","start_url":"https://example.com/",
//  "outbound_file":"C:\\os-work\\out-a.json"}]}
#include "appcontainer_win.hpp"
#include "browser_win.hpp"
#include "firewall_win.hpp"
#include "launch_win.hpp"
#include "orangespace/json.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")

namespace sb = orangespace::sandbox;
namespace json = orangespace::json;

namespace {
constexpr UINT kHostEvent = WM_APP + 1;
enum : int { kBack = 10, kForward, kReload, kAddress, kGo, kNewTab, kCloseTab, kTabs, kSandboxBase = 1000 };

std::wstring Wide(const std::string& s) {
  if (s.empty()) return {};
  const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
  std::wstring w(n, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
  return w;
}
std::string Narrow(const std::wstring& w) {
  if (w.empty()) return {};
  const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
  std::string s(n, '\0');
  WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
  return s;
}
std::string Quote(const std::string& s) {
  std::string o = "\"";
  for (char c : s) {
    if (c == '"' || c == '\\') o += '\\';
    if (static_cast<unsigned char>(c) < 0x20) continue;
    o += c;
  }
  return o + "\"";
}
std::string RandomHex(std::size_t bytes) {
  std::vector<unsigned char> b(bytes);
  if (BCryptGenRandom(nullptr, b.data(), static_cast<ULONG>(b.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
    throw std::runtime_error("BCryptGenRandom");
  static constexpr char hex[] = "0123456789abcdef";
  std::string s;
  for (auto c : b) {
    s += hex[c >> 4];
    s += hex[c & 15];
  }
  return s;
}
std::uint16_t FreeLoopbackPort() {
  SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  int len = sizeof(a);
  if (s == INVALID_SOCKET || bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 ||
      getsockname(s, reinterpret_cast<sockaddr*>(&a), &len) != 0)
    throw std::runtime_error("no free port");
  closesocket(s);
  return ntohs(a.sin_port);
}
bool PortOpen(std::uint16_t port) {
  SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  a.sin_port = htons(port);
  const bool ok = connect(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0;
  closesocket(s);
  return ok;
}
std::string ReadLine(HANDLE in, bool& ok) {
  std::string line;
  char c{};
  DWORD got{};
  ok = false;
  while (ReadFile(in, &c, 1, &got, nullptr) && got == 1) {
    if (c == '\n') {
      ok = true;
      return line;
    }
    if (line.size() > 4096) return {};
    line.push_back(c);
  }
  return line;
}

class Log {
 public:
  void open(const std::wstring& path) { out_.open(path, std::ios::app); }
  void line(const std::string& text) {
    std::lock_guard lock(m_);
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    out_ << std::chrono::duration_cast<std::chrono::milliseconds>(now).count() << ' ' << text << '\n';
    out_.flush();
  }

 private:
  std::mutex m_;
  std::ofstream out_;
} g_log;

struct SandboxConfig {
  std::string id, name, start_url, outbound;
};
struct Config {
  std::wstring runtime, sing_box, log_dir, sandbox_root;
  std::vector<SandboxConfig> sandboxes;
} g_config;

bool LoadConfig(const std::wstring& path, std::string& error) {
  std::ifstream f(path, std::ios::binary);
  std::stringstream ss;
  ss << f.rdbuf();
  try {
    const auto v = json::Parser(ss.str()).parse();
    g_config.runtime = Wide(v.find("runtime")->text());
    g_config.sing_box = Wide(v.find("sing_box")->text());
    g_config.log_dir = Wide(v.find("log_dir")->text());
    g_config.sandbox_root = v.find("sandbox_root")
                                ? Wide(v.find("sandbox_root")->text())
                                : (std::filesystem::path(g_config.runtime).parent_path() / L"sandboxes").wstring();
    for (const auto& item : std::get<json::Value::Array>(v.find("sandboxes")->data)) {
      SandboxConfig s;
      s.id = item.find("id")->text();
      s.name = item.find("name")->text();
      s.start_url = item.find("start_url") ? item.find("start_url")->text() : "about:blank";
      s.outbound = item.find("outbound_file") ? item.find("outbound_file")->text() : "";
      g_config.sandboxes.push_back(std::move(s));
    }
    return !g_config.sandboxes.empty();
  } catch (const std::exception& e) {
    error = e.what();
    return false;
  }
}

// ===========================================================================
// Agent (Service role, elevated)
// ===========================================================================
struct Helper {
  sb::LocalProxy proxy;
  sb::UniqueHandle process, job;
};

std::unique_ptr<Helper> StartHelper(const SandboxConfig& s) {
  auto h = std::make_unique<Helper>();
  h->proxy.port = FreeLoopbackPort();
  h->proxy.username = "os-" + s.id.substr(0, 8);
  h->proxy.password = RandomHex(24);
  std::string outbound = R"({"type":"direct","tag":"out"})";
  if (!s.outbound.empty()) {
    std::ifstream f(Wide(s.outbound), std::ios::binary);
    std::stringstream ss;
    ss << f.rdbuf();
    outbound = ss.str();
    if (outbound.empty()) throw std::runtime_error("empty outbound file");
  }
  std::string config = std::string(R"({"log":{"level":"warn"},"inbounds":[{"type":"mixed","tag":"in",)") +
                       R"("listen":"127.0.0.1","listen_port":)" + std::to_string(h->proxy.port) +
                       R"(,"users":[{"username":)" + Quote(h->proxy.username) + R"(,"password":)" +
                       Quote(h->proxy.password) + R"(}],"set_system_proxy":false}],"outbounds":[)" + outbound +
                       R"(],"route":{"final":"out"}})";
  SECURITY_ATTRIBUTES inherit{sizeof(inherit), nullptr, TRUE};
  HANDLE r{}, w{};
  if (!CreatePipe(&r, &w, &inherit, 0)) throw sb::Win32Error("CreatePipe", GetLastError());
  sb::UniqueHandle in_read(r), in_write(w);
  SetHandleInformation(in_write.get(), HANDLE_FLAG_INHERIT, 0);
  const auto log_path = g_config.log_dir + L"\\singbox-" + Wide(s.name) + L".log";
  sb::UniqueHandle log(CreateFileW(log_path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, &inherit, OPEN_ALWAYS,
                                   FILE_ATTRIBUTE_NORMAL, nullptr));
  h->job.reset(CreateJobObjectW(nullptr, nullptr));
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  SetInformationJobObject(h->job.get(), JobObjectExtendedLimitInformation, &limits, sizeof(limits));
  STARTUPINFOW si{sizeof(si)};
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdInput = in_read.get();
  si.hStdOutput = log.get();
  si.hStdError = log.get();
  std::wstring cmd = L"\"" + g_config.sing_box + L"\" run --config stdin";
  PROCESS_INFORMATION pi{};
  if (!CreateProcessW(g_config.sing_box.c_str(), cmd.data(), nullptr, nullptr, TRUE,
                      CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
    throw sb::Win32Error("CreateProcess(sing-box)", GetLastError());
  AssignProcessToJobObject(h->job.get(), pi.hProcess);
  ResumeThread(pi.hThread);
  CloseHandle(pi.hThread);
  h->process.reset(pi.hProcess);
  in_read.reset();
  sb::WriteAll(in_write.get(), config);
  SecureZeroMemory(config.data(), config.size());
  in_write.reset();
  for (int i = 0; i < 100 && !PortOpen(h->proxy.port); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  if (!PortOpen(h->proxy.port)) throw std::runtime_error("helper did not start listening");
  g_log.line(s.name + " helper listening on 127.0.0.1:" + std::to_string(h->proxy.port));
  return h;
}

// Dev stand-in for CreateProcessAsUser(session token): an elevated admin may not
// assign another primary token, so the browser is started by a non-elevated
// stub whose parent is this session's explorer.exe.
sb::BrowserProcess LaunchViaStub(const std::wstring& image) {
  wchar_t self[MAX_PATH]{};
  GetModuleFileNameW(nullptr, self, MAX_PATH);
  DWORD shell_pid = 0;
  GetWindowThreadProcessId(GetShellWindow(), &shell_pid);
  sb::UniqueHandle shell(OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE, FALSE, shell_pid));
  if (!shell) throw sb::Win32Error("OpenProcess(shell)", GetLastError());
  sb::BrowserLaunch launch{self, nullptr, nullptr};
  launch.arguments = L"--spawn none \"" + image + L"\"";
  launch.no_appcontainer = true;
  launch.parent_process = shell.get();
  return sb::LaunchBrowser(launch);
}

int RunAgent(const std::wstring& config_path) {
  g_log.open(g_config.log_dir + L"\\devlaunch-agent.log");
  g_log.line("---- agent start (Service role)");
  try {
    sb::SandboxFirewall firewall;
    std::mutex mutex;  // guards helpers/browsers between the request loop and the monitor
    std::map<std::string, std::unique_ptr<Helper>> helpers;
    std::map<std::string, std::unique_ptr<sb::SandboxBrowser>> browsers;

    wchar_t self[MAX_PATH]{};
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    sb::BrowserProcess ui = [&] {
      DWORD shell_pid = 0;
      GetWindowThreadProcessId(GetShellWindow(), &shell_pid);
      sb::UniqueHandle shell(OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE, FALSE, shell_pid));
      if (!shell) throw sb::Win32Error("OpenProcess(shell)", GetLastError());
      sb::BrowserLaunch launch{self, nullptr, nullptr};
      launch.arguments = L"--spawn none \"" + std::wstring(self) + L"\" --ui \"" + config_path + L"\"";
      launch.no_appcontainer = true;
      launch.parent_process = shell.get();
      return sb::LaunchBrowser(launch);
    }();
    sb::UniqueHandle client;  // the real UI process (behind the stub hops)

    // Helper gone => that sandbox is cut off immediately (block-all), as the
    // Service does when a lease or helper is lost.
    std::atomic<bool> stop{false};
    std::thread monitor([&] {
      while (!stop) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        std::lock_guard lock(mutex);
        for (auto& [id, helper] : helpers) {
          if (!helper->process || WaitForSingleObject(helper->process.get(), 0) != WAIT_OBJECT_0) continue;
          helper->process.reset();
          if (auto it = browsers.find(id); it != browsers.end()) {
            it->second->cut();
            g_log.line("agent: helper of " + id + " exited -> sandbox cut off (WFP block-all)");
          }
        }
        for (auto& [id, browser] : browsers)
          if (browser->running() && !browser->verify()) {
            browser->cut();
            g_log.line("agent: rules of " + id + " changed -> sandbox cut off");
          }
      }
    });

    auto reply = [&](const std::string& text) { sb::WriteAll(ui.to_host.get(), text + "\n"); };
    bool ok = true;
    for (std::string line = ReadLine(ui.from_host.get(), ok); ok; line = ReadLine(ui.from_host.get(), ok)) {
      std::istringstream in(line);
      std::string op, id;
      in >> op;
      try {
        if (op == "hello") {
          DWORD pid = 0;
          in >> pid;
          sb::UniqueHandle h(OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
          BOOL member = FALSE;
          // Only a process of the UI's own Job (i.e. the UI we started) may receive pipes.
          if (!h || !IsProcessInJob(h.get(), ui.job.get(), &member) || !member)
            throw std::runtime_error("hello from a process we did not start");
          client = std::move(h);
          g_log.line("agent: client pid " + std::to_string(pid));
          reply("ok");
          continue;
        }
        in >> id;
        const SandboxConfig* known = nullptr;
        for (const auto& s : g_config.sandboxes)
          if (s.id == id) known = &s;
        if (!known) throw std::runtime_error("unknown sandbox");
        if (op == "open") {
          if (!client) throw std::runtime_error("no client");
          std::uint64_t hwnd = 0;
          in >> hwnd;
          std::lock_guard lock(mutex);
          if (browsers.count(id)) throw std::runtime_error("already open");
          auto helper = StartHelper(*known);
          wchar_t* local = nullptr;
          SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &local);
          const std::wstring profile = std::wstring(local) + L"\\OrangeSpace\\dev\\" + Wide(id) + L"\\profile";
          CoTaskMemFree(local);
          std::filesystem::create_directories(profile);
          sb::BrowserOpen request;
          request.sandbox_id = id;
          request.client_process = client.get();
          request.container_window = hwnd;
          request.shared_runtime = g_config.runtime;
          request.sandbox_root = g_config.sandbox_root;
          request.profile_dir = profile;
          request.start_url = known->start_url;
          request.launch = LaunchViaStub;
          auto browser = std::make_unique<sb::SandboxBrowser>(firewall, request, helper->proxy);
          g_log.line("agent: " + known->name + " image " + Narrow(browser->image()) +
                     ", WFP proxy-only rules for port " + std::to_string(helper->proxy.port) +
                     " verified, browser started, pipes handed to client");
          const auto pipes = browser->pipes();
          helpers[id] = std::move(helper);
          browsers[id] = std::move(browser);
          reply("ok " + std::to_string(pipes.commands) + " " + std::to_string(pipes.events));
        } else if (op == "close") {
          std::lock_guard lock(mutex);
          browsers.erase(id);  // kills the tree, then removes the rules
          helpers.erase(id);
          g_log.line("agent: " + known->name + " closed");
          reply("ok");
        } else {
          throw std::runtime_error("unknown op");
        }
      } catch (const std::exception& e) {
        g_log.line("agent: '" + line.substr(0, 80) + "' -> " + e.what());
        reply(std::string("error ") + e.what());
      }
    }
    stop = true;
    monitor.join();
    {
      std::lock_guard lock(mutex);
      browsers.clear();
      helpers.clear();
    }
    WaitForSingleObject(ui.process.get(), 10000);
    g_log.line("---- agent exit");
  } catch (const std::exception& e) {
    g_log.line(std::string("agent failed: ") + e.what());
    return 3;
  }
  return 0;
}

// ===========================================================================
// UI (client role, not elevated)
// ===========================================================================
struct Tab {
  std::string url, title;
  bool loading{}, back{}, forward{};
};
struct Sandbox {
  const SandboxConfig* config{};
  HWND container{}, button{};
  sb::UniqueHandle commands, events;
  std::map<int, Tab> tabs;
  int active_tab{};
  bool ready{}, closed{};
};
struct Ui {
  HANDLE agent_in{}, agent_out{};
  std::vector<std::unique_ptr<Sandbox>> sandboxes;
  HWND window{}, address{}, tabs{}, status{};
  std::size_t active{};
} g;

std::string AgentCall(const std::string& request) {
  sb::WriteAll(g.agent_out, request + "\n");
  bool ok = false;
  return ReadLine(g.agent_in, ok);
}

void Send(Sandbox& s, const std::string& line) {
  if (!s.commands) return;
  try {
    sb::WriteAll(s.commands.get(), line + "\n");
  } catch (const std::exception& e) {
    g_log.line(s.config->name + " send failed: " + e.what());
  }
}

void Open(Sandbox& s, std::size_t index) {
  const auto reply =
      AgentCall("open " + s.config->id + " " + std::to_string(reinterpret_cast<std::uintptr_t>(s.container)));
  std::istringstream in(reply);
  std::string status;
  std::uint64_t commands = 0, events = 0;
  in >> status >> commands >> events;
  if (status != "ok" || !commands || !events) throw std::runtime_error("agent: " + reply);
  s.commands.reset(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(commands)));
  s.events.reset(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(events)));
  g_log.line(s.config->name + " opened by the agent; holding only command/event pipes");
  HANDLE from = s.events.get();
  std::thread([from, index] {
    bool ok = true;
    for (std::string line = ReadLine(from, ok); ok; line = ReadLine(from, ok))
      PostMessageW(g.window, kHostEvent, index, reinterpret_cast<LPARAM>(new std::string(line)));
    PostMessageW(g.window, kHostEvent, index, reinterpret_cast<LPARAM>(new std::string("{\"ev\":\"pipe_closed\"}")));
  }).detach();
}

Sandbox* Active() { return g.sandboxes.empty() ? nullptr : g.sandboxes[g.active].get(); }

void RefreshTabs() {
  TabCtrl_DeleteAllItems(g.tabs);
  auto* s = Active();
  if (!s) return;
  int i = 0, selected = -1;
  for (auto& [id, t] : s->tabs) {
    std::wstring title = Wide(t.title.empty() ? t.url : t.title);
    if (title.size() > 24) title = title.substr(0, 24) + L"...";
    if (t.loading) title = L"* " + title;
    TCITEMW item{};
    item.mask = TCIF_TEXT | TCIF_PARAM;
    item.pszText = title.data();
    item.lParam = id;
    TabCtrl_InsertItem(g.tabs, i, &item);
    if (id == s->active_tab) selected = i;
    ++i;
  }
  if (selected >= 0) TabCtrl_SetCurSel(g.tabs, selected);
  if (auto it = s->tabs.find(s->active_tab); it != s->tabs.end() && GetFocus() != g.address)
    SetWindowTextW(g.address, Wide(it->second.url).c_str());
}

void Layout() {
  RECT r{};
  GetClientRect(g.window, &r);
  const int w = r.right, h = r.bottom;
  int x = 8;
  for (auto& s : g.sandboxes) {
    MoveWindow(s->button, x, 6, 150, 28, TRUE);
    x += 156;
  }
  MoveWindow(GetDlgItem(g.window, kBack), 8, 40, 32, 28, TRUE);
  MoveWindow(GetDlgItem(g.window, kForward), 44, 40, 32, 28, TRUE);
  MoveWindow(GetDlgItem(g.window, kReload), 80, 40, 32, 28, TRUE);
  MoveWindow(g.address, 118, 42, w - 118 - 220, 24, TRUE);
  MoveWindow(GetDlgItem(g.window, kGo), w - 96 - 120, 40, 60, 28, TRUE);
  MoveWindow(GetDlgItem(g.window, kNewTab), w - 150, 40, 70, 28, TRUE);
  MoveWindow(GetDlgItem(g.window, kCloseTab), w - 76, 40, 68, 28, TRUE);
  MoveWindow(g.tabs, 8, 72, w - 16, 26, TRUE);
  MoveWindow(g.status, 8, h - 22, w - 16, 18, TRUE);
  for (std::size_t i = 0; i < g.sandboxes.size(); ++i) {
    auto& s = *g.sandboxes[i];
    MoveWindow(s.container, 8, 100, w - 16, h - 100 - 26, TRUE);
    ShowWindow(s.container, i == g.active ? SW_SHOW : SW_HIDE);
  }
  if (auto* s = Active()) Send(*s, R"({"op":"resize"})");
}

void Status() {
  auto* s = Active();
  if (!s) return;
  std::wstring text = Wide(s->config->name) + L"  |  WFP: proxy-only (agent)" +
                      (s->closed ? L"  |  browser exited" : s->ready ? L"" : L"  |  starting");
  SetWindowTextW(g.status, text.c_str());
}

void OnHostEvent(std::size_t index, const std::string& line) {
  if (index >= g.sandboxes.size()) return;
  auto& s = *g.sandboxes[index];
  g_log.line(s.config->name + " < " + line);
  try {
    const auto v = json::Parser(line).parse();
    const auto ev = v.find("ev") ? v.find("ev")->text() : "";
    if (ev == "ready") s.ready = true;
    if (ev == "pipe_closed") s.closed = true;
    if (ev == "tab") {
      const int id = static_cast<int>(std::get<double>(v.find("tab")->data));
      auto& t = s.tabs[id];
      t.url = v.find("url")->text();
      t.title = v.find("title")->text();
      t.loading = v.find("loading")->is_true();
      t.back = v.find("back")->is_true();
      t.forward = v.find("forward")->is_true();
      if (v.find("active")->is_true()) s.active_tab = id;
    } else if (ev == "tab_closed") {
      s.tabs.erase(static_cast<int>(std::get<double>(v.find("tab")->data)));
    }
  } catch (...) {
  }
  if (index == g.active) {
    RefreshTabs();
    Status();
  }
}

void Select(std::size_t index) {
  g.active = index;
  Layout();
  RefreshTabs();
  Status();
}

void Shutdown() {
  for (auto& s : g.sandboxes) Send(*s, R"({"op":"shutdown"})");
  std::this_thread::sleep_for(std::chrono::milliseconds(1500));
  for (auto& s : g.sandboxes) {
    s->commands.reset();
    AgentCall("close " + s->config->id);
  }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
  switch (msg) {
    case WM_SIZE: Layout(); return 0;
    case kHostEvent: {
      std::unique_ptr<std::string> line(reinterpret_cast<std::string*>(lp));
      OnHostEvent(static_cast<std::size_t>(wp), *line);
      return 0;
    }
    case WM_NOTIFY:
      if (reinterpret_cast<NMHDR*>(lp)->idFrom == kTabs && reinterpret_cast<NMHDR*>(lp)->code == TCN_SELCHANGE) {
        TCITEMW item{};
        item.mask = TCIF_PARAM;
        if (TabCtrl_GetItem(g.tabs, TabCtrl_GetCurSel(g.tabs), &item) && Active())
          Send(*Active(), R"({"op":"select_tab","tab":)" + std::to_string(item.lParam) + "}");
      }
      return 0;
    case WM_COMMAND: {
      const int id = LOWORD(wp);
      auto* s = Active();
      if (id >= kSandboxBase && id < kSandboxBase + static_cast<int>(g.sandboxes.size())) {
        Select(static_cast<std::size_t>(id - kSandboxBase));
        return 0;
      }
      if (!s) return 0;
      if (id == kBack) Send(*s, R"({"op":"back"})");
      if (id == kForward) Send(*s, R"({"op":"forward"})");
      if (id == kReload) Send(*s, R"({"op":"reload"})");
      if (id == kCloseTab && s->active_tab)
        Send(*s, R"({"op":"close_tab","tab":)" + std::to_string(s->active_tab) + "}");
      if (id == kNewTab) Send(*s, R"({"op":"new_tab","url":"about:blank"})");
      if (id == kGo) {
        wchar_t buffer[4096]{};
        GetWindowTextW(g.address, buffer, 4096);
        std::string url = Narrow(buffer);
        if (url.find("://") == std::string::npos && url != "about:blank") url = "https://" + url;
        Send(*s, R"({"op":"navigate","url":)" + Quote(url) + "}");
      }
      return 0;
    }
    case WM_CLOSE:
      Shutdown();
      DestroyWindow(hwnd);
      return 0;
    case WM_DESTROY: PostQuitMessage(0); return 0;
  }
  return DefWindowProcW(hwnd, msg, wp, lp);
}

int RunUi(HINSTANCE instance, int show) {
  g.agent_in = GetStdHandle(STD_INPUT_HANDLE);
  g.agent_out = GetStdHandle(STD_OUTPUT_HANDLE);
  g_log.open(g_config.log_dir + L"\\devlaunch.log");
  g_log.line("---- UI start (client role), sandboxes=" + std::to_string(g_config.sandboxes.size()));
  if (AgentCall("hello " + std::to_string(GetCurrentProcessId())) != "ok") {
    g_log.line("agent refused hello");
    return 3;
  }
  INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_TAB_CLASSES | ICC_STANDARD_CLASSES};
  InitCommonControlsEx(&icc);
  WNDCLASSW wc{};
  wc.lpfnWndProc = WndProc;
  wc.hInstance = instance;
  wc.lpszClassName = L"OrangeSpaceDevLaunch";
  wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
  wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
  RegisterClassW(&wc);
  g.window = CreateWindowW(wc.lpszClassName, L"OrangeSpace sandbox devlaunch", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                           CW_USEDEFAULT, CW_USEDEFAULT, 1280, 860, nullptr, nullptr, instance, nullptr);
  auto make = [&](const wchar_t* cls, const wchar_t* text, DWORD style, int id) {
    return CreateWindowW(cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 10, 10, g.window,
                         reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), instance, nullptr);
  };
  make(L"BUTTON", L"<", BS_PUSHBUTTON, kBack);
  make(L"BUTTON", L">", BS_PUSHBUTTON, kForward);
  make(L"BUTTON", L"R", BS_PUSHBUTTON, kReload);
  g.address = make(L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL, kAddress);
  make(L"BUTTON", L"Go", BS_DEFPUSHBUTTON, kGo);
  make(L"BUTTON", L"+ Tab", BS_PUSHBUTTON, kNewTab);
  make(L"BUTTON", L"x Tab", BS_PUSHBUTTON, kCloseTab);
  g.tabs = make(WC_TABCONTROLW, L"", 0, kTabs);
  g.status = make(L"STATIC", L"", SS_LEFT, 0);
  for (std::size_t i = 0; i < g_config.sandboxes.size(); ++i) {
    auto s = std::make_unique<Sandbox>();
    s->config = &g_config.sandboxes[i];
    s->button = make(L"BUTTON", Wide("Sandbox " + s->config->name).c_str(), BS_PUSHBUTTON,
                     kSandboxBase + static_cast<int>(i));
    s->container = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_CLIPCHILDREN | SS_BLACKRECT, 0, 0, 10, 10,
                                   g.window, nullptr, instance, nullptr);
    g.sandboxes.push_back(std::move(s));
  }
  ShowWindow(g.window, show);
  Layout();
  UpdateWindow(g.window);
  for (std::size_t i = 0; i < g.sandboxes.size(); ++i) {
    try {
      Open(*g.sandboxes[i], i);
    } catch (const std::exception& e) {
      g_log.line(g.sandboxes[i]->config->name + " open failed: " + e.what());
    }
  }
  Select(0);
  MSG msg;
  while (GetMessageW(&msg, nullptr, 0, 0)) {
    if (msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN && msg.hwnd == g.address) {
      SendMessageW(g.window, WM_COMMAND, kGo, 0);
      continue;
    }
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }
  g_log.line("---- UI exit");
  return 0;
}

// Non-elevated stub: started by the elevated agent with explorer as parent,
// holding the pipes as its std handles. Starts <exe> with a token that is
// entirely the desktop user's, then waits for it.
int SpawnStub(const wchar_t* exe, const std::wstring& extra) {
  HANDLE std_handles[] = {GetStdHandle(STD_INPUT_HANDLE), GetStdHandle(STD_OUTPUT_HANDLE),
                          GetStdHandle(STD_ERROR_HANDLE)};
  SIZE_T size = 0;
  InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
  std::vector<BYTE> storage(size);
  auto* attrs = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
  if (!InitializeProcThreadAttributeList(attrs, 1, 0, &size)) return 91;
  if (!UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, std_handles, sizeof(std_handles),
                                 nullptr, nullptr))
    return 93;
  STARTUPINFOEXW si{};
  si.StartupInfo.cb = sizeof(si);
  si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  si.StartupInfo.hStdInput = std_handles[0];
  si.StartupInfo.hStdOutput = std_handles[1];
  si.StartupInfo.hStdError = std_handles[2];
  si.lpAttributeList = attrs;
  std::wstring command = L"\"" + std::wstring(exe) + L"\"" + extra;
  std::wstring dir(exe);
  dir = dir.substr(0, dir.find_last_of(L'\\'));
  PROCESS_INFORMATION pi{};
  if (!CreateProcessW(exe, command.data(), nullptr, nullptr, TRUE, EXTENDED_STARTUPINFO_PRESENT, nullptr, dir.c_str(),
                      &si.StartupInfo, &pi))
    return 1000 + static_cast<int>(GetLastError());
  DeleteProcThreadAttributeList(attrs);
  CloseHandle(pi.hThread);
  for (HANDLE h : std_handles) CloseHandle(h);  // the owner sees EOF when <exe> exits
  WaitForSingleObject(pi.hProcess, INFINITE);
  DWORD code = 0;
  GetExitCodeProcess(pi.hProcess, &code);
  return static_cast<int>(code);
}

bool Elevated() {
  HANDLE token = nullptr;
  TOKEN_ELEVATION elevation{};
  DWORD len = 0;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
    GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &len);
    CloseHandle(token);
  }
  return elevation.TokenIsElevated != 0;
}
}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, LPWSTR, int show) {
  int argc = 0;
  wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  // "--spawn none <exe> [args...]": first hop. Our token object was created by
  // the elevated agent and is not accessible to us; relaunch once so the second
  // hop's token belongs entirely to the desktop user.
  std::wstring extra;
  for (int i = 4; i < argc; ++i) extra += L" \"" + std::wstring(argv[i]) + L"\"";
  if (argc >= 4 && std::wstring(argv[1]) == L"--spawn") {
    wchar_t self[MAX_PATH]{};
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    std::wstring cmd = L"\"" + std::wstring(self) + L"\" --spawn2 none \"" + argv[3] + L"\"" + extra;
    STARTUPINFOW si{sizeof(si)};
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(self, cmd.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi))
      return 2000 + static_cast<int>(GetLastError());
    CloseHandle(pi.hThread);
    for (HANDLE h : {si.hStdInput, si.hStdOutput, si.hStdError}) CloseHandle(h);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    return static_cast<int>(code);
  }
  if (argc >= 4 && std::wstring(argv[1]) == L"--spawn2") return SpawnStub(argv[3], extra);

  const bool ui = argc == 3 && std::wstring(argv[1]) == L"--ui";
  const std::wstring config_path = argc >= 2 ? argv[ui ? 2 : 1] : L"";
  std::string error;
  if (argc < 2 || !LoadConfig(config_path, error)) {
    MessageBoxW(nullptr, Wide("config error: " + error).c_str(), L"devlaunch", MB_ICONERROR);
    return 2;
  }
  std::filesystem::create_directories(g_config.log_dir);
  WSADATA wsa{};
  WSAStartup(MAKEWORD(2, 2), &wsa);
  if (ui) return RunUi(instance, show);
  if (!Elevated()) {
    MessageBoxW(nullptr, L"Start devlaunch elevated: it plays the Service (WFP) and starts its UI non-elevated.",
                L"devlaunch", MB_ICONERROR);
    return 2;
  }
  return RunAgent(config_path);
}
