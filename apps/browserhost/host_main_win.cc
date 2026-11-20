// OrangeSpace BrowserHost entry point. Loaded by the official CEF bootstrap
// (osbrowser.exe -> osbrowser.dll). One process tree per sandbox; the Service
// starts it inside that sandbox's AppContainer and Job and owns its pipes.
#include "bootstrap_policy.hpp"
#include "cef_pin.hpp"
#include "host_client_win.hpp"
#include "host_protocol.hpp"

#include "include/base/cef_callback.h"
#include "include/cef_api_hash.h"
#include "include/cef_command_line.h"
#include "include/cef_sandbox_win.h"
#include "include/wrapper/cef_closure_task.h"
#include "include/wrapper/cef_library_loader.h"
#include "include/wrapper/cef_util_win.h"

#include <windows.h>

#include <memory>
#include <string>
#include <thread>
#include <type_traits>

namespace orangespace::cef_host {
static_assert(CEF_API_VERSION == pin::api_version);
static_assert(std::string_view(CEF_VERSION) == pin::version);
static_assert(std::string_view(CEF_COMMIT_HASH) == pin::commit);
static_assert(std::string_view(CEF_API_HASH_PLATFORM) == pin::api_hash);
static_assert(std::string_view(CEF_SANDBOX_COMPAT_HASH) == pin::sandbox_hash);
}  // namespace orangespace::cef_host

namespace {
using namespace orangespace::browserhost;
namespace host = orangespace::cef_host;

enum ExitCode : int {
  kOk = 0,
  kBadConfig = 60,
  kBadProfile = 61,
  kBadParent = 62,
  kInitFailed = 63,
  kForbiddenSwitch = 64,
  kLibraryLoadBase = 0x10000,  // + Win32 error of LoadLibraryEx(libcef.dll)
};

host::BootstrapVersion Snapshot(const cef_version_info_t& info) {
  return {{{info.cef_version_major, info.cef_version_minor, info.cef_version_patch, info.cef_commit_number,
            info.chrome_version_major, info.chrome_version_minor, info.chrome_version_build,
            info.chrome_version_patch}},
          std::string_view(info.sandbox_compat_hash, 16)};
}

std::wstring Wide(const std::string& s) {
  if (s.empty()) return {};
  const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
  std::wstring out(n > 0 ? n : 0, L'\0');
  if (n > 0) MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), out.data(), n);
  return out;
}

// Reads one '\n'-terminated line. Returns false on EOF/error/oversize.
bool ReadLine(HANDLE in, std::string& line) {
  line.clear();
  char c{};
  DWORD got{};
  while (ReadFile(in, &c, 1, &got, nullptr) && got == 1) {
    if (c == '\n') {
      if (!line.empty() && line.back() == '\r') line.pop_back();
      return true;
    }
    if (line.size() >= kMaxLine) return false;
    line.push_back(c);
  }
  return false;
}

bool IsDirectory(const std::wstring& path) {
  const DWORD a = GetFileAttributesW(path.c_str());
  return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) && !(a & FILE_ATTRIBUTE_REPARSE_POINT);
}

void Wipe(std::string& s) {
  SecureZeroMemory(s.data(), s.size());
  s.clear();
}
}  // namespace

// C linkage, cdecl ABI required by the official bootstrap.
CEF_BOOTSTRAP_EXPORT int RunWinMain(HINSTANCE instance, LPWSTR, int, void* sandbox_info,
                                   cef_version_info_t* version_info) {
  if (!sandbox_info) return static_cast<int>(host::StartupResult::invalid_sandbox);
  if (!version_info || version_info->size != sizeof(cef_version_info_t) ||
      version_info->sandbox_compat_hash[16] != '\0')
    return static_cast<int>(host::StartupResult::invalid_bootstrap);
  cef_version_info_t expected_info = {};
  CEF_POPULATE_VERSION_INFO(&expected_info);
  const auto expected = Snapshot(expected_info);
  const auto actual = Snapshot(*version_info);
  if (auto r = host::CheckBootstrap(sandbox_info, &actual, expected); r != host::StartupResult::compatible)
    return static_cast<int>(r);
  // Runtime must sit next to the executable; no installer/CDN/machine-wide lookup.
  if (version_info->installer_error_code || version_info->libcef_path)
    return static_cast<int>(host::StartupResult::invalid_bootstrap);

  CefScopedLibraryLoader loader;
  {
    cef::logging::ScopedEarlySupport early_logging({});
    const auto exe = cef_util::GetExePath();
    const auto slash = exe.find_last_of(L"/\\");
    if (slash == std::wstring::npos) return static_cast<int>(host::StartupResult::invalid_runtime);
    const std::wstring library = exe.substr(0, slash + 1) + L"libcef.dll";
    // LoadInMainAssert terminates with a breakpoint (before any logging exists)
    // if the library cannot be loaded. Probe first so a sandboxed child that
    // cannot read the runtime exits with a recognisable code instead; the
    // browser process logs child exit codes.
    if (HMODULE probe = LoadLibraryExW(library.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH)) {
      FreeLibrary(probe);
    } else {
      return kLibraryLoadBase + static_cast<int>(GetLastError() & 0xFFFF);
    }
    // The official minimal libcef.dll is not Authenticode-signed. The Service
    // verifies the SHA-256 of the installed runtime before starting us.
    if (!loader.LoadInMainAssert(library.c_str(), nullptr, true, &expected_info))
      return static_cast<int>(host::StartupResult::invalid_runtime);
  }
  if (auto r = host::CheckRuntime(cef_api_hash(CEF_API_VERSION, 0), cef_api_hash(CEF_API_VERSION, 2),
                                  cef_api_hash(CEF_API_VERSION, 3), cef_version_full(),
                                  {host::pin::api_hash, host::pin::commit, host::pin::sandbox_hash,
                                   host::pin::version});
      r != host::StartupResult::compatible)
    return static_cast<int>(r);

  auto command_line = CefCommandLine::CreateCommandLine();
  command_line->InitFromString(GetCommandLineW());
  for (const char* forbidden :
       {"no-sandbox", "disable-gpu-sandbox", "single-process", "in-process-gpu", "proxy-server", "no-proxy-server",
        "proxy-pac-url", "proxy-auto-detect", "remote-debugging-port", "remote-debugging-pipe"}) {
    if (command_line->HasSwitch(forbidden)) return kForbiddenSwitch;
  }
  CefMainArgs args(instance);
  const bool browser_process = !command_line->HasSwitch("type");
  if (!browser_process) {
    CefRefPtr<CefApp> sub_app = new HostApp(nullptr, nullptr);
    return CefExecuteProcess(args, sub_app, sandbox_info);
  }
  // The browser process must have been started with an explicit command line
  // (switches above were rejected) and owner pipes on stdin/stdout.
  const HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
  const HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
  if (!in || in == INVALID_HANDLE_VALUE || !out || out == INVALID_HANDLE_VALUE) return kBadConfig;
  EventSink events(out);

  std::string line, error;
  if (!ReadLine(in, line)) return kBadConfig;
  auto parsed = parse_config(line, error);
  Wipe(line);
  if (!parsed) {
    events.send(error_event(error));
    return kBadConfig;
  }
  const Config config = std::move(*parsed);
  const std::wstring profile = Wide(config.profile_dir);
  if (!IsDirectory(profile)) {
    events.send(error_event("profile directory missing"));
    return kBadProfile;
  }
  const HWND parent = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(config.parent_window));
  if (!IsWindow(parent)) {
    events.send(error_event("parent window missing"));
    return kBadParent;
  }

  CefRefPtr<HostClient> client = new HostClient(config, events);
  CefRefPtr<CefApp> app = new HostApp(&config, [client, &events, url = config.start_url] {
    events.send(simple_event("ready"));
    client->OpenTab(url);
  });
  CefSettings settings;
  settings.no_sandbox = false;
  settings.command_line_args_disabled = true;
  settings.persist_session_cookies = true;
  settings.multi_threaded_message_loop = false;
  CefString(&settings.root_cache_path) = profile;
  CefString(&settings.cache_path) = profile + L"\\Default";
  CefString(&settings.log_file) = profile + L"\\browserhost.log";
  settings.log_severity = LOGSEVERITY_WARNING;
  if (!CefInitialize(args, settings, app, sandbox_info)) {
    events.send(error_event("cef initialize failed"));
    return kInitFailed;
  }

  // Owner commands arrive on stdin; EOF (owner or Service gone) closes everything.
  std::thread([in, client, &events] {
    std::string text, err;
    while (ReadLine(in, text)) {
      auto command = parse_command(text, err);
      if (!command) {
        events.send(error_event(err));
        continue;
      }
      CefPostTask(TID_UI, base::BindOnce(&HostClient::Execute, client, *command));
      if (command->op == Op::shutdown) return;
    }
    CefPostTask(TID_UI, base::BindOnce(&HostClient::CloseAll, client));
  }).detach();

  CefRunMessageLoop();
  events.send(simple_event("closed"));
  CefShutdown();
  // Do not return through stack unwinding of the detached reader; exit now.
  ExitProcess(kOk);
}

using BootstrapEntry = int (*)(HINSTANCE, LPWSTR, int, void*, cef_version_info_t*);
static_assert(std::is_same_v<decltype(&RunWinMain), BootstrapEntry>);
