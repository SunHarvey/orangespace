#include "browser_win.hpp"

#include "appcontainer_win.hpp"
#include "host_protocol.hpp"
#include "runtime_win.hpp"

#include <chrono>
#include <thread>

namespace orangespace::sandbox {
namespace {
std::string Utf8(const std::wstring& w) {
  if (w.empty()) return {};
  const int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w.data(), static_cast<int>(w.size()), nullptr, 0,
                                    nullptr, nullptr);
  if (n <= 0) throw std::runtime_error("path is not valid UTF-16");
  std::string out(static_cast<std::size_t>(n), '\0');
  WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w.data(), static_cast<int>(w.size()), out.data(), n, nullptr,
                      nullptr);
  return out;
}

std::uint64_t DuplicateInto(HANDLE target_process, HANDLE handle) {
  HANDLE copy = nullptr;
  if (!DuplicateHandle(GetCurrentProcess(), handle, target_process, &copy, 0, FALSE, DUPLICATE_SAME_ACCESS))
    throw Win32Error("DuplicateHandle(client pipe)", GetLastError());
  return reinterpret_cast<std::uintptr_t>(copy);
}

// Closes a handle we duplicated into the client if the open fails afterwards.
void CloseInClient(HANDLE client, std::uint64_t value) noexcept {
  if (!value) return;
  HANDLE ignored = nullptr;
  DuplicateHandle(client, reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(value)), GetCurrentProcess(), &ignored,
                  0, FALSE, DUPLICATE_CLOSE_SOURCE);
  if (ignored) CloseHandle(ignored);
}

void KillTree(BrowserProcess& p) noexcept {
  if (p.job) {
    TerminateJobObject(p.job.get(), 1);
    // Rules may only go once no process of this sandbox is left.
    for (int i = 0; i < 100; ++i) {
      JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info{};
      if (!QueryInformationJobObject(p.job.get(), JobObjectBasicAccountingInformation, &info, sizeof(info), nullptr) ||
          info.ActiveProcesses == 0)
        break;
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
  }
  if (p.process) WaitForSingleObject(p.process.get(), 5000);
  p.to_host.reset();
  p.from_host.reset();
  p.job.reset();
}
}  // namespace

BrowserLauncher LaunchAsUser(HANDLE user_token) {
  if (!user_token) throw std::invalid_argument("user token required");
  return [user_token](const std::wstring& executable) {
    BrowserLaunch spec{executable, nullptr, user_token};
    spec.no_appcontainer = true;  // identity is the per-sandbox image path (WFP AppId)
    return LaunchBrowser(spec);
  };
}

void RequireClientWindow(std::uint64_t window, DWORD client_pid) {
  const HWND hwnd = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(window));
  DWORD owner = 0;
  if (!window || !IsWindow(hwnd) || !GetWindowThreadProcessId(hwnd, &owner) || owner == 0 || owner != client_pid)
    throw std::runtime_error("container window is not owned by the requesting client");
}

SandboxBrowser::SandboxBrowser(SandboxFirewall& firewall, const BrowserOpen& request, const LocalProxy& proxy)
    : firewall_(firewall), sandbox_id_(request.sandbox_id) {
  if (!browserhost::canonical_uuid(request.sandbox_id) || !request.client_process || !request.launch ||
      request.shared_runtime.empty() || request.sandbox_root.empty() || request.profile_dir.empty() ||
      proxy.port < 1024)
    throw std::invalid_argument("browser open request");
  RequireClientWindow(request.container_window, GetProcessId(request.client_process));

  image_ = PrepareSandboxRuntime(request.shared_runtime,
                                 request.sandbox_root + L"\\" + std::wstring(sandbox_id_.begin(), sandbox_id_.end()));
  const auto who = FirewallIdentity::Executable(image_);
  firewall_.Apply(sandbox_id_, who, proxy.port);
  try {
    if (!firewall_.Verify(sandbox_id_)) throw std::runtime_error("WFP rules did not read back");
    process_ = request.launch(image_);

    browserhost::Config config;
    config.sandbox_id = sandbox_id_;
    config.parent_window = request.container_window;
    config.proxy_port = proxy.port;
    config.proxy_username = proxy.username;
    config.proxy_password = proxy.password;
    config.profile_dir = Utf8(request.profile_dir);
    config.start_url = request.start_url;
    std::string line = browserhost::config_line(config);
    SecureZeroMemory(config.proxy_password.data(), config.proxy_password.size());
    try {
      WriteAll(process_.to_host.get(), line);
    } catch (...) {
      SecureZeroMemory(line.data(), line.size());
      throw;
    }
    SecureZeroMemory(line.data(), line.size());

    pipes_.commands = DuplicateInto(request.client_process, process_.to_host.get());
    try {
      pipes_.events = DuplicateInto(request.client_process, process_.from_host.get());
    } catch (...) {
      CloseInClient(request.client_process, pipes_.commands);
      pipes_ = {};
      throw;
    }
    // From here only the client talks to the browser.
    process_.to_host.reset();
    process_.from_host.reset();
  } catch (...) {
    KillTree(process_);
    firewall_.Remove(sandbox_id_);
    throw;
  }
}

SandboxBrowser::~SandboxBrowser() {
  KillTree(process_);
  try {
    firewall_.Remove(sandbox_id_);
  } catch (...) {
  }
}

bool SandboxBrowser::running() const {
  return process_.process && WaitForSingleObject(process_.process.get(), 0) == WAIT_TIMEOUT;
}

bool SandboxBrowser::verify() { return firewall_.Verify(sandbox_id_); }

void SandboxBrowser::cut() noexcept {
  try {
    firewall_.Block(sandbox_id_, FirewallIdentity::Executable(image_));
    return;
  } catch (...) {
  }
  // Could not switch to block-all: do not leave a browser with unknown rules.
  if (process_.job) TerminateJobObject(process_.job.get(), 1);
}

}  // namespace orangespace::sandbox
