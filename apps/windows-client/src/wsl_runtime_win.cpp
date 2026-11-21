#include "orangespace/wsl_runtime.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <vector>

namespace orangespace::wsl {
namespace {
struct Handle {
  HANDLE h{};
  ~Handle() {
    if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
  }
};

std::wstring quote(const std::wstring& arg) {
  // Arguments here are fixed words or absolute paths; refuse anything that
  // would need escaping rather than trying to escape it.
  if (arg.empty() || arg.find(L'"') != std::wstring::npos) throw RuntimeError("invalid wsl.exe argument");
  // wsl.exe parses its own command line and does not accept quoted options
  // ("--import"), so quote only what needs it.
  return arg.find_first_of(L" \t") == std::wstring::npos ? arg : L"\"" + arg + L"\"";
}

// Runs wsl.exe with fixed arguments, no window, and returns its exit code.
DWORD run_wsl(const std::vector<std::wstring>& args, DWORD timeout_ms) {
  const auto exe = wsl_executable();
  if (exe.empty()) throw RuntimeError("WSL is not installed");
  std::wstring command = quote(exe);
  for (const auto& a : args) command += L" " + quote(a);
  STARTUPINFOW si{sizeof(si)};
  PROCESS_INFORMATION pi{};
  if (!CreateProcessW(exe.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si,
                      &pi))
    throw RuntimeError("cannot start wsl.exe");
  Handle process{pi.hProcess}, thread{pi.hThread};
  if (WaitForSingleObject(pi.hProcess, timeout_ms) != WAIT_OBJECT_0) {
    TerminateProcess(pi.hProcess, 1);
    throw RuntimeError("wsl.exe timed out");
  }
  DWORD code = 1;
  GetExitCodeProcess(pi.hProcess, &code);
  return code;
}

bool tick_passed(DWORD deadline) { return static_cast<LONG>(GetTickCount() - deadline) >= 0; }
}  // namespace

std::wstring wsl_executable() {
  std::array<wchar_t, MAX_PATH> dir{};
  const UINT n = GetSystemDirectoryW(dir.data(), static_cast<UINT>(dir.size()));
  if (!n || n >= dir.size()) return {};
  std::wstring path(dir.data(), n);
  path += L"\\wsl.exe";
  const DWORD attrs = GetFileAttributesW(path.c_str());
  return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY) ? path : std::wstring{};
}

bool distribution_registered() {
  HKEY lxss{};
  if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Lxss", 0,
                    KEY_READ, &lxss) != ERROR_SUCCESS)
    return false;
  bool found = false;
  for (DWORD i = 0; !found; ++i) {
    wchar_t name[64]{};
    DWORD name_len = 64;
    if (RegEnumKeyExW(lxss, i, name, &name_len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
    wchar_t value[256]{};
    DWORD bytes = sizeof(value) - sizeof(wchar_t);
    if (RegGetValueW(lxss, name, L"DistributionName", RRF_RT_REG_SZ, nullptr, value, &bytes) == ERROR_SUCCESS)
      found = _wcsicmp(value, kDistribution) == 0;
  }
  RegCloseKey(lxss);
  return found;
}

void import_distribution(const std::wstring& rootfs, const std::wstring& install_dir) {
  if (distribution_registered()) throw RuntimeError("the OrangeSpace distribution is already registered");
  // wsl --import needs the parent directories to exist.
  std::error_code ec;
  std::filesystem::create_directories(install_dir, ec);
  if (ec) throw RuntimeError("cannot create the distribution directory");
  if (run_wsl({L"--import", kDistribution, install_dir, rootfs, L"--version", L"2"}, 30 * 60 * 1000) != 0 ||
      !distribution_registered())
    throw RuntimeError("wsl --import failed");
}

void terminate_distribution() { (void)run_wsl({L"--terminate", kDistribution}, 60000); }

void unregister_distribution() {
  if (run_wsl({L"--unregister", kDistribution}, 10 * 60 * 1000) != 0) throw RuntimeError("wsl --unregister failed");
}

Agent::Agent(DWORD start_timeout_ms) {
  const auto exe = wsl_executable();
  if (exe.empty()) throw RuntimeError("WSL is not installed");
  if (!distribution_registered()) throw RuntimeError("the OrangeSpace distribution is not installed");
  SECURITY_ATTRIBUTES inherit{sizeof(inherit), nullptr, TRUE};
  Handle in_read, in_write, out_read, out_write, err;
  if (!CreatePipe(&in_read.h, &in_write.h, &inherit, 0) || !CreatePipe(&out_read.h, &out_write.h, &inherit, 0))
    throw RuntimeError("cannot create agent pipes");
  SetHandleInformation(in_write.h, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(out_read.h, HANDLE_FLAG_INHERIT, 0);
  err.h = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_WRITE, &inherit, OPEN_EXISTING, 0, nullptr);

  // Only these three handles are inherited.
  SIZE_T size = 0;
  InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
  std::vector<unsigned char> storage(size);
  auto* attrs = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
  if (!InitializeProcThreadAttributeList(attrs, 1, 0, &size)) throw RuntimeError("cannot prepare agent start");
  HANDLE handles[] = {in_read.h, out_write.h, err.h};
  UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, sizeof(handles), nullptr, nullptr);
  STARTUPINFOEXW si{};
  si.StartupInfo.cb = sizeof(si);
  si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  si.StartupInfo.hStdInput = in_read.h;
  si.StartupInfo.hStdOutput = out_write.h;
  si.StartupInfo.hStdError = err.h;
  si.lpAttributeList = attrs;
  std::wstring command = quote(exe) + L" -d " + std::wstring(kDistribution) +
                         L" -u root --cd / -- /usr/bin/python3 /opt/orangespace/wsl/agent.py";
  PROCESS_INFORMATION pi{};
  const BOOL started = CreateProcessW(exe.c_str(), command.data(), nullptr, nullptr, TRUE,
                                      CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
                                      &si.StartupInfo, &pi);
  DeleteProcThreadAttributeList(attrs);
  if (!started) throw RuntimeError("cannot start the WSL agent");
  CloseHandle(pi.hThread);
  process_ = pi.hProcess;
  pid_ = pi.dwProcessId;
  to_agent_ = in_write.h;
  in_write.h = nullptr;
  from_agent_ = out_read.h;
  out_read.h = nullptr;
  try {
    read_marker(GetTickCount() + start_timeout_ms);  // first boot can take a while
  } catch (...) {
    shutdown();
    throw;
  }
  reader_thread_ = std::thread([this] { read_replies(); });
}

Agent::~Agent() { shutdown(); }

bool Agent::running() const noexcept { return process_ && WaitForSingleObject(process_, 0) == WAIT_TIMEOUT; }

void Agent::read_marker(DWORD deadline) {
  while (!reader_.synced()) {
    DWORD available = 0;
    if (!PeekNamedPipe(from_agent_, nullptr, 0, nullptr, &available, nullptr))
      throw RuntimeError("the WSL agent exited");
    if (available) {
      // Read only what is there: never block past the deadline.
      std::array<char, 16384> buffer{};
      DWORD got = 0;
      if (!ReadFile(from_agent_, buffer.data(), static_cast<DWORD>((std::min<std::size_t>)(available, buffer.size())),
                    &got, nullptr) ||
          !got)
        throw RuntimeError("the WSL agent exited");
      reader_.feed(buffer.data(), got);
      continue;
    }
    if (tick_passed(deadline)) throw RuntimeError("the WSL agent did not start");
    Sleep(10);
  }
}

void Agent::read_replies() noexcept {
  try {
    for (;;) {
      while (auto reply = reader_.next()) {
        std::lock_guard lock(mutex_);
        if (waiting_.count(reply->number)) {
          replies_[reply->number] = std::move(reply->payload);
          replied_.notify_all();
        }
      }
      std::array<char, 16384> buffer{};
      DWORD got = 0;
      if (!ReadFile(from_agent_, buffer.data(), static_cast<DWORD>(buffer.size()), &got, nullptr) || !got) break;
      reader_.feed(buffer.data(), got);
    }
  } catch (...) {
    // A malformed frame ends the channel like an exit does.
  }
  std::lock_guard lock(mutex_);
  closed_ = true;
  replied_.notify_all();
}

std::string Agent::request(std::string_view json, DWORD timeout_ms) {
  std::uint32_t number = 0;
  {
    std::lock_guard lock(mutex_);
    if (closed_ || !process_) throw RuntimeError("the WSL agent is not running");
    number = next_++;
    if (next_ == 0) next_ = 1;
    waiting_.insert(number);
  }
  const auto forget = [&] {
    std::lock_guard lock(mutex_);
    waiting_.erase(number);
    replies_.erase(number);
  };
  try {
    const auto frame = request_frame(number, json);
    std::lock_guard write(write_mutex_);
    DWORD wrote = 0;
    if (!to_agent_ || !WriteFile(to_agent_, frame.data(), static_cast<DWORD>(frame.size()), &wrote, nullptr) ||
        wrote != frame.size())
      throw RuntimeError("cannot write to the WSL agent");
  } catch (...) {
    forget();
    throw;
  }
  std::unique_lock lock(mutex_);
  const bool answered = replied_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                                          [&] { return replies_.count(number) || closed_; });
  auto found = replies_.find(number);
  if (!answered || found == replies_.end()) {
    waiting_.erase(number);
    throw RuntimeError(closed_ ? "the WSL agent exited" : "the WSL agent did not answer");
  }
  std::string reply = std::move(found->second);
  replies_.erase(found);
  waiting_.erase(number);
  return reply;
}

void Agent::shutdown() noexcept {
  if (!process_) return;
  try {
    if (running() && reader_thread_.joinable()) (void)request(R"({"op":"shutdown"})", 10000);
  } catch (...) {
  }
  {
    std::lock_guard write(write_mutex_);
    if (to_agent_) CloseHandle(to_agent_);  // EOF also ends the agent
    to_agent_ = nullptr;
  }
  if (WaitForSingleObject(process_, 15000) != WAIT_OBJECT_0) TerminateProcess(process_, 1);
  // wsl.exe has exited, so the pipe's write end is gone and the reader sees EOF.
  if (reader_thread_.joinable()) {
    if (WaitForSingleObject(process_, 5000) == WAIT_OBJECT_0) CancelSynchronousIo(reader_thread_.native_handle());
    reader_thread_.join();
  }
  if (from_agent_) CloseHandle(from_agent_);
  from_agent_ = nullptr;
  CloseHandle(process_);
  process_ = nullptr;
  std::lock_guard lock(mutex_);
  closed_ = true;
  replied_.notify_all();
}

}  // namespace orangespace::wsl
