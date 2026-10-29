#include "orangespace/broker_win.hpp"
#include "orangespace/model.hpp"

#ifdef _WIN32
#include <array>
#include <memory>
#include <stdexcept>

namespace orangespace {
namespace {
class Handle {
 public:
  explicit Handle(HANDLE value = nullptr) : value_(value) {}
  ~Handle() { if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_); }
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  HANDLE get() const { return value_; }
  void reset(HANDLE value = nullptr) {
    if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_);
    value_ = value;
  }
 private:
  HANDLE value_;
};
std::wstring failure_text(std::wstring_view action) {
  return std::wstring(action) + L"（Windows 错误 " + std::to_wstring(GetLastError()) + L"）";
}
}  // namespace

std::wstring widen(const std::string& input) {
  if (input.empty()) return {};
  const auto count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()), nullptr, 0);
  if (!count) throw std::runtime_error("broker returned invalid UTF-8");
  std::wstring result(count, L'\0');
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()), result.data(), count);
  return result;
}
std::string narrow(const std::wstring& input) {
  if (input.empty()) return {};
  const auto count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()), nullptr, 0, nullptr, nullptr);
  if (!count) throw std::runtime_error("invalid Unicode input");
  std::string result(count, '\0');
  WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()), result.data(), count, nullptr, nullptr);
  return result;
}
std::wstring module_directory() {
  std::wstring path(32768, L'\0');
  const auto size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
  if (!size || size == path.size()) throw std::runtime_error("cannot locate OrangeSpace executable");
  path.resize(size);
  return std::filesystem::path(path).parent_path().wstring();
}

ProcessResult run_broker(const std::vector<std::wstring>& arguments) {
  ProcessResult result;
  const auto directory = module_directory();
  const auto executable = directory + L"\\orangespace-broker.exe";
  if (GetFileAttributesW(executable.c_str()) == INVALID_FILE_ATTRIBUTES) {
    result.failure = L"找不到 orangespace-broker.exe，请将它放在 OrangeSpace.exe 同一目录。";
    return result;
  }
  std::wstring command = quote_argument(executable);
  for (const auto& argument : arguments) command += L" " + quote_argument(argument);

  SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
  HANDLE raw_read{}, raw_write{};
  if (!CreatePipe(&raw_read, &raw_write, &security, 0)) {
    result.failure = failure_text(L"无法建立组件通信"); return result;
  }
  Handle pipe_read(raw_read), pipe_write(raw_write);
  if (!SetHandleInformation(pipe_read.get(), HANDLE_FLAG_INHERIT, 0)) {
    result.failure = failure_text(L"无法保护通信句柄"); return result;
  }
  Handle input(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
  if (input.get() == INVALID_HANDLE_VALUE) {
    result.failure = failure_text(L"无法初始化组件输入"); return result;
  }
  Handle job(CreateJobObjectW(nullptr, nullptr));
  if (!job.get()) { result.failure = failure_text(L"无法建立组件任务"); return result; }
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (!SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
    result.failure = failure_text(L"无法保护组件生命周期"); return result;
  }

  SIZE_T bytes{};
  InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
  auto attributes = std::make_unique<std::byte[]>(bytes);
  auto* list = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(attributes.get());
  if (!InitializeProcThreadAttributeList(list, 1, 0, &bytes)) {
    result.failure = failure_text(L"无法初始化进程属性"); return result;
  }
  struct AttributeCleanup {
    PPROC_THREAD_ATTRIBUTE_LIST list;
    ~AttributeCleanup() { DeleteProcThreadAttributeList(list); }
  } cleanup{list};
  HANDLE inherited[] = {pipe_write.get(), input.get()};
  if (!UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited,
                                 sizeof(inherited), nullptr, nullptr)) {
    result.failure = failure_text(L"无法限制组件句柄"); return result;
  }
  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = sizeof(startup);
  startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  startup.StartupInfo.hStdInput = input.get();
  startup.StartupInfo.hStdOutput = pipe_write.get();
  startup.StartupInfo.hStdError = pipe_write.get();
  startup.lpAttributeList = list;
  PROCESS_INFORMATION process_info{};
  if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE,
                       CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                       nullptr, directory.c_str(), &startup.StartupInfo, &process_info)) {
    result.failure = failure_text(L"无法启动组件"); return result;
  }
  Handle process(process_info.hProcess), thread(process_info.hThread);
  if (!AssignProcessToJobObject(job.get(), process.get())) {
    TerminateProcess(process.get(), 1);
    result.failure = failure_text(L"无法绑定组件任务"); return result;
  }
  pipe_write.reset();
  if (ResumeThread(thread.get()) == static_cast<DWORD>(-1)) {
    result.failure = failure_text(L"无法运行组件"); return result;
  }
  const auto deadline = GetTickCount64() + 15000;
  std::array<char, 8192> buffer{};
  for (;;) {
    DWORD available{};
    if (PeekNamedPipe(pipe_read.get(), nullptr, 0, nullptr, &available, nullptr) && available) {
      DWORD received{};
      if (!ReadFile(pipe_read.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &received, nullptr)) break;
      result.output.append(buffer.data(), received);
      if (result.output.size() > 1024 * 1024) {
        result.failure = L"组件响应超过大小限制。"; return result;
      }
      continue;
    }
    const auto state = WaitForSingleObject(process.get(), 10);
    if (state == WAIT_OBJECT_0) {
      DWORD tail{};
      if (PeekNamedPipe(pipe_read.get(), nullptr, 0, nullptr, &tail, nullptr) && tail) continue;
      break;
    }
    if (state == WAIT_FAILED) { result.failure = failure_text(L"组件状态读取失败"); return result; }
    if (GetTickCount64() >= deadline) { result.failure = L"组件响应超时，已终止此次操作。"; return result; }
  }
  if (!GetExitCodeProcess(process.get(), &result.exit_code)) result.failure = failure_text(L"组件返回状态读取失败");
  return result;
}
}  // namespace orangespace
#endif
