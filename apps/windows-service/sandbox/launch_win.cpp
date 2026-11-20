#include "launch_win.hpp"

#include "appcontainer_win.hpp"

#include <userenv.h>

#include <algorithm>
#include <functional>
#include <vector>

namespace orangespace::sandbox {
namespace {
void Pipe(UniqueHandle& read, UniqueHandle& write) {
  HANDLE r{}, w{};
  if (!CreatePipe(&r, &w, nullptr, 64 * 1024)) throw Win32Error("CreatePipe", GetLastError());
  read.reset(r);
  write.reset(w);
}
void Inheritable(HANDLE h) {
  if (!SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
    throw Win32Error("SetHandleInformation", GetLastError());
}
}  // namespace

void WriteAll(HANDLE pipe, const std::string& data) {
  std::size_t done = 0;
  while (done < data.size()) {
    DWORD wrote = 0;
    const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(data.size() - done, 64 * 1024));
    if (!WriteFile(pipe, data.data() + done, chunk, &wrote, nullptr) || wrote == 0)
      throw Win32Error("WriteFile(pipe)", GetLastError());
    done += wrote;
  }
}

BrowserProcess LaunchBrowser(const BrowserLaunch& spec) {
  if (spec.executable.empty() || (!spec.package_sid && !spec.no_appcontainer)) throw std::invalid_argument("launch spec");
  BrowserProcess out;

  // stdin: host reads, we write. stdout: host writes, we read.
  UniqueHandle in_read, in_write, out_read, out_write;
  Pipe(in_read, in_write);
  Pipe(out_read, out_write);
  Inheritable(in_read.get());
  Inheritable(out_write.get());
  SECURITY_ATTRIBUTES inherit{sizeof(inherit), nullptr, TRUE};
  UniqueHandle null_err(CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_WRITE, &inherit, OPEN_EXISTING, 0, nullptr));
  if (!null_err) throw Win32Error("CreateFile(NUL)", GetLastError());

  // Job first, so the process is a member from its first instruction.
  out.job.reset(CreateJobObjectW(nullptr, nullptr));
  if (!out.job) throw Win32Error("CreateJobObject", GetLastError());
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
  if (!SetInformationJobObject(out.job.get(), JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
    throw Win32Error("SetInformationJobObject", GetLastError());

  SECURITY_CAPABILITIES caps{};
  caps.AppContainerSid = static_cast<PSID>(spec.package_sid);
  caps.Capabilities = nullptr;  // no internetClient, no privateNetwork: loopback only (via exemption)
  caps.CapabilityCount = 0;
  HANDLE err = spec.stderr_handle ? spec.stderr_handle : null_err.get();
  HANDLE inherited[] = {in_read.get(), out_write.get(), err};
  HANDLE jobs[] = {out.job.get()};

  // With a substitute parent, inherited handles are taken from that process:
  // place inheritable copies there for the duration of CreateProcess.
  HANDLE parent = spec.parent_process;
  auto close_in_parent = [&] {
    if (!parent) return;
    for (HANDLE h : inherited)
      if (h) DuplicateHandle(parent, h, nullptr, nullptr, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
  };
  if (parent) {
    for (HANDLE& h : inherited) {
      HANDLE copy = nullptr;
      if (!DuplicateHandle(GetCurrentProcess(), h, parent, &copy, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
        const DWORD e = GetLastError();
        close_in_parent();
        throw Win32Error("DuplicateHandle(to parent)", e);
      }
      h = copy;
    }
  }
  struct ParentGuard {
    std::function<void()> f;
    ~ParentGuard() { f(); }
  } parent_guard{close_in_parent};

  SIZE_T size = 0;
  InitializeProcThreadAttributeList(nullptr, 4, 0, &size);
  std::vector<BYTE> storage(size);
  auto* attrs = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
  if (!InitializeProcThreadAttributeList(attrs, 4, 0, &size))
    throw Win32Error("InitializeProcThreadAttributeList", GetLastError());
  struct AttrGuard {
    LPPROC_THREAD_ATTRIBUTE_LIST a;
    ~AttrGuard() { DeleteProcThreadAttributeList(a); }
  } guard{attrs};
  if (!spec.no_appcontainer &&
      !UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &caps, sizeof(caps), nullptr,
                                 nullptr))
    throw Win32Error("UpdateProcThreadAttribute(SECURITY_CAPABILITIES)", GetLastError());
  if (!UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), nullptr,
                                 nullptr))
    throw Win32Error("UpdateProcThreadAttribute(HANDLE_LIST)", GetLastError());
  if (parent) {
    if (!UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parent, sizeof(parent), nullptr,
                                   nullptr))
      throw Win32Error("UpdateProcThreadAttribute(PARENT_PROCESS)", GetLastError());
  } else if (!UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, jobs, sizeof(jobs), nullptr,
                                        nullptr)) {
    throw Win32Error("UpdateProcThreadAttribute(JOB_LIST)", GetLastError());
  }

  STARTUPINFOEXW si{};
  si.StartupInfo.cb = sizeof(si);
  si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  si.StartupInfo.hStdInput = inherited[0];
  si.StartupInfo.hStdOutput = inherited[1];
  si.StartupInfo.hStdError = inherited[2];
  si.StartupInfo.lpDesktop = const_cast<wchar_t*>(L"winsta0\\default");
  si.lpAttributeList = attrs;

  std::wstring command_line = L"\"" + spec.executable + L"\"";
  if (!spec.arguments.empty()) command_line += L" " + spec.arguments;
  const auto slash = spec.executable.find_last_of(L'\\');
  const std::wstring directory = slash == std::wstring::npos ? std::wstring() : spec.executable.substr(0, slash);

  void* environment = nullptr;
  if (spec.user_token && !CreateEnvironmentBlock(&environment, spec.user_token, FALSE))
    throw Win32Error("CreateEnvironmentBlock", GetLastError());
  struct EnvGuard {
    void* e;
    ~EnvGuard() {
      if (e) DestroyEnvironmentBlock(e);
    }
  } env_guard{environment};

  PROCESS_INFORMATION pi{};
  const DWORD flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | (parent ? CREATE_SUSPENDED : 0);
  const BOOL ok = spec.user_token
                      ? CreateProcessAsUserW(spec.user_token, spec.executable.c_str(), command_line.data(), nullptr,
                                             nullptr, TRUE, flags, environment,
                                             directory.empty() ? nullptr : directory.c_str(), &si.StartupInfo, &pi)
                      : CreateProcessW(spec.executable.c_str(), command_line.data(), nullptr, nullptr, TRUE, flags,
                                       nullptr, directory.empty() ? nullptr : directory.c_str(), &si.StartupInfo, &pi);
  if (!ok) throw Win32Error("CreateProcess(BrowserHost)", GetLastError());
  if (parent) {
    // JOB_LIST is not combined with a substitute parent; assign before resuming.
    if (!spec.no_job && !AssignProcessToJobObject(out.job.get(), pi.hProcess)) {
      const DWORD e = GetLastError();
      TerminateProcess(pi.hProcess, 1);
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
      throw Win32Error("AssignProcessToJobObject", e);
    }
    ResumeThread(pi.hThread);
  }
  CloseHandle(pi.hThread);
  out.process.reset(pi.hProcess);
  out.pid = pi.dwProcessId;
  out.to_host = std::move(in_write);
  out.from_host = std::move(out_read);
  return out;
}

}  // namespace orangespace::sandbox
