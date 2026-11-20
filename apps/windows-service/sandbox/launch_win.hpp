#pragma once
// Starts one sandbox's BrowserHost in a kill-on-close Job (optionally inside an
// AppContainer), with private anonymous pipes as its only inherited handles.
#include <windows.h>

#include <string>

namespace orangespace::sandbox {

struct UniqueHandle {
  HANDLE h{};
  UniqueHandle() = default;
  explicit UniqueHandle(HANDLE handle) : h(handle == INVALID_HANDLE_VALUE ? nullptr : handle) {}
  UniqueHandle(UniqueHandle&& o) noexcept : h(o.release()) {}
  UniqueHandle& operator=(UniqueHandle&& o) noexcept {
    if (this != &o) reset(o.release());
    return *this;
  }
  UniqueHandle(const UniqueHandle&) = delete;
  UniqueHandle& operator=(const UniqueHandle&) = delete;
  ~UniqueHandle() { reset(); }
  HANDLE get() const { return h; }
  HANDLE release() {
    HANDLE r = h;
    h = nullptr;
    return r;
  }
  void reset(HANDLE n = nullptr) {
    if (h) CloseHandle(h);
    h = n;
  }
  explicit operator bool() const { return h != nullptr; }
};

struct BrowserLaunch {
  std::wstring executable;   // absolute path of osbrowser.exe
  void* package_sid{};       // this sandbox's AppContainer SID
  HANDLE user_token{};       // primary token of the session user (Service); null = caller
  std::wstring arguments;    // appended after the quoted executable (tests only; BrowserHost takes none)
  HANDLE stderr_handle{};    // optional diagnostics sink (inheritable); default NUL
  // Production BrowserHost runs outside any AppContainer (Chromium's broker
  // cannot run inside one); its identity is the per-sandbox image path.
  bool no_appcontainer{};
  // Developer harness only: an elevated tool cannot start Chromium with its own
  // (elevated) token - Chromium refuses with exit 38 "auto de-elevated". The
  // child then inherits the token of this non-elevated process (e.g. explorer).
  // The Service uses user_token instead.
  HANDLE parent_process{};
  bool no_job{};             // developer diagnostics only
};

struct BrowserProcess {
  UniqueHandle process;
  UniqueHandle job;          // kill-on-close: closing it ends the whole browser tree
  DWORD pid{};
  UniqueHandle to_host;      // write end of the host's stdin
  UniqueHandle from_host;    // read end of the host's stdout
};

BrowserProcess LaunchBrowser(const BrowserLaunch& spec);

// Writes all bytes or throws.
void WriteAll(HANDLE pipe, const std::string& data);

}  // namespace orangespace::sandbox
