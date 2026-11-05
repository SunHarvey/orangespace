#pragma once
#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
namespace orangespace::files::panel_detail {
struct Scope { std::string user_id, sandbox_id, node_id, directory; std::uint64_t epoch{}; };
class TaskPin {
 public:
  explicit TaskPin(Scope scope) : scope_(std::move(scope)) {}
  const Scope& scope() const noexcept { return scope_; }
  void cancel() noexcept { cancel_.store(true); }
  bool cancelled() const noexcept { return cancel_.load(); }
  std::atomic<bool>& cancellation() noexcept { return cancel_; }
  bool publishable(const std::string& user, std::uint64_t epoch) const noexcept {
    return !cancelled() && scope_.user_id == user && scope_.epoch == epoch;
  }
 private:
  const Scope scope_;
  std::atomic<bool> cancel_{false};
};
}
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include "orangespace/file_transfer.hpp"
namespace orangespace::files {
inline constexpr UINT ReturnToBrowserMessage = WM_APP + 37;
// UI-thread only. Workers only write mailboxes; parent polls every 100 ms.
class FilePanel {
 public:
  FilePanel(HWND parent, HINSTANCE instance);
  ~FilePanel();
  FilePanel(const FilePanel&) = delete;
  FilePanel& operator=(const FilePanel&) = delete;
  HWND window() const noexcept;
  void show(const FileContext& context);
  void hide();
  // UI-thread nonblocking invalidation/cancellation; call logout after can_close.
  void request_logout();
  void logout();
  bool can_close() const;
  void poll();
 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
}
#endif
