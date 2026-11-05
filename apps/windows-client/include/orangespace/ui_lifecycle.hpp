#pragma once
#include <cstdint>
#include <map>
#include <memory>
#include <type_traits>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace orangespace::ui_lifecycle {
// Allocate the final object storage AND shared control block before an RPC.
// A returned non-default-constructible DTO is adopted without allocating; the
// alias keeps its optional's storage alive, not a separately allocated copy.
// Single-use: consume the slot only after the RPC successfully returns.
template<class T> class SharedReturnSlot {
 public:
  SharedReturnSlot() : owner_(std::make_shared<std::optional<T>>()) {}
  SharedReturnSlot(const SharedReturnSlot&) = delete;
  SharedReturnSlot& operator=(const SharedReturnSlot&) = delete;
  std::shared_ptr<T> adopt(T&& value) && noexcept {
    static_assert(std::is_nothrow_move_constructible_v<T>);
    static_assert(std::is_nothrow_destructible_v<T>);
    auto* retained=&owner_->emplace(std::move(value));
    return std::shared_ptr<T>(std::move(owner_),retained);
  }
 private:
  std::shared_ptr<std::optional<T>> owner_;
};
// UI-thread confined result accounting. Explicit logout is best effort, but a
// failed remote attempt never suppresses or falsely confirms local retirement.
class Retirement {
 public:
  template<class Logout, class Retire> bool run(const std::string& id, bool explicit_logout,
                                               Logout logout, Retire retire) {
    if(explicit_logout && attempted_.insert(id).second) {
      try {logout();return true;}catch (...) {remote_failed_=true;}
    }
    try {retire();return true;}catch (...) {return false;}
  }
  bool remote_failed() const {return remote_failed_;}
 private:
  bool remote_failed_{};
  std::set<std::string> attempted_;
};
class LogoutState {
 public:
  // Admit intent without allocating, before catalog enumeration can fail.
  void request() noexcept {blocked_=true; initialized_=false; pending_.clear();}
  bool initialized() const {return initialized_;}
  void begin(std::vector<std::string> aliases) {
    blocked_=true; pending_=std::move(aliases); initialized_=true;
  }
  bool restore_blocked() const {return blocked_;}
  bool erased() const {return !blocked_;}
  template<class Erase> void retry_erasure(Erase erase) {
    if(!initialized_)return;
    for (auto it=pending_.begin();it!=pending_.end();) {
      bool ok=false; try {ok=erase(*it);} catch (...) {}
      if(ok) it=pending_.erase(it); else ++it;
    }
    blocked_=!pending_.empty();
  }
 private:
  bool blocked_{}, initialized_{};
  std::vector<std::string> pending_;
};
// Each dispatched startup owns a ticket until *after* its result/late grant is
// published. Cleanup has one owner; callbacks run outside the state lock.
template<class Resource> class Drain {
 public:
  using Ticket = std::uint64_t;
  std::optional<Ticket> begin() {
    std::lock_guard lock(mutex_);
    if (closed_) return {};
    const auto t=next_+1;
    // Allocate the final resource node before dispatch, never after an RPC.
    owned_.try_emplace(t);
    try {pending_.emplace(t,true);} catch (...) {owned_.erase(t);throw;}
    next_=t;return t;
  }
  void finish(Ticket t, std::optional<Resource> resource = {}) {
    static_assert(std::is_nothrow_move_constructible_v<Resource>);
    static_assert(std::is_nothrow_destructible_v<Resource>);
    std::lock_guard lock(mutex_);
    if (!pending_.contains(t)) return;
    auto it=owned_.find(t);
    if (resource) it->second.emplace(std::move(*resource));
    else owned_.erase(it);
    pending_.erase(t);
  }
  void close() { std::lock_guard lock(mutex_); closed_=true; }
  bool ready() const {
    std::lock_guard lock(mutex_);
    return closed_ && pending_.empty() && owned_.empty() && !cleaning_;
  }
  template<class Cleanup> void retry(Cleanup cleanup) {
    std::vector<std::pair<Ticket,Resource>> batch;
    {
      std::lock_guard lock(mutex_);
      if (!closed_ || !pending_.empty() || cleaning_) return;
      // Snapshot construction may allocate/copy. Do not latch the cleanup
      // owner until it succeeds; failure leaves every exact node retryable.
      try {
        for (const auto& [id,resource]:owned_) batch.emplace_back(id,*resource);
      } catch (...) {return;}
      cleaning_=true;
    }
    for (auto& [id,resource]:batch) {
      bool ok=false; try {ok=cleanup(resource);} catch (...) {}
      if (ok) {std::lock_guard lock(mutex_);owned_.erase(id);}
    }
    {std::lock_guard lock(mutex_);cleaning_=false;}
  }
 private:
  mutable std::mutex mutex_;
  bool closed_{}, cleaning_{};
  Ticket next_{};
  std::map<Ticket,bool> pending_;
  std::map<Ticket,std::optional<Resource>> owned_;
};
}
