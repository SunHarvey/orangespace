#pragma once
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>

namespace orangespace {
// UI-thread confined. Session must be the authenticated NodeSession in production;
// this template's fake session seam is for portable policy tests, not trust input.
template<class Session> class WorkspaceAuth {
 public:
  struct LoginTicket { std::uint64_t epoch; std::string alias; };
  LoginTicket begin_login(std::string alias) { return {++epoch_, std::move(alias)}; }
  bool finish_login(const LoginTicket& ticket, std::unique_ptr<Session> session, std::int64_t now) {
    if (closed_ || ticket.epoch != epoch_ || !session || session->expires_at() <= now) return false;
    ++epoch_; // Consume the completion; replay cannot replace identity.
    selected_ = ticket.alias;
    if (user_.empty()) user_ = session->identity().user_id;
    sessions_[selected_] = std::move(session);
    return true;
  }
  const Session* active(std::int64_t now) const {
    auto it = sessions_.find(selected_);
    return it == sessions_.end() || it->second->expires_at() <= now ? nullptr : it->second.get();
  }
  struct Operation { std::uint64_t epoch; std::string user, node, bound_node; std::int64_t expiry; };
  const std::string& workspace_user() const { return user_; }
  void select(std::string alias) { ++epoch_; selected_ = std::move(alias); }
  void logout() { ++epoch_; sessions_.clear(); selected_.clear(); user_.clear(); }
  void close() { logout(); closed_ = true; }
  bool authorize(const std::string& user, const std::string& bound_node,
                 const std::string& destination, std::int64_t now) const {
    const auto* selected = active(now);
    if (!selected || user != user_ || selected->identity().user_id != user ||
        selected->identity().node_id != destination) return false;
    if (bound_node.empty()) return true;
    for (const auto& [alias, session] : sessions_) {
      (void)alias;
      if (session->expires_at() > now && session->identity().user_id == user &&
          session->identity().node_id == bound_node) return true;
    }
    return false;
  }
  bool manage(const std::string& user, const std::string& bound_node, std::int64_t now) const {
    const auto* s = active(now);
    return s && (bound_node.empty() || bound_node == s->identity().node_id) &&
        authorize(user, bound_node, s->identity().node_id, now);
  }
  Operation operation(std::int64_t now, const std::string& bound_node = "") const {
    const auto* s = active(now);
    if (!s || !authorize(user_, bound_node, s->identity().node_id, now)) return {};
    auto expiry = s->expires_at();
    if (!bound_node.empty()) {
      for (const auto& [alias, session] : sessions_) {
        (void)alias;
        if (session->identity().node_id == bound_node && session->identity().user_id == user_ && session->expires_at() > now) {
          if (session->expires_at() < expiry) expiry = session->expires_at();
          break;
        }
      }
    }
    return {epoch_, user_, s->identity().node_id, bound_node, expiry};
  }
  bool current(const Operation& op, std::int64_t now) const {
    return !closed_ && op.epoch == epoch_ && now < op.expiry &&
        authorize(op.user, op.bound_node, op.node, now);
  }
 private:
  bool closed_{};
  std::uint64_t epoch_{};
  std::string selected_, user_;
  std::map<std::string, std::unique_ptr<Session>> sessions_;
};
} // namespace orangespace
