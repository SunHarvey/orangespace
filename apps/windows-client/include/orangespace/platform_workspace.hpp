#pragma once
#include "orangespace/model.hpp"
#include <memory>
#include <map>
#include <cstdint>
#include <algorithm>

namespace orangespace {
// UI-thread confined; production Session and Node are the independently
// authenticated platform SDK types, never node legacy identities or UI UUIDs.
template<class Session, class Node> class PlatformWorkspace {
 public:
  struct LoginTicket { std::uint64_t epoch{}; };
  struct Operation { std::uint64_t epoch{}; std::string user, node, bound_node; std::int64_t expiry{}; };
  LoginTicket begin_login() { return {++epoch_}; }
  bool finish_login(LoginTicket ticket, std::unique_ptr<Session>&& session,
                    std::vector<Node> nodes, std::int64_t now) {
    if(closed_ || ticket.epoch!=epoch_ || !session || session->identity().expires_at<=now) return false;
    // Prepare fallible metadata before consuming the caller's cleanup owner.
    // Rejection/exception preserves it for the GUI's existing logout drain.
    std::string user=session->identity().central_user_id;
    std::string selected=nodes.empty() ? std::string{} : nodes.front().alias;
    std::shared_ptr<Session> retained(std::move(session));
    session_=std::move(retained);nodes_=std::move(nodes);user_=std::move(user);selected_=std::move(selected);++epoch_;
    return true;
  }
  const Session* active(std::int64_t now) const {
    return !closed_ && session_ && session_->identity().expires_at>now ? session_.get() : nullptr;
  }
  std::shared_ptr<Session> retain(std::int64_t now) const { return active(now) ? session_ : nullptr; }
  const std::vector<Node>& nodes() const { return nodes_; }
  const Node* node(const std::string& id, std::int64_t now) const {
    if(!active(now))return nullptr;
    for(const auto& n:nodes_) if(n.node_id==id)return &n;
    return nullptr;
  }
  const Node* selected_node(std::int64_t now) const {
    if(!active(now))return nullptr;
    for(const auto& n:nodes_)if(n.alias==selected_)return &n;
    return nullptr;
  }
  void select(std::string alias) { ++epoch_;selected_=std::move(alias); }
  const std::string& workspace_user() const { return user_; }
  bool authorize(const std::string& user,const std::string& bound,const std::string& destination,std::int64_t now) const {
    return active(now) && user==user_ && node(destination,now) && (bound.empty() || node(bound,now));
  }
  bool manage(const std::string& user,const std::string& bound,std::int64_t now) const {
    return active(now) && user==user_ && (bound.empty() || node(bound,now));
  }
  Operation operation(std::int64_t now,const std::string& bound={}) const {
    const auto* n=selected_node(now);
    if(!n || !authorize(user_,bound,n->node_id,now))return {};
    return {epoch_,user_,n->node_id,bound,session_->identity().expires_at};
  }
  bool current(const Operation& op,std::int64_t now) const {
    return op.epoch==epoch_ && now<op.expiry && authorize(op.user,op.bound_node,op.node,now);
  }
  void logout() { ++epoch_;session_.reset();nodes_.clear();selected_.clear();user_.clear(); }
  void close() { logout();closed_=true; }
 private:
  bool closed_{};
  std::uint64_t epoch_{};
  std::shared_ptr<Session> session_;
  std::vector<Node> nodes_;
  std::string selected_,user_;
};
// Row-specific completion fences are independent of the node selector and of
// sibling sandboxes. A boolean here is only a presentation of typed Service
// proof; never a BrowserPermit or a substitute for validation in service_client.
class PlatformRows {
 public:
  enum class State { unknown, starting, verified, stopping, stopped, failed };
  struct Ticket { std::string local,node; std::uint64_t epoch{}; };
  Ticket begin(const std::string& local,const std::string& node) {
    auto& row=rows_[local]; ++row.epoch;row.node=node;row.state=State::starting;
    return {local,node,row.epoch};
  }
  bool current(const Ticket& t) const {
    auto i=rows_.find(t.local);
    return i!=rows_.end() && i->second.epoch==t.epoch && i->second.node==t.node && i->second.state==State::starting;
  }
  bool complete(const Ticket& t,bool process,bool authenticated,bool forwarded) {
    if(!current(t))return false;
    auto& row=rows_.at(t.local);
    row.state=(process && authenticated && forwarded) ? State::verified : State::failed;
    return row.state==State::verified;
  }
  void stop(const std::string& local) {auto& row=rows_[local];++row.epoch;row.state=State::stopping;}
  void stopped(const std::string& local) {auto& row=rows_[local];++row.epoch;row.state=State::stopped;}
  State state(const std::string& local) const {auto i=rows_.find(local);return i==rows_.end() ? State::unknown : i->second.state;}
  bool proven(const std::string& local) const {return state(local)==State::verified;}
  void retired_all() noexcept { rows_.clear(); }
  bool may_mutate(const std::string& local) const {
    const auto s=state(local);return s!=State::starting && s!=State::stopping;
  }
 private:
  struct Row {std::uint64_t epoch{};std::string node;State state{State::unknown};};
  std::map<std::string,Row> rows_;
};
} // namespace orangespace
