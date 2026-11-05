#include "orangespace/workspace_auth.hpp"
#include <iostream>
#include <stdexcept>
struct Session {
  struct Identity { std::string user_id, username, node_id; } who;
  std::int64_t expiry;
  const Identity& identity() const { return who; }
  std::int64_t expires_at() const { return expiry; }
};
using Controller = orangespace::WorkspaceAuth<Session>;
void check(bool ok, const char* why) { if (!ok) throw std::runtime_error(why); }
std::unique_ptr<Session> session(std::string user = "user-a", std::string node = "node-a", std::int64_t expiry = 100) {
  return std::make_unique<Session>(Session{{std::move(user), "same-name", std::move(node)}, expiry});
}
int main() {
  Controller auth;
  check(!auth.active(1), "signed out cannot authorize");
  auto login = auth.begin_login("office");
  check(auth.finish_login(login, session(), 1), "authenticated session published");
  check(auth.active(1)->identity().user_id == "user-a", "identity from session");
  check(!auth.finish_login(login, session("user-b"), 1), "login completion accepted only once");
  check(auth.authorize("user-a", "", "node-a", 99), "unbound create/bind allowed");
  check(!auth.authorize("user-a", "", "node-a", 100), "expiry boundary denied");
  check(!auth.authorize("user-b", "", "node-a", 1), "other workspace denied");
  check(!auth.authorize("user-a", "node-b", "node-a", 1), "old bound node needs authentication");
  auto other = auth.begin_login("remote");
  check(auth.finish_login(other, session("user-b", "node-b"), 1), "separate account retained");
  check(!auth.authorize("user-a", "", "node-b", 1), "same username never maps UUIDs");
  check(auth.workspace_user() == "user-a", "different login does not migrate workspace");
  auth.select("missing-alias");
  check(!auth.active(1), "unknown alias cannot authorize");
  auth.select("office");
  check(auth.active(1)->identity().node_id == "node-a", "per-node session retained");
  auto matching = auth.begin_login("remote");
  check(auth.finish_login(matching, session("user-a", "node-b"), 1), "same UUID separately authenticated");
  check(auth.authorize("user-a", "node-a", "node-b", 1), "rebind requires both authenticated nodes");
  check(!auth.authorize("user-a", "node-a", "node-c", 1), "destination exact match");
  check(!auth.manage("user-a", "node-a", 1), "manage cannot use another node's selected session");
  check(auth.manage("user-a", "node-b", 1), "manage exact user and selected node");
  check(auth.manage("user-a", "", 1), "unbound sandbox may be managed by its owner");
  check(!auth.manage("user-b", "node-b", 1), "other account cannot manage");
  auto rebind = auth.operation(1, "node-a");
  check(auth.current(rebind, 99), "bound operation valid before expiry");
  auto shorter = auth.begin_login("office");
  check(auth.finish_login(shorter, session("user-a", "node-a", 10), 1), "short original node session");
  auth.select("remote");
  auto old_node_expires = auth.operation(1, "node-a");
  check(!auth.current(old_node_expires, 10), "original bound session expiry invalidates rebind");
  auto operation = auth.operation(1);
  check(auth.current(operation, 99), "live completion accepted");
  check(!auth.current(operation, 100), "expired completion rejected");
  auth.select("office");
  check(!auth.current(operation, 1), "selection invalidates completion");
  auto stale = auth.begin_login("office");
  auto latest = auth.begin_login("remote");
  check(!auth.finish_login(stale, session(), 1), "superseded login rejected");
  auth.logout();
  check(!auth.finish_login(latest, session(), 1), "logout rejects late login");
  check(!auth.active(1) && auth.workspace_user().empty(), "logout clears all identity");
  auto closing = auth.begin_login("office");
  auth.close();
  check(!auth.finish_login(closing, session(), 1), "close rejects late login");
  check(!auth.finish_login(auth.begin_login("office"), session(), 1), "closed controller terminal");
  std::cout << "workspace auth: login, isolation, expiry and race checks passed\n";
}
