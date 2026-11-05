#include "orangespace/platform_workspace.hpp"
#include <cassert>
#include <iostream>
struct Identity { std::string central_user_id, central_session_id, username; std::int64_t expires_at; };
struct Node { std::string node_id, alias, remote_legacy_user_id; };
struct Session {
  Identity id;
  explicit Session(std::string user) : id{std::move(user),"session","user",1000} {}
  const Identity& identity() const { return id; }
};
int main() {
  orangespace::PlatformWorkspace<Session,Node> auth;
  auto ticket=auth.begin_login();
  std::vector<Node> nodes{{"node-A","sz.example","legacy-A"},{"node-B","gz.example","legacy-B"}};
  assert(auth.finish_login(ticket,std::make_unique<Session>("central"),nodes,10));
  auth.select("sz.example");
  assert(auth.workspace_user()=="central");
  assert(auth.authorize("central","node-A","node-B",10));
  assert(!auth.authorize("legacy-A","node-A","node-A",10));
  assert(!auth.authorize("legacy-B","node-B","node-B",10));
  auth.select("gz.example");
  assert(auth.workspace_user()=="central");
  assert(auth.manage("central","node-A",10));
  assert(auth.selected_node(10)->alias=="gz.example");
  auto op=auth.operation(10,"node-A");
  assert(op.node=="node-B" && op.user=="central");
  auth.logout();
  assert(!auth.current(op,10));
  assert(!auth.finish_login(ticket,std::make_unique<Session>("central"),nodes,10));
  auto rejected=std::make_unique<Session>("central");
  assert(!auth.finish_login(ticket,std::move(rejected),nodes,10));
  assert(rejected); // Caller must retain the unadopted session for revoke.
  // Existing legacy ownership is rejected, never rewritten or merged by name.
  orangespace::Sandbox legacy{"local","legacy-A","same name","node-A","closed","old/profile"};
  auto next=auth.begin_login();
  assert(auth.finish_login(next,std::make_unique<Session>("central"),nodes,10));
  assert(!auth.manage(legacy.user_id,legacy.node_id,10));
  assert(legacy.user_id=="legacy-A" && legacy.profile=="old/profile");
  orangespace::PlatformRows rows;
  auto a=rows.begin("A","node-A"), b=rows.begin("B","node-B");
  assert(rows.state("A")==orangespace::PlatformRows::State::starting);
  assert(!rows.proven("A"));
  assert(!rows.may_mutate("A"));
  assert(rows.complete(b,true,true,true));
  assert(rows.may_mutate("B"));
  rows.stop("A");
  assert(!rows.complete(a,true,true,true));
  assert(rows.proven("B"));
  assert(rows.state("A")==orangespace::PlatformRows::State::stopping);
  rows.stopped("A");
  assert(rows.state("A")==orangespace::PlatformRows::State::stopped);
  auto a2=rows.begin("A","node-A");
  assert(!rows.complete(a2,true,true,false));
  assert(!rows.proven("A") && rows.proven("B"));
  std::cout << "central ownership, legacy preservation, row proof/late-reply isolation: PASS\n";
}
