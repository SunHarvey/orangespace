#include "orangespace/ui_v2.hpp"
#include <cassert>
int main() {
  using orangespace::Sandbox;
  std::vector<Sandbox> rows{{"b","user","renamed","node","closed","profile-b"}, {"a","other","x","node","closed","p"}, {"c","user","x","other","closed","p"}};
  assert(orangespace::ui_v2::default_sandbox(rows,"user","node")->id=="b");
  assert(!orangespace::ui_v2::default_sandbox(rows,"user","absent"));
  auto created=orangespace::ui_v2::created_sandbox(R"({"schema_version":1,"ok":true,"sandbox":{"id":"11111111-1111-4111-8111-111111111111","user_id":"22222222-2222-4222-8222-222222222222","name":"live","node_id":"","state":"closed","profile_path":"p"}})","22222222-2222-4222-8222-222222222222");
  assert(created.name=="live");
  std::vector<Sandbox> pending{created};
  assert(orangespace::ui_v2::default_sandbox(pending,created.user_id,"33333333-3333-4333-8333-333333333333",created.id));
  assert(!orangespace::ui_v2::default_sandbox(pending,"44444444-4444-4444-8444-444444444444","33333333-3333-4333-8333-333333333333",created.id));
  assert(!orangespace::ui_v2::default_sandbox(pending,created.user_id,"33333333-3333-4333-8333-333333333333"));
  rows.push_back({"aa","user","second","node","closed","p"});
  assert(orangespace::ui_v2::default_sandbox(rows,"user","node","b")->id=="b");
  assert(orangespace::ui_v2::default_sandbox(rows,"user","node")->id=="aa");
}
