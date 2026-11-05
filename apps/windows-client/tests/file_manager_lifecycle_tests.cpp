#include "orangespace/file_manager_win.hpp"
#include <cassert>
#include <iostream>
int main() {
  using namespace orangespace::files::panel_detail;
  Scope a{"user-a", "sandbox-a", "node-a", "docs", 1};
  TaskPin pin(a);
  a.node_id = "node-b"; a.directory = "other";
  assert(pin.scope().node_id == "node-a");
  assert(pin.scope().directory == "docs");
  assert(pin.publishable("user-a", 1));
  assert(!pin.publishable("user-b", 1));
  assert(!pin.publishable("user-a", 2));
  pin.cancel(); assert(pin.cancelled());
  assert(!pin.publishable("user-a", 1));
  std::cout << "file manager immutable scope and logout fence passed\n";
}
