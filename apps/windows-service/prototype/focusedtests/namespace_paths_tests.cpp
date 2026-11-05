#include "orangespace/prototype_namespace.hpp"
#include <cassert>
#include <string>
int main() {
  using orangespace::service::win::prototype_namespace_paths;
  const auto a=prototype_namespace_paths(L"C:\\Program Files\\OrangeSpace-SinglePrototype\\");
  assert(a.anchor==L"C:\\Program Files\\OrangeSpace-SinglePrototype-SG-v25-State\\namespace.anchor");
  assert(a.state==L"C:\\Program Files\\OrangeSpace-SinglePrototype-SG-v25-State\\service-state.json");
  assert(a.next==L"C:\\Program Files\\OrangeSpace-SinglePrototype-SG-v25-State\\service-state.next");
  assert(!a.state.starts_with(L"C:\\Program Files\\OrangeSpace-SinglePrototype\\"));
  const auto b=prototype_namespace_paths(L"D:\\Applications\\OwnedPrototype\\");
  assert(b.state==L"D:\\Applications\\OrangeSpace-SinglePrototype-SG-v25-State\\service-state.json");
  for(auto path:{L"",L"relative\\",L"C:\\",L"C:\\Program Files\\Owned",L"C:\\Program Files\\..\\Owned\\",L"\\\\host\\share\\Owned\\"}) {
    bool rejected=false;try{(void)prototype_namespace_paths(path);}catch(...){rejected=true;}assert(rejected);
  }
}
