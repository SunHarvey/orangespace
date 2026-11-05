#pragma once
#include "orangespace/node_session.hpp"
namespace orangespace::service::win {
// Fixed privileged namespace adjacent to, never inside, the hash-pinned runtime.
// The caller supplies its OS module directory, not any request/config path.
struct PrototypeNamespacePaths { std::wstring anchor,state,next; };
inline PrototypeNamespacePaths prototype_namespace_paths(std::wstring_view installation) {
  namespace nd=node_session::detail;
  nd::require(installation.size()>4 && installation.back()==L'\\' &&
      nd::explicit_local_path(installation.substr(0,installation.size()-1)));
  const auto leaf_end=installation.size()-1;
  const auto parent_end=installation.rfind(L'\\',leaf_end-1);
  nd::require(parent_end!=std::wstring_view::npos && parent_end>=2 && parent_end<leaf_end);
  for(std::size_t begin=3;begin<installation.size();) {
    const auto end=installation.find(L'\\',begin);
    nd::require(end!=std::wstring_view::npos && end>begin);
    const auto part=installation.substr(begin,end-begin);
    nd::require(part!=L"." && part!=L".." && part.find(L':')==std::wstring_view::npos);
    begin=end+1;
  }
  auto directory=std::wstring(installation.substr(0,parent_end+1))+L"OrangeSpace-SinglePrototype-SG-v25-State\\";
  return {directory+L"namespace.anchor",directory+L"service-state.json",directory+L"service-state.next"};
}
} // namespace orangespace::service::win
