#include "orangespace/platform_session.hpp"
#include <cassert>
#include <iostream>
using namespace orangespace;
template<class F> void rejects(F f) { bool denied=false;try {f();}catch(const std::exception&){denied=true;}assert(denied); }
int main() {
  namespace nd=node_session::detail;
  int reads=0;
  auto reader=[&](const std::wstring& path) {assert(path==L"C:\\OrangeSpace\\ca.pem");++reads;return std::string("CA fixture bytes");};
  const auto config=R"({"schema":2,"api_origin":"https://centre.test:19093","ca_file":"C:\\OrangeSpace\\ca.pem"})";
  auto bootstrap=platform_session::detail::validate_bootstrap(config,reader);
  assert(bootstrap.ca_pem && *bootstrap.ca_pem=="CA fixture bytes" && reads==1);
  auto legacy=platform_session::detail::validate_bootstrap(R"({"schema":1,"api_origin":"https://centre.test"})");
  assert(!legacy.ca_pem);
  rejects([&]{platform_session::detail::validate_bootstrap(R"({"schema":1,"api_origin":"https://centre.test","ca_file":"C:\\OrangeSpace\\ca.pem"})",reader);});
  rejects([&]{platform_session::detail::validate_bootstrap(R"({"schema":2,"api_origin":"https://centre.test","ca_file":"relative.pem"})",reader);});
  rejects([&]{platform_session::detail::validate_bootstrap(config);});
  auto nodes=nd::parse_catalog(R"({"schema":2,"nodes":[{"name":"node-a","node_id":"11111111-1111-4111-8111-111111111111","api_origin":"https://node.test:19094","ca_file":"C:\\OrangeSpace\\ca.pem"}]})",reader);
  assert(nodes.size()==1 && nodes[0].ca_pem && reads==2);
  const auto snapshot=nodes[0].ca_pem;
  nodes.clear();assert(*snapshot=="CA fixture bytes");
  rejects([&]{platform_session::detail::validate_bootstrap(config,[](const std::wstring&)->std::string {throw std::runtime_error("protected read denied");});});
  rejects([&]{platform_session::detail::validate_bootstrap(config,[](const std::wstring&){return std::string();});});
  rejects([&]{platform_session::detail::validate_bootstrap(config,[](const std::wstring&){return std::string(65537,'x');});});
  for(const auto path:{"..\\ca.pem","\\\\host\\share\\ca.pem","C:\\OrangeSpace\\..\\ca.pem","C:\\OrangeSpace\\ca.pem:stream"}) {
    const auto before=reads;rejects([&]{nd::load_private_ca(path,reader);});assert(reads==before);
  }
  rejects([&]{platform_session::detail::validate_bootstrap(R"({"schema":2.0,"api_origin":"https://centre.test","ca_file":"C:\\OrangeSpace\\ca.pem"})",reader);});
  rejects([&]{nd::parse_catalog(R"({"schema":1,"nodes":[{"name":"node-a","node_id":"11111111-1111-4111-8111-111111111111","api_origin":"https://node.test","ca_file":"C:\\OrangeSpace\\ca.pem"}]})",reader);});
  auto mixed=nd::parse_catalog(R"({"schema":2,"nodes":[{"name":"node-a","node_id":"11111111-1111-4111-8111-111111111111","api_origin":"https://node.test"}]})",reader);
  assert(!mixed[0].ca_pem);
  nd::NodeEntry aggregate{"node-a","11111111-1111-4111-8111-111111111111","node.test",443,""};
  assert(!aggregate.ca_pem);
  std::cout<<"app-private CA parser policy passed\n";
}
