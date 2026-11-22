#include "orangespace/platform_credential_store.hpp"
#include "orangespace/credential_store.hpp"
#include <cassert>
#include <iostream>
using namespace orangespace;
namespace pd = platform_session::credential_detail;
const std::string origin = "https://control.example.test:443";
const std::string envelope = R"({"schema":1,"namespace":"orangespace.platform.renewal","api_origin":"https://control.example.test:443","central_user_id":"11111111-1111-4111-8111-111111111111","central_session_id":"22222222-2222-4222-8222-222222222222","username":"alice","role":"user","user_epoch":1,"session_deadline":5000,"refresh_expires_at":2000,"refresh_token":"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"})";
template<class F> void rejects(F f) { bool threw=false; try { f(); } catch (...) { threw=true; } assert(threw); }
int main() {
  assert(pd::directory_name == L"OrangeSpace-Platform-Credentials-v1");
  auto b=pd::validate_origin(origin); assert(b.api_origin==origin && b.port==443);
  rejects([]{pd::validate_origin("https://control.example.test/../../x");});
  rejects([]{pd::validate_origin("https://control.example.test\"}");});
  pd::validate_renewal(origin,envelope,1000);
  rejects([]{pd::validate_renewal("https://other.example.test",envelope,1000);});
  rejects([]{pd::validate_renewal(origin,envelope,2000);});  // refresh credential expired
  auto changed=envelope; changed.replace(changed.find("\"session_deadline\":5000"),23,"\"session_deadline\":1500");
  rejects([&]{pd::validate_renewal(origin,changed,1000);});  // outlives the session
  changed=envelope; changed.replace(changed.find("orangespace.platform.renewal"),28,"orangespace.platform.session");
  rejects([&]{pd::validate_renewal(origin,changed,1000);});  // an access-credential envelope is never stored
  changed=envelope; changed.replace(changed.find("\"schema\":1"),10,"\"schema\":1.0");
  rejects([&]{pd::validate_renewal(origin,changed,1000);});
  changed=envelope; changed.insert(changed.size()-1,",\"extra\":1");
  rejects([&]{pd::validate_renewal(origin,changed,1000);});
  changed=envelope; changed.replace(changed.find("abcdefghij"),10,"abcdefghi!");
  rejects([&]{pd::validate_renewal(origin,changed,1000);});
  auto a=pd::entropy("S-1-5-21-123",origin);
  assert(a!=pd::entropy("S-1-5-21-124",origin));
  assert(a!=pd::entropy("S-1-5-21-123","https://other.example.test"));
  node_session::detail::NodeEntry node; node.node_id="11111111-1111-4111-8111-111111111111"; node.host="control.example.test";
  assert(a!=node_session::credential_detail::entropy("S-1-5-21-123",node));
  rejects([]{pd::entropy("",origin);});
  assert(pd::storage_id(std::string(64,'a')));
  assert(!pd::storage_id("../evil")); assert(!pd::storage_id(std::string(64,'A')));
  std::cout << "platform credential policy passed\n";
}
