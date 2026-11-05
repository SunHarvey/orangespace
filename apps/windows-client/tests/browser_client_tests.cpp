#include "orangespace/service_client.hpp"
#include <cassert>
#include <iostream>
using namespace orangespace::service_client;
int main(){
 const chain::Binding b{"11111111-1111-4111-8111-111111111111","22222222-2222-4222-8222-222222222222","33333333-3333-4333-8333-333333333333","44444444-4444-4444-8444-444444444444",7};
 const std::string body=R"({"schema":1,"ok":true,"browser":{"phase":3,"sandbox":"22222222-2222-4222-8222-222222222222","node":"33333333-3333-4333-8333-333333333333","package_sid":"S-1-15-2-123","profile_name":"OrangeSpace.SinglePrototype.test","url":"https://example.com/","title":"Example","error":"","generation":7,"process_birth":134067918123456789,"process_id":123,"loading":false,"can_go_back":true,"can_go_forward":false}})";
 assert(validate_browser_reply(body,b));
 assert(browser_wire_birth(body)==134067918123456789ULL);
 auto wrong=b;wrong.generation++;assert(!validate_browser_reply(body,wrong));
 wrong=b;wrong.node=b.user;assert(!validate_browser_reply(body,wrong));
 auto mutate=[&](std::string from,std::string to){auto s=body;s.replace(s.find(from),from.size(),to);return s;};
 assert(validate_browser_reply(mutate("\"title\":\"Example\"","\"title\":\"process_birth\""),b));
 assert(!validate_browser_reply(mutate("\"loading\":false","\"loading\":0"),b));
 assert(!validate_browser_reply(mutate("\"phase\":3","\"phase\":5"),b));
 assert(!validate_browser_reply(mutate("\"schema\":1","\"schema\":1.0"),b));
 assert(!validate_browser_reply(mutate("134067918123456789","18446744073709551616"),b));
 assert(!validate_browser_reply(mutate("134067918123456789","134067918123456789.1"),b));
 assert(!validate_browser_reply(mutate("\"error\":\"\"","\"error\":\"\",\"extra\":true"),b));
 assert(valid_browser_url("https://example.com/a?q=1"));
 assert(!valid_browser_url("https://example.com/\xc2\x85"));
 assert(!valid_browser_url("file:///c:/secret"));assert(!valid_browser_url("https://x/\r\nHost:x"));
 assert(!valid_browser_url(std::string(2049,'a')));
 std::cout<<"browser-client: strict 14-field schema, exact uint64 birth, tuple and URL negatives passed\n";
}
