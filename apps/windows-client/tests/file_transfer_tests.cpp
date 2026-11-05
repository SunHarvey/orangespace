#include "orangespace/file_transfer.hpp"
#include <cassert>
#include <iostream>
using namespace orangespace::files;
template<class F> void denied(F f) { bool threw=false;try{f();}catch(...){threw=true;}assert(threw); }
int main() {
 FileContext c; c.central_user_id="11111111-1111-4111-8111-111111111111";c.sandbox_id="22222222-2222-4222-8222-222222222222";c.node_id="33333333-3333-4333-8333-333333333333";
 detail::TaskScope s(c,"folder/file"); c.node_id="44444444-4444-4444-8444-444444444444";
 assert(s.node_id=="33333333-3333-4333-8333-333333333333" && s.path=="folder/file");
 assert(detail::checked_path("",true).empty());
 for(auto p:{"","/a","a//b","a/../b","a\\b",".orangespace-upload-x","a/.orangespace-upload-x"})denied([&]{detail::checked_path(p);});
 assert(detail::encode_path("a/#?% x")=="a/%23%3F%25%20x");
 const std::string listing=R"({"node_id":"33333333-3333-4333-8333-333333333333","path":"folder/file","entries":[{"name":"x","kind":"file","size":1048577,"modified_at_ns":1793000000000000001}]})";
 auto entries=detail::parse_listing(listing,s);assert(entries.size()==1&&entries[0].size==1048577&&entries[0].path=="folder/file/x"&&!entries[0].modified_at_ns);
 auto wrong=listing;wrong.replace(wrong.find(s.node_id),36,c.node_id);denied([&]{detail::parse_listing(wrong,s);});
 wrong=listing;wrong.replace(wrong.find("\"name\":\"x\""),10,"\"name\":\"..\"");denied([&]{detail::parse_listing(wrong,s);});
 std::atomic<bool> cancelled{true};denied([&]{detail::cancellation_point(cancelled);});
 detail::DownloadOwnership part;unsigned publications=0;
 denied([&]{part.publish(cancelled,[&]{++publications;});});
 assert(part.owns_part() && publications==0);
 cancelled=false;
 denied([&]{part.publish(cancelled,[&]{throw std::runtime_error("conflict");});});
 assert(part.owns_part());
 part.publish(cancelled,[&]{++publications;});assert(!part.owns_part()&&publications==1);
 denied([&]{part.publish(cancelled,[&]{++publications;});});assert(publications==1);
 std::cout<<"file transfer immutable scope/path/cancellation/publication ownership passed\n";
}
