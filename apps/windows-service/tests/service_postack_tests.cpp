#include <cstdlib>
#include <new>
static bool fail_new=false;
void* operator new(std::size_t n){if(fail_new)throw std::bad_alloc();if(auto p=std::malloc(n?n:1))return p;throw std::bad_alloc();}
void operator delete(void* p) noexcept{std::free(p);}
void operator delete(void* p,std::size_t) noexcept{std::free(p);}
#define main supplied_policy_main
#include "chain_tests.cpp"
#undef main
#define _WIN32
#include "orangespace/service_client.hpp"
#undef _WIN32
// Explicit injected NodeSession fixture; no Windows implementation is linked.
namespace orangespace::node_session {
TrustedCatalog TrustedCatalog::load(const std::wstring&){return TrustedCatalog({});}
NodeSession NodeSession::restore(const TrustedCatalog&,std::string_view,std::string_view){
 return NodeSession({},detail::Identity{"11111111-1111-4111-8111-111111111111","fixture","22222222-2222-4222-8222-222222222222"},detail::LoginReply("test-only",1000));
}
std::string NodeSession::credential_envelope() const{return "{}";}
}
namespace orangespace::service_client {
static std::vector<std::uint8_t> transport_bytes;
static chain::Response* server_response{};
static bool ack_seen{}, fail_after_ack=true, write_ok=true;
struct MockHandle{int get()const{return 0;}};
bool transfer(int,int,void* bytes,unsigned size,bool write,unsigned& count){
 check(write && size==1 && *static_cast<uint8_t*>(bytes)==6,"actual ACK byte unchanged");
 if(!write_ok)return false;
 server_response->finish(true);ack_seen=true;count=1;
 if(fail_after_ack)fail_new=true;
 return true;
}
#include "postack_under_test.hpp"
}
void packet(orangespace::service::chain::Response& r){
 using namespace orangespace::service_client;
 server_response=&r;ack_seen=false;
 transport_bytes.resize(r.body.size()+4);
 for(unsigned i=0;i<4;++i)transport_bytes[i]=static_cast<uint8_t>(r.body.size()>>(8*i));
 std::copy(r.body.begin(),r.body.end(),transport_bytes.begin()+4);
}
int main(int argc,char** argv){
 const std::string_view mode=argc>1?argv[1]:"authorize";
 using namespace orangespace;using namespace service_client;
 fail_after_ack=(mode=="authorize");
 service::Peer p{"S-1-5-21-100",1,99};FakeBackend b;Engine e(p,b,[]{return 100;});
 auto catalog=node_session::TrustedCatalog::load(L"injected");auto session=node_session::NodeSession::restore(catalog,"node","test-only");
 auto auth=e.authorize_response(p,"node","{}");packet(auth);
 bool returned=false;
 try{auto grant=authorize("node",session);returned=true;fail_new=false;check(grant.user()==session.identity().user_id,"final Grant returned");}catch(...){fail_new=false;}
 check(returned && ack_seen,"POSTACK authorize: actual ACK must deliver final owned Grant under persistent allocation failure");
 // Use a second authorization for subsequent wrappers.
 fail_after_ack=false;auto next=e.authorize_response(p,"node","{}");packet(next);auto grant=authorize("node",session);fail_after_ack=(mode=="start");
 auto start=e.start_response(p,grant.id());packet(start);service::chain::Binding binding;
 returned=false;try{binding=start_tunnel(grant);returned=true;}catch(...){ }fail_new=false;
 check(returned && ack_seen && !binding.tunnel.empty(),"POSTACK start: final owned Binding survives persistent allocation failure");
 fail_after_ack=(mode=="stop");
 auto cursor=e.stop(p,grant.id(),{binding.sandbox,binding.generation});
 chain::Response stop("{\"ok\":true,\"browser_allowed\":false,\"sandbox_id\":"+chain::quote(cursor.sandbox)+",\"generation\":"+std::to_string(cursor.generation)+"}");packet(stop);
 returned=false;try{auto result=stop_tunnel(grant,binding);returned=true;fail_new=false;check(result.sandbox==cursor.sandbox && result.generation==cursor.generation,"stop final Cursor delivered");}catch(...){fail_new=false;}
 check(returned && ack_seen,"POSTACK stop: final owned Cursor survives persistent allocation failure");
 std::cout<<"PASS exact client wrappers/ACK tail: authorize Grant, start Binding, stop Cursor; persistent new failure AFTER actual Engine ACK; -fno-elide (injected transport, NOT Windows IPC)\n";
}
