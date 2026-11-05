// Actual client thread token differs while the held process primary token is
// unchanged. No process token/role launch, privileges enabled or real secrets.
#include "phase1_secure_channel.hpp"
#include <thread>
#include <iostream>
#include <exception>
using namespace phase1::secure;
int wmain(){
 try{
  auto expected=HeldPeer::capture(GetCurrentProcess());
  PSID raw_sid{};require(ConvertStringSidToSidW(expected.identity().sid.c_str(),&raw_sid),"restrict_sid");Local sid{raw_sid};SID_AND_ATTRIBUTES restricting{raw_sid,0};
  HANDLE raw{},restricted_raw{};require(OpenProcessToken(GetCurrentProcess(),TOKEN_DUPLICATE|TOKEN_QUERY,&raw),"restrict_primary");Handle primary(raw);
  require(CreateRestrictedToken(primary.get(),DISABLE_MAX_PRIVILEGE,0,nullptr,0,nullptr,1,&restricting,&restricted_raw),"restrict_test_thread_token");Handle restricted(restricted_raw);
  auto restricted_identity=token_identity(restricted.get());
  require(restricted_identity.restricted&&restricted_identity.sid==expected.identity().sid&&restricted_identity.session==expected.identity().session&&restricted_identity.logon.LowPart==expected.identity().logon.LowPart&&restricted_identity.logon.HighPart==expected.identity().logon.HighPart,"same_sid_session_logon_but_restricted");
  auto name=L"\\\\.\\pipe\\OrangeSpace-secure-actual-token-"+std::to_wstring(GetCurrentProcessId());
  auto server=create_server(name,expected.identity().sid);std::exception_ptr peer_failure;bool opened=false;
  std::thread peer([&]{
   try{
    require(ImpersonateLoggedOnUser(restricted.get()),"test_thread_impersonation");
    struct Revert{~Revert(){if(!RevertToSelf())TerminateProcess(GetCurrentProcess(),ERROR_CANNOT_IMPERSONATE);}} revert;
    auto pipe=open_client(name);opened=true;
    // Only a nonsecret hello, no claimed identity fields, enters the endpoint.
    BYTE marker=0x71;transfer(pipe.get(),&marker,1,true,Deadline(1000));Sleep(150);
   }catch(...){peer_failure=std::current_exception();}
  });
  bool rejected=false;
  try{
   connect(server.get(),Deadline(1000));
   try{auto channel=SecureChannel::server(std::move(server),std::move(expected),Deadline(1000));}
   catch(const Failure& f){rejected=std::string_view(f.stage)=="connection_sid_session_logon_role";}
  }catch(...){peer.join();throw;}
  peer.join();if(peer_failure)std::rethrow_exception(peer_failure);
  require(opened&&rejected,"actual_connection_token_must_override_primary_only_check");
  std::cout<<"{\"kind\":\"actual_pipe_impersonation_token\",\"ok\":true,\"same_sid_session_logon_restricted_thread_denied\":true,\"different_logon_tested\":false}\n";return 0;
 }catch(const Failure& f){std::cout<<"{\"ok\":false,\"stage\":\""<<f.stage<<"\",\"code\":"<<f.code<<"}\n";return 1;}
 catch(...){std::cout<<"{\"ok\":false,\"unexpected\":true}\n";return 2;}
}
