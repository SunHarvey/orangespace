// Real private-pipe transport sentinels; every byte is a known NONSECRET marker.
#include "phase1_secure_channel.hpp"
#include <thread>
#include <iostream>
#include <functional>
#include <exception>
#ifdef PHASE1_SECURE_OLD_READ_BASELINE
#include "phase1_native.hpp" // Read-only original baseline; never execute old drivers.
#endif
using namespace phase1::secure;
static unsigned sequence{};
static void pair(const std::function<void(HANDLE)>& a,const std::function<void(HANDLE)>& b){
 auto self=HeldPeer::capture(GetCurrentProcess());
 auto name=L"\\\\.\\pipe\\OrangeSpace-secure-io-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(++sequence);
 auto server=create_server(name,self.identity().sid);std::exception_ptr error;
 std::thread client([&]{try{auto p=open_client(name);b(p.get());}catch(...){error=std::current_exception();}});
 try{connect(server.get(),Deadline(1500));a(server.get());}catch(...){client.join();throw;}
 client.join();if(error)std::rethrow_exception(error);
}
static void timeout(const std::function<void()>& f,const char* stage){
 bool rejected=false;auto start=GetTickCount64();
 try{f();}catch(const Failure& e){rejected=e.code==WAIT_TIMEOUT;}
 require(rejected&&GetTickCount64()-start<500,stage);
}
static void acl_test(){
 auto self=HeldPeer::capture(GetCurrentProcess());
 auto name=L"\\\\.\\pipe\\OrangeSpace-secure-acl-"+std::to_wstring(GetCurrentProcessId());
 bool alias_rejected=false;try{auto invalid=create_server(name+L"-invalid",L"WD");}catch(const Failure& f){alias_rejected=std::string_view(f.stage)=="canonical_numeric_peer_sid";}
 require(alias_rejected,"self_asserted_sddl_sid_alias_rejected");
 auto server=create_server(name,self.identity().sid);
 bool rejected=false;try{auto duplicate=create_server(name,self.identity().sid);}catch(const Failure&){rejected=true;}
 require(rejected,"first_instance_squatter_rejected");
 DWORD bytes{};GetKernelObjectSecurity(server.get(),OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,nullptr,0,&bytes);
 require(bytes>0&&bytes<65536,"pipe_acl_size");std::vector<BYTE> sd(bytes);
 require(GetKernelObjectSecurity(server.get(),OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,reinterpret_cast<PSECURITY_DESCRIPTOR>(sd.data()),bytes,&bytes),"pipe_acl_read");
 HANDLE raw{},imp{};require(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_DUPLICATE,&raw),"acl_primary");Handle token(raw);
 require(DuplicateTokenEx(token.get(),TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES,nullptr,SecurityImpersonation,TokenImpersonation,&imp),"acl_impersonation");Handle duplicate(imp);
 // AccessCheck-only token; never assigned/impersonated/launched. Exclude the
 // SSH admin's enabled SeTakeOwnership override when testing discretionary ACL.
 require(AdjustTokenPrivileges(duplicate.get(),TRUE,nullptr,0,nullptr,nullptr),"acl_disable_privileges");
 GENERIC_MAPPING mapping{FILE_GENERIC_READ,FILE_GENERIC_WRITE,FILE_GENERIC_EXECUTE,FILE_ALL_ACCESS};
 auto granted=[&](DWORD access){PRIVILEGE_SET privileges{};DWORD size=sizeof(privileges),mask{};BOOL allowed{};
  require(AccessCheck(reinterpret_cast<PSECURITY_DESCRIPTOR>(sd.data()),duplicate.get(),access,&mapping,&privileges,&size,&mask,&allowed),"acl_accesscheck");return allowed!=FALSE;};
 require(granted(FILE_READ_DATA|FILE_WRITE_DATA|FILE_READ_ATTRIBUTES|READ_CONTROL|SYNCHRONIZE),"narrow_client_rights");
 require(!granted(FILE_CREATE_PIPE_INSTANCE),"no_create_instance_right");
 require(!granted(WRITE_DAC),"no_write_dac_right");
 require(!granted(WRITE_OWNER),"no_write_owner_right");
}
int wmain(){
 try {
  // Original quarantined read_exact accepts already-buffered data after expiry.
  pair([](HANDLE s){Sleep(40);char value{};
#ifdef PHASE1_SECURE_OLD_READ_BASELINE
   bool rejected=false;try{phase1::read_exact(s,&value,1,GetTickCount64());}catch(phase1::Failure e){rejected=e.code==WAIT_TIMEOUT;}
   require(rejected,"expired_buffered_read_must_reject");
#else
   timeout([&]{transfer(s,&value,1,false,Deadline(0));},"expired_buffered_read_must_reject");
#endif
  },[](HANDLE c){char value='N';transfer(c,&value,1,true,Deadline(1000));Sleep(100);});
  pair([](HANDLE s){timeout([&]{(void)receive_frame(s,Deadline(70));},"stalled_read");},[](HANDLE){Sleep(250);});
  pair([](HANDLE s){SecretBuffer b;b.assign(std::string(32768,'N'));timeout([&]{send_frame(s,b,Deadline(70));},"stalled_write");},[](HANDLE){Sleep(250);});
  pair([](HANDLE s){char b[128]{};timeout([&]{transfer(s,b,128,false,Deadline(70));},"slow_positive_progress");},[](HANDLE c){char n='N';for(unsigned i=0;i<128;++i){transfer(c,&n,1,true,Deadline(1000));Sleep(3);}});
  pair([](HANDLE s){timeout([&]{(void)receive_frame(s,Deadline(70));},"partial_header_deadline");},[](HANDLE c){BYTE first=10;transfer(c,&first,1,true,Deadline(1000));Sleep(250);});
  pair([](HANDLE s){bool failed=false;try{(void)receive_frame(s,Deadline(500));}catch(const Failure& f){failed=f.code!=WAIT_TIMEOUT;}require(failed,"peer_loss_rejected");},[](HANDLE){});
  pair([](HANDLE s){bool failed=false;try{(void)receive_frame(s,Deadline(500));}catch(const Failure&){failed=true;}require(failed,"oversize_rejected");},[](HANDLE c){BYTE header[4]{0xff,0xff,0xff,0x7f};transfer(c,header,4,true,Deadline(1000));});
  // Repeat native cancellation/completion races; no OVERLAPPED reuse after free.
  for(unsigned i=0;i<40;++i)pair([](HANDLE s){char n{};try{transfer(s,&n,1,false,Deadline(2));}catch(const Failure& f){require(f.code==WAIT_TIMEOUT,"cancel_completion_result");}},[i](HANDLE c){Sleep(i%4);char n='N';transfer(c,&n,1,true,Deadline(500));});
  acl_test();
  auto self=HeldPeer::capture(GetCurrentProcess());
  std::cout<<"{\"kind\":\"isolated_secure_io\",\"ok\":true,\"cancel_races\":40,\"session\":"<<self.identity().session<<",\"integrity\":"<<self.identity().integrity<<",\"full_bootstrap\":false}\n";return 0;
 }catch(const Failure& f){std::cout<<"{\"ok\":false,\"stage\":\""<<f.stage<<"\",\"code\":"<<f.code<<"}\n";return 1;}
 catch(...){std::cout<<"{\"ok\":false,\"unexpected\":true}\n";return 2;}
}
