// Isolated nonsecret sentinel only: no API, SCM, accounts, tasks or profiles.
#include <windows.h>
#include <iostream>
#include <string>
#if __has_include("phase1_secure_channel.hpp")
#include "phase1_secure_channel.hpp"
#include <thread>
#include <exception>
using namespace phase1::secure;
int wmain(int argc,wchar_t** argv){
 if(argc==2&&std::wstring_view(argv[1])==L"--bound") {
#ifndef PHASE1_SECURE_BOUND_CHANNEL
  std::cerr<<"RED: authenticated framed channel with fail-closed ownership missing\n";return 1;
#else
  try {
   auto self=HeldPeer::capture(GetCurrentProcess());
   auto name=L"\\\\.\\pipe\\OrangeSpace-secure-bound-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64());
   auto pipe=create_server(name,self.identity().sid);std::exception_ptr failure;
   std::thread peer([&]{try{
    auto channel=SecureChannel::client(open_client(name),HeldPeer::capture(GetCurrentProcess()),Deadline(2000));
    SecretBuffer marker;marker.assign("NONSECRET_BOUND");channel.send(marker,Deadline(2000));
    require(channel.receive(Deadline(2000)).view()=="NONSECRET_BOUND","bound_reply");
    Sleep(500);
   }catch(...){failure=std::current_exception();}});
   try {
    connect(pipe.get(),Deadline(2000));
    auto channel=SecureChannel::server(std::move(pipe),HeldPeer::capture(GetCurrentProcess()),Deadline(2000));
    auto marker=channel.receive(Deadline(2000));channel.send(marker,Deadline(2000));
    bool timed=false;try{(void)channel.receive(Deadline(70));}catch(const Failure& f){timed=f.code==WAIT_TIMEOUT;}
    require(timed&&!channel.open(),"timeout_closes_channel");
   }catch(...){peer.join();throw;}
   peer.join();if(failure)std::rethrow_exception(failure);
   std::cout<<"{\"case\":\"bound_authenticated_frames_and_timeout_close\",\"ok\":true}\n";return 0;
  }catch(const Failure& f){std::cout<<"FAIL "<<f.stage<<" "<<f.code<<"\n";return 1;}
#endif
 }
 try {
  auto expected=HeldPeer::capture(GetCurrentProcess());
  auto name=L"\\\\.\\pipe\\OrangeSpace-secure-sentinel-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64());
  auto server=create_server(name,expected.identity().sid);
  std::exception_ptr client_error;
  std::thread client([&]{try{
   auto pipe=open_client(name);
   authenticate_server(pipe.get(),expected);
   SecretBuffer marker; marker.assign("NONSECRET_SENTINEL");
   send_frame(pipe.get(),marker,Deadline(2000));
   auto reply=receive_frame(pipe.get(),Deadline(2000));
   require(reply.view()=="NONSECRET_SENTINEL","duplex_reply");
  }catch(...){client_error=std::current_exception();}});
  try {
   connect(server.get(),Deadline(2000));
   auto incoming=receive_frame(server.get(),Deadline(2000));
   authenticate_client(server.get(),expected);
   require(incoming.view()=="NONSECRET_SENTINEL","duplex_request");
   send_frame(server.get(),incoming,Deadline(2000));
  } catch(...) {client.join();throw;}
  client.join();if(client_error)std::rethrow_exception(client_error);
  std::cout<<"{\"case\":\"bounded_duplex_actual_token\",\"ok\":true,\"session\":"<<expected.identity().session<<",\"full_bootstrap\":false}\n";
  return 0;
 }catch(const Failure& f){std::cout<<"{\"ok\":false,\"stage\":\""<<f.stage<<"\",\"code\":"<<f.code<<"}\n";return 1;}
 catch(...){std::cout<<"{\"ok\":false,\"unexpected\":true}\n";return 2;}
}
#else
int wmain(){std::cerr<<"RED: bounded authenticated channel missing\n";return 1;}
#endif
