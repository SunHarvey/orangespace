#include "orangespace/node_session.hpp"
#include <cassert>
#include <iostream>
#include <cstring>
using namespace orangespace::node_session;
namespace nd=orangespace::node_session::detail;
static int calls=0,mode=0;
static std::string seen_path;
static const char* expected_body=nullptr;
static const char* expected_token=nullptr;
static int32_t injected(const OsHttpsRequest* req,uint8_t* out,size_t cap,uint32_t* status,uint8_t* header,size_t hcap,uint32_t* hlen) {
  ++calls;assert(cap==OS_HTTPS_MAX_RESPONSE && hcap==64);
  assert(std::string_view(reinterpret_cast<const char*>(req->ca_pem.ptr),req->ca_pem.len)=="private CA");
  assert(std::string_view(reinterpret_cast<const char*>(req->origin.ptr),req->origin.len)=="https://node.test:443");
  seen_path.assign(reinterpret_cast<const char*>(req->path.ptr),req->path.len);
  if(expected_body) assert(req->body.ptr==reinterpret_cast<const uint8_t*>(expected_body));
  if(expected_token) assert(req->bearer.ptr==reinterpret_cast<const uint8_t*>(expected_token));
  if(mode==1) return -1;
  *status=mode==2?401:200;
  const std::string id=mode==3?"22222222-2222-4222-8222-222222222222":"11111111-1111-4111-8111-111111111111";
  *hlen=static_cast<uint32_t>(id.size());memcpy(header,id.data(),id.size());
  if(mode==4) return 16385;
  if(mode==5) return 1048577;
  memcpy(out,"{}",2);return 2;
}
template<class F> void rejects(F f) {bool bad=false;try{f();}catch(const std::runtime_error&){bad=true;}assert(bad);}
int main(){
  nd::NodeEntry node{"node-a","11111111-1111-4111-8111-111111111111","node.test",443,"/nodes/11111111-1111-4111-8111-111111111111"};
  node.ca_pem=std::make_shared<const std::string>("private CA");
  bool received=false;
  auto receive=[&](unsigned status,std::string_view header,std::string_view body){received=true;assert(status==200 && header==node.node_id && body=="{}");};
  nd::private_https_request(node,"GET","/healthz",{},{},true,receive,injected);
  assert(received && seen_path==node.api_prefix+"/healthz");
  const std::string body="{\"password\":\"fixture\"}",token(43,'A');
  expected_body=body.data();expected_token=token.data();
  nd::private_https_request(node,"POST","/v1/auth/login",body,token,true,receive,injected);
  expected_body=nullptr;expected_token=nullptr;
  rejects([&]{nd::private_https_request(node,"GET","/healthz",{},{},true,[](unsigned,std::string_view,std::string_view){throw std::runtime_error("consumer rejected");},injected);});
  mode=1;received=false;
  try {nd::private_https_request(node,"GET","/healthz",{},{},true,receive,injected);assert(false);}catch(const std::runtime_error& e){assert(std::string_view(e.what())=="app-private HTTPS failed");}
  assert(!received);
  mode=2;
  try{nd::private_https_request(node,"GET","/healthz",{},{},true,[&](unsigned s,std::string_view h,std::string_view b){nd::require_http_response(node,s,h,b.size());},injected);assert(false);}catch(const HttpStatusError& e){assert(e.status_code()==401);}
  for(mode=3;mode<=5;++mode) rejects([&]{nd::private_https_request(node,"GET","/healthz",{},{},true,receive,injected);});
  mode=4;node.api_prefix.clear();
  nd::private_https_request(node,"GET","/control/v1/me/nodes?limit=100",{},{},false,[](unsigned,std::string_view,std::string_view b){assert(b.size()==16385);},injected);
  mode=0;node.ca_pem.reset();const auto before=calls;
  rejects([&]{nd::private_https_request(node,"GET","/healthz",{},{},true,receive,injected);});assert(calls==before);
  std::cout<<"app-private C ABI bridge policy passed\n";
}
