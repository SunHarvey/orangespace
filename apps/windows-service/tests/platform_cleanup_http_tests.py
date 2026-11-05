#!/usr/bin/env python3
"""Compile real SDK federation + receipt bodies with injected HTTP, not Native."""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
source = (ROOT / 'apps/windows-client/src/node_session_win.cpp').read_text()
methods = source[source.index('const detail::NodeEntry& TrustedCatalog::federation_node('):source.index('NodeSession NodeSession::login(')]
receipt = (ROOT / 'apps/windows-service/src/platform_chain_windows.inc').read_text()
receipt = receipt[receipt.index('struct PlatformReceipt {'):receipt.index('class PlatformReceipts {')]
cpp = r'''
#include "orangespace/platform_protocol.hpp"
#include <iostream>
#include <cwchar>
using namespace orangespace;
const std::string nid="33333333-3333-4333-8333-333333333333";
unsigned pre=200,post=200; bool wrong=false,duplicate=false;int gets=0,posts=0;
std::string payload=R"({"schema":1,"local_session_state":"revoked"})";
namespace orangespace::node_session {
namespace {
[[noreturn]] void fail(const char* s){throw std::runtime_error(s);}
struct Body {std::string value;std::string_view view()const{return value;}};
struct Response {unsigned status;std::string node;Body body;};
struct Transport {
 explicit Transport(const detail::NodeEntry&){}
 Response request(const wchar_t* method,const wchar_t* path,std::string_view={}) {
  if(std::wcscmp(method,L"GET")==0){++gets;detail::require(std::wcscmp(path,L"/healthz")==0);return {pre,nid,{"{}"}};}
  ++posts;detail::require(std::wcscmp(method,L"POST")==0);
  detail::require(std::wcscmp(path,L"/federation/v1/sessions/exchange-cleanup")==0||std::wcscmp(path,L"/federation/v1/sessions/exchange")==0);
  // Models unique_header rejection before request returns.
  detail::require(!duplicate);
  return {post,wrong?"wrong-node":nid,{payload}};
 }
};
}
TrustedCatalog TrustedCatalog::load(const std::wstring&){return TrustedCatalog({detail::NodeEntry{"test",nid,"node.test",443,{}}});}
'''+methods+r'''
}
namespace orangespace::service::win {
using namespace chain; namespace detail=node_session::detail;
'''+receipt+r'''
}
void check(bool ok,const char* label){if(!ok)throw std::runtime_error(label);}
int main(){
 using service::win::PlatformReceipt;
 auto catalog=std::make_shared<node_session::TrustedCatalog>(node_session::TrustedCatalog::load(L"mock"));
 auto reset=[] {pre=post=200;wrong=duplicate=false;gets=posts=0;payload=R"({"schema":1,"local_session_state":"revoked"})";};
 auto attempt=[&](bool expected,const char* label){PlatformReceipt r;r.catalog=catalog;r.node=nid;r.submitted=true;r.ticket.emplace();r.ticket->exchange_id=nid;r.ticket->exchange_token=platform_session::SerializedSecret(std::string(43,'B'));bool threw=false;try{r.cleanup();}catch(...){threw=true;}check(r.complete==expected&&r.ticket.has_value()!=expected&&threw!=expected,label);};
 reset();pre=410;attempt(false,"preflight410 lost receipt");check(gets==1&&posts==0,"preflight submitted POST");
 reset();post=410;attempt(true,"cleanup POST410 not absent");check(posts==1,"cleanup not submitted");
 reset();post=401;attempt(false,"401 completed");
 reset();post=410;wrong=true;attempt(false,"wrong header completed");
 reset();post=410;duplicate=true;attempt(false,"duplicate header completed");
 reset();post=410;payload=std::string(16385,'x');attempt(false,"oversize completed");
 reset();payload=R"({"schema":1,"local_session_state":"active"})";attempt(false,"malformed revoked completed");
 reset();payload=R"({"schema":1.0,"local_session_state":"revoked"})";attempt(false,"fraction schema completed");
 reset();attempt(true,"valid revoked failed");
 reset();post=410;bool rejected=false;try{catalog->federation_exchange(nid,"{\"schema\":1,\"exchange_id\":\""+nid+"\",\"exchange_token\":\""+std::string(43,'B')+"\"}",false,[](auto){});}catch(const node_session::HttpStatusError& e){rejected=e.status_code()==410;}check(rejected&&posts==1,"ordinary exchange410 not HttpStatusError");
 std::cout<<"PASS actual federation_exchange + PlatformReceipt: preflight410 retained/no POST; cleanup POST410 only; 401/header/duplicate/size/revoked/exchange negatives (injected HTTP model, NOT Native)\n";
}
'''
with tempfile.TemporaryDirectory(prefix='f1-http-', dir=os.environ.get('TMPDIR')) as tmp:
    src=Path(tmp)/'test.cpp'; exe=Path(tmp)/'test'; src.write_text(cpp)
    subprocess.run(['g++','-std=c++20','-Wall','-Wextra','-Werror','-pthread','-I'+str(ROOT/'apps/windows-client/include'),'-I'+str(ROOT/'apps/windows-service/include'),str(src),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
