#!/usr/bin/env python3
"""Compile/run exact production caller with injected RPCs; not native IPC evidence."""
import os, pathlib, subprocess, tempfile
root=pathlib.Path(__file__).resolve().parents[3]
s=(root/'apps/windows-client/src/login_win.cpp').read_text()
assert '// PLATFORM_CHAIN_PORTABLE_BEGIN' in s, 'missing platform chain caller'
b=s.split('// PLATFORM_CHAIN_PORTABLE_BEGIN',1)[1].split('// PLATFORM_CHAIN_PORTABLE_END',1)[0]
h=r'''
#include "orangespace/platform_session.hpp"
#include "orangespace/service_chain.hpp"
#include <optional>
#include <cassert>
#include <iostream>
namespace platform_diag {namespace nd=orangespace::node_session::detail;}
'''+b+r'''
using B=orangespace::service::chain::Binding;
struct Node {std::string node_id="node";};
struct S {int* out;std::vector<Node> nodes(){return {{}};}void logout(){++*out;}};
struct G {std::string user()const{return "user";}std::string node()const{return "node";}};
struct State {int calls=0,fail=0,central=0,logged=0,retired=0;bool mismatch=false,dead=false,cleanup_fail=false;std::vector<B> active;};
struct C {
 State* p;
 void tick(){if(++p->calls==p->fail)throw 1;}
 S login(int,std::string_view,std::string_view){tick();return {&p->central};}
 G authorize(S&,const Node&){tick();return {};}
 std::string uuid(){tick();return p->calls%2?"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";}
 B start(const G&,std::string_view id){tick();B b{"user",std::string(id),"node",std::to_string(p->calls),1};p->active.push_back(b);if(p->mismatch)b.node="other";return b;}
 std::vector<B> active(const G&){tick();if(p->dead && p->active.size()==1)return {};return p->active;}
 void stop(const G&,const B& b){tick();if(p->cleanup_fail)throw 1;for(auto i=p->active.begin();i!=p->active.end();++i)if(*i==b){p->active.erase(i);return;}throw 1;}
 void logout(const G&){tick();if(p->cleanup_fail)throw 1;++p->logged;p->active.clear();}
 void retire(const G&){++p->retired;if(p->cleanup_fail)throw 1;p->active.clear();}
};
int main(){
 for(int fail=0;fail<=13;++fail){State p;p.fail=fail;const char* stage="";bool clean=true,pass=false;try{platform_chain_diag::run(0,"u","p","node",C{&p},stage,clean);pass=true;}catch(...){}assert(pass==(fail==0));if(fail!=1)assert(p.central==1);assert(p.active.empty());assert(clean);}
 for(int mode=0;mode<4;++mode){State p;p.mismatch=mode==0;p.dead=mode==1;p.cleanup_fail=mode==2;const char* stage="";bool clean=true,pass=false;try{platform_chain_diag::run(0,"u","p",mode==3?"absent":"node",C{&p},stage,clean);pass=true;}catch(...){}assert(!pass);assert(p.central==1);if(mode==2)assert(!clean);else assert(p.active.empty());}
 std::cout<<"platform chain exact caller injection passed\n";
}
'''
with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as d:
 p=pathlib.Path(d);(p/'test.cpp').write_text(h)
 subprocess.run(['g++','-std=c++20','-Wall','-Wextra','-Werror','-I'+str(root/'apps/windows-client/include'),'-I'+str(root/'apps/windows-service/include'),str(p/'test.cpp'),str(root/'apps/windows-client/src/node_session_win.cpp'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
assert 'L"--platform-chain-login-stdin"' in s
branch=s.split('L"--platform-chain-login-stdin"',1)[1].split('// This branch owns its complete exception boundary',1)[0]
assert branch.index('current_interactive_session()') < branch.index('PlatformConfig::load') < branch.index('platform_diag::line')
assert '!elevation.TokenIsElevated' in branch and 'WinInteractiveSid' in branch
assert 'sc::authorize_platform(s,n)' in branch and 'sc::start_registered_tunnel(g,id)' in branch
assert 'BCryptGenRandom' in branch and 'CredentialStore' not in branch
assert 'renewal_tested=false' in branch and 'return cleanup_complete?1:3' in branch
