#!/usr/bin/env python3
"""Portable extraction of the exact diagnostic caller; not Windows execution."""
import pathlib, subprocess, tempfile, os
root = pathlib.Path(__file__).resolve().parents[3]
source = (root/'apps/windows-client/src/login_win.cpp').read_text()
assert '// PLATFORM_HTTPS_PORTABLE_BEGIN' in source, 'missing bounded platform HTTPS diagnostic'
block = source.split('// PLATFORM_HTTPS_PORTABLE_BEGIN',1)[1].split('// PLATFORM_HTTPS_PORTABLE_END',1)[0]
harness = r'''
#include "orangespace/platform_session.hpp"
#include <cassert>
#include <optional>
#include <string>
#include <vector>
#include <iostream>
namespace ns = orangespace::node_session;
'''+block+r'''
struct Identity {std::string central_user_id="u",central_session_id="s",username="a",role="user";long user_epoch=1,expires_at=9;};
struct Node {std::string node_id;};
struct State {int logins=0,logouts=0,restores=0;unsigned wrong=401,stale=401;bool fail_nodes=false,fail_logout=false,changed=false,empty=false;};
struct S {
 State* p; Identity i;
 const Identity& identity() const{return i;}
 void revalidate(){}
 std::vector<Node> nodes(){if(p->fail_nodes)throw 1;if(p->empty)return {};return {{"node"}};}
 orangespace::platform_session::SerializedSecret export_envelope(){return orangespace::platform_session::SerializedSecret("private-envelope");}
 void logout(){++p->logouts;if(p->fail_logout)throw 1;}
};
struct Caller {
 State* p;
 S login(int,std::string_view,std::string_view password){++p->logins;if(p->logins==1){assert(password!="secret");if(p->wrong!=200)throw orangespace::platform_session::HttpStatusError(p->wrong);}assert(password!="");return {p,{}};}
 S restore(int,std::string_view){++p->restores;if(p->logouts && p->stale!=200)throw orangespace::platform_session::HttpStatusError(p->stale);S s{p,{}};if(p->changed)s.i.central_session_id="other";return s;}
};
int main(){
 const char* stage="stdin";
 auto read=[](std::string input,size_t limit){size_t n=0;return platform_diag::line([&](char& c){if(n==input.size())return false;c=input[n++];return true;},limit);};
 assert(read("alice\nNOT_CONSUMED",256).view()=="alice");
 for(auto input:{std::string("\n"),std::string("a\r\n"),std::string("a"),std::string("\xff\n"),std::string(257,'a')+"\n"}){bool denied=false;try{read(input,256);}catch(...){denied=true;}assert(denied);}
 assert(read(std::string(256,'a')+"\n",256).view().size()==256);
 for(int mode=0;mode<10;++mode){State state;state.fail_nodes=mode==1;state.wrong=mode==2?403:mode==3?200:401;state.fail_logout=mode==4;state.stale=mode==5?503:mode==8?200:401;state.changed=mode==6;state.empty=mode==9;
 bool passed=false;try{auto count=platform_diag::run(0,"alice","secret",mode==7?"missing":"",Caller{&state},stage);assert(count==(mode==9?0u:1u));passed=true;}catch(...){}
 assert(passed==(mode==0 || mode==9));
 if(mode==2)assert(state.logouts==0);else assert(state.logouts>=1);
 if(mode==3)assert(state.logins==1 && state.logouts==1);
 }
 std::cout<<"platform HTTPS diagnostic portable caller tests passed\n";
}
'''
with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
    cpp=pathlib.Path(tmp)/'test.cpp'; exe=pathlib.Path(tmp)/'test'
    cpp.write_text(harness)
    subprocess.run(['g++','-std=c++20','-Wall','-Wextra','-Werror','-I'+str(root/'apps/windows-client/include'),str(cpp),str(root/'apps/windows-client/src/node_session_win.cpp'),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
assert 'L"--platform-https-stdin"' in source, 'missing Windows command dispatch'
assert 'GetFileType(input)!=FILE_TYPE_PIPE' in source, 'stdin must be a pipe, not console/file'
assert 'Platform HTTPS diagnostic passed nodes=' in source
assert 'catch (...)' in source, 'mode boundary must suppress nonstandard exceptions'
