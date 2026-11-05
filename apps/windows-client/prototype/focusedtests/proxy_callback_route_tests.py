from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[4];s=(root/'apps/windows-client/prototype/online_app.hpp').read_text()
a=s.index(' void OnBeforeCommandLineProcessing(');left=s.index('{',a);depth=1;i=left+1
while depth:
 depth+=(s[i]=='{')-(s[i]=='}');i+=1
method=s[a:i]
assert 'AppendSwitch("disable-chrome-login-prompt")' in method,'missing Chrome auth callback routing switch'
code=r"""
#include <memory>
#include <string>
#include <map>
#include <set>
#include <cassert>
using CefString=std::string;
struct CefCommandLine{std::set<std::string> flags;std::map<std::string,std::string> values;void AppendSwitch(const char*s){flags.insert(s);}void AppendSwitchWithValue(std::string a,std::string b){values[a]=b;}};
template<class T>using CefRefPtr=std::shared_ptr<T>;
struct Owner{struct{unsigned short port=1234;}offer;};
struct Base{virtual void OnBeforeCommandLineProcessing(const CefString&,CefRefPtr<CefCommandLine>)=0;};
struct App:Base {Owner*owner_; explicit App(Owner*o):owner_(o){}
"""+method+r"""
};
int main(){Owner o;for(auto type:{"","renderer","gpu-process"})for(bool own:{false,true}){App a(own?&o:nullptr);auto c=std::make_shared<CefCommandLine>();a.OnBeforeCommandLineProcessing(type,c);bool root=std::string(type).empty()&&own;assert(c->flags.contains("disable-chrome-login-prompt")==root);assert(c->values.contains("proxy-server")==root);assert(c->flags.contains("disable-quic"));assert(!c->flags.contains("no-sandbox"));if(root){assert(c->values["proxy-server"]=="http://127.0.0.1:1234");assert(c->values["proxy-bypass-list"]=="<-loopback>");}}}
"""
with tempfile.TemporaryDirectory(dir='/root/.hermes/cache/scratch') as d:
 p=Path(d);(p/'t.cpp').write_text(code);subprocess.run(['g++','-std=c++20',str(p/'t.cpp'),'-o',str(p/'t')],check=True);subprocess.run([str(p/'t')],check=True)
print('6 extracted production command-line cases passed: owned root only; proxy and safety switches unchanged')
