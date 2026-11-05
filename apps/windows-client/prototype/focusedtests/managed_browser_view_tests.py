from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[4];s=(root/'apps/windows-client/prototype/online_app.hpp').read_text();a=s.index(' void OnContextInitialized()');left=s.index('{',a);depth=1;i=left+1
while depth:depth+=(s[i]=='{')-(s[i]=='}');i+=1
method=s[a:i];assert 'window.runtime_style=CEF_RUNTIME_STYLE_ALLOY;' in method,'managed view must not create Chrome multi-tab windows'
code=r"""
#include <cassert>
#include <string>
struct Owner{};struct OnlineClient{explicit OnlineClient(Owner*){}};
constexpr int CEF_RUNTIME_STYLE_ALLOY=2,STATE_ENABLED=1;bool created=false,quit=false,succeed=true;
void CefQuitMessageLoop(){quit=true;}
struct CefWindowInfo{int runtime_style=0;struct{int x,y,w,h;}bounds;void SetAsPopup(void*,const wchar_t*){}};
struct CefBrowserSettings{int javascript=0;};
struct CefBrowserHost{static bool CreateBrowser(CefWindowInfo w,OnlineClient*c,const char*url,CefBrowserSettings b,void*,void*){assert(w.runtime_style==2&&w.bounds.w==1000&&w.bounds.h==720&&b.javascript==1&&std::string(url)=="https://example.com/");delete c;created=true;return succeed;}};
struct Base{virtual void OnContextInitialized()=0;};struct App:Base{Owner*owner_;explicit App(Owner*p):owner_(p){}
"""+method+r"""
};int main(){Owner o;for(bool own:{false,true})for(bool ok:{false,true}){created=quit=false;succeed=ok;App a(own?&o:nullptr);a.OnContextInitialized();assert(created==own);assert(quit==(!own||!ok));}}
"""
with tempfile.TemporaryDirectory(dir='/root/.hermes/cache/scratch') as d:
 p=Path(d);(p/'t.cpp').write_text(code);subprocess.run(['g++','-std=c++20',str(p/'t.cpp'),'-o',str(p/'t')],check=True);subprocess.run([str(p/'t')],check=True)
print('4 extracted real OnContextInitialized cases: same managed CEF owner/settings/url, single Alloy-style view')
