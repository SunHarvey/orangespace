"""Bounded production wire/source tests; not Windows runtime evidence."""
from pathlib import Path
import subprocess,tempfile,unittest
R=Path(__file__).resolve().parents[4]
class BrowserTests(unittest.TestCase):
 def test_bounded_navigation(self):
  code=r'''#include "private_channel.hpp"
#include <cassert>
using namespace orangespace::prototype;
int main(){assert(OnlineNavigation("https://example.com/"));assert(!OnlineNavigation("https://x/\r\nHeader:x"));assert(!OnlineNavigation(std::string("https://x/")+std::string(2048,'a')));assert(!OnlineNavigation("file:///c:/"));BrowserFrame f;assert(ValidBrowserFrame(f));f.url_size=2049;assert(!ValidBrowserFrame(f));}'''
  with tempfile.TemporaryDirectory(dir='/root/.hermes/cache/scratch') as d:
   p=Path(d);(p/'t.cpp').write_text(code)
   subprocess.run(['g++','-std=c++20','-I'+str(R/'apps/windows-client/prototype'),str(p/'t.cpp'),'-o',str(p/'t')],check=True)
   subprocess.run([str(p/'t')],check=True)
 def test_browser_request_is_exact_and_bounded(self):
  code=r'''#include "orangespace/platform_protocol.hpp"
#include <cassert>
int main(){namespace p=orangespace::service::platform;namespace c=orangespace::service::chain;
 c::Binding b{"11111111-1111-4111-8111-111111111111","22222222-2222-4222-8222-222222222222","33333333-3333-4333-8333-333333333333","44444444-4444-4444-8444-444444444444",1};
 auto run=[&](int cmd,std::string url){auto body=std::string("{\"auth_id\":\"11111111-1111-4111-8111-111111111111\",\"binding\":")+c::binding_json(b)+",\"command\":"+std::to_string(cmd)+",\"url\":"+c::quote(url)+"}";auto frame=p::request_frame(9,body);return p::parse_request(frame).op;};
 assert(run(0,"")==9);assert(run(1,"https://example.com/")==9);assert(run(6,"")==9);
 for(auto [cmd,url]:{std::pair{7,""},std::pair{2,"https://example.com/"},std::pair{1,"file:///c:/"},std::pair{1,"https://x/\r\n"}}){bool rejected=false;try{run(cmd,url);}catch(...){rejected=true;}assert(rejected);}
}'''
  with tempfile.TemporaryDirectory(dir='/root/.hermes/cache/scratch') as d:
   p=Path(d);(p/'t.cpp').write_text(code)
   subprocess.run(['g++','-std=c++20','-I'+str(R/'apps/windows-service/include'),'-I'+str(R/'apps/windows-client/include'),str(p/'t.cpp'),'-o',str(p/'t')],check=True)
   subprocess.run([str(p/'t')],check=True)
 def test_service_cef_wiring(self):
  ctl=(R/'apps/windows-service/prototype/online_control_win.cpp').read_text()
  self.assertIn('request.op==9',ctl)
  self.assertNotIn('single_start',ctl)
  cef=(R/'apps/windows-client/prototype/online_app.hpp').read_text()
  for item in ['OnAddressChange','OnTitleChange','OnLoadingStateChange','CefPostTask','GoBack','GoForward','Reload','CloseBrowser'] :self.assertIn(item,cef)
if __name__=='__main__':unittest.main()
