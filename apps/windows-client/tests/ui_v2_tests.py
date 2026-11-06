"""Approved v2 caller contracts; source evidence, not native GUI acceptance."""
import pathlib
import unittest
ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'src/main_win.cpp'
class UiV2(unittest.TestCase):
    def test_protected_configuration_is_automatic_executable_sibling(self):
        source = SOURCE.read_text()
        self.assertIn('GetModuleFileNameW', source)
        self.assertIn('parent_path() / L"platform.json"', source)
        self.assertNotIn('trust_ = edit(', source)
    def test_remember_controls_persistence(self):
        source = SOURCE.read_text()
        self.assertIn('BS_AUTOCHECKBOX', source)
        self.assertIn('if(remember)', source)
    def test_tabs_and_file_context_preserve_identity(self):
        source = SOURCE.read_text()
        self.assertIn('active_sandbox_', source)
        self.assertIn('auth_.retain(now())', source)
        self.assertIn('FileContext', source)
        self.assertNotIn('current_node', source)
    def test_automatic_node_open_is_one_worker_and_browser_stays_locked(self):
        source = SOURCE.read_text()
        self.assertIn('void open_node(', source)
        self.assertIn('ui_v2::default_sandbox', source)
        self.assertIn('browser_launch_decision()', source)
        self.assertNotIn('LVS_REPORT', source)
    def test_logout_requests_nonblocking_file_drain_before_identity_reuse(self):
        source = SOURCE.read_text()
        invalidate = source.split('  void invalidate_ui() {', 1)[1].split('  void begin_close()', 1)[0]
        self.assertIn('file_panel_->request_logout()', invalidate)
        self.assertNotIn('file_panel_->logout()', invalidate)
        cleanup = source.split('  void cleanup_step() {', 1)[1].split('  void command(', 1)[0]
        self.assertIn('const bool local=drain_->ready() && (!file_panel_ || file_panel_->can_close())', cleanup)
        self.assertLess(cleanup.index('file_panel_->logout()'), cleanup.index('draining_=false'))

    def test_chooser_primary_restores_default_and_native_menu_is_separate(self):
        source=SOURCE.read_text()
        self.assertIn('open_node(static_cast<std::size_t>(id-1000),false)',source)
        self.assertIn('node_menu(',source)
        self.assertIn('NewIndependent',source)
        self.assertIn('TrackPopupMenu',source)
        self.assertIn('if(!additional && requested.empty())default_preference',source)
        self.assertIn('if(!already_open && !tunnels_.contains(active_sandbox_)',source)
        self.assertIn('if(picked==NewIndependent)open_node(index,true)',source)

    def test_actual_default_worker_retries_exact_created_uuid(self):
        import subprocess
        output=pathlib.Path('/var/tmp/hermes-runtime/tmp/orangespace-ui-v2/default-worker')
        output.mkdir(parents=True,exist_ok=True)
        text=SOURCE.read_text()
        worker='[op,node,additional,candidate,requested]'+text.split('start([op,node,additional,candidate,requested]',1)[1].split('\n      });',1)[0]+'\n      }'
        prelude=r'''
#include "orangespace/ui_v2.hpp"
#include <cassert>
#include <memory>
struct Op {std::string user="22222222-2222-4222-8222-222222222222";int expiry=100;};
struct Node {std::string node_id="33333333-3333-4333-8333-333333333333",display_name="node",alias="node";};
enum class Job {open_node};
struct Completion {Job job;Op operation;std::string local_sandbox;std::vector<orangespace::Sandbox> sandboxes;};
struct Mailbox {bool cancelled=false;};
static int creates=0,binds=0;static bool bound=false,fail_bind=true;
static std::string preferred;static bool fail_preference=false,lose_create=false;
static std::string state="closed",owner="22222222-2222-4222-8222-222222222222";
static const std::string id="11111111-1111-4111-8111-111111111111";
int now(){return 10;}
std::string default_preference(const std::string&,const std::string&,const std::string& save={}){if(!save.empty()){if(fail_preference)throw 1;preferred=save;}return preferred;}
namespace orangespace {
std::wstring widen(const std::string& s){return {s.begin(),s.end()};}
struct Process {std::string failure,output;int exit_code=0;};
Process run_broker(const std::vector<std::wstring>& args){
 const auto row=std::string(R"({"id":")")+id+R"(","user_id":")"+owner+R"(","name":"node","node_id":")"+(bound?"33333333-3333-4333-8333-333333333333":"")+R"(","state":")"+state+R"(","profile_path":"p"})";
 if(args[0]==L"create"){++creates;if(lose_create)throw 1;return {{},std::string(R"({"schema_version":1,"ok":true,"sandbox":)")+row+"}"};}
 if(args[0]==L"bind"){++binds;assert(args[4]==widen(id));if(fail_bind)throw 1;bound=true;return {{},R"({"schema_version":1,"ok":true})"};}
 return {{},std::string(R"({"schema_version":1,"ok":true,"sandboxes":[)")+(creates?row:"")+"]}"};
}
}
int main(){Op op;Node node;std::string requested;bool additional=false;auto candidate=std::make_shared<std::string>();auto work=WORKER;
 Completion first;Mailbox box;try{work(first,box);assert(false);}catch(...){}
 assert(creates==1 && binds==1 && preferred==id);
 fail_bind=false;Completion retry;work(retry,box);assert(creates==1 && binds==2 && retry.local_sandbox==id && bound);
 assert(candidate->empty()); // Only unresolved create/bind work retains the latch.
 creates=binds=0;bound=false; // Confirmed deletion: list no longer has the prior row.
 work(retry,box);assert(creates==1 && binds==1 && bound && candidate->empty());
 creates=binds=0;bound=false;preferred.clear();candidate->clear();fail_preference=true;
 try{work(first,box);assert(false);}catch(...){}assert(creates==1 && binds==0 && *candidate==id);
 fail_preference=false;work(retry,box);assert(creates==1 && binds==1 && bound);
 creates=binds=0;bound=false;preferred.clear();candidate->clear();lose_create=true;
 try{work(first,box);assert(false);}catch(...){}assert(creates==1);
 try{work(retry,box);assert(false);}catch(...){}assert(creates==1 && binds==0);
 // Exact closed restore: same UUID/Profile, no create/bind/default mutation.
 lose_create=false;creates=1;bound=true;candidate->clear();preferred="unchanged";requested=id;
 auto exact=WORKER;exact(retry,box);
 assert(retry.local_sandbox==id && retry.sandboxes.front().profile=="p" && creates==1 && binds==0 && preferred=="unchanged");
 creates=0;try{exact(retry,box);assert(false);}catch(...){}assert(creates==0);
 creates=1;state="deleting";try{exact(retry,box);assert(false);}catch(...){}assert(creates==1 && binds==0);
 state="closed";bound=false;try{exact(retry,box);assert(false);}catch(...){}assert(creates==1 && binds==0);
 bound=true;owner="44444444-4444-4444-8444-444444444444";try{exact(retry,box);assert(false);}catch(...){}assert(creates==1 && binds==0);
 assert(preferred=="unchanged");
}
'''
        src=output/'worker.cpp';src.write_text(prelude.replace('WORKER',worker))
        exe=output/'worker'
        subprocess.run(['g++','-std=c++20','-Wall','-Wextra','-Werror','-I'+str(ROOT/'include'),str(src),'-o',str(exe)],check=True)
        subprocess.run([str(exe)],check=True)

    def test_actual_node_menu_rejects_changed_identity_or_node(self):
        import subprocess
        output=pathlib.Path('/var/tmp/hermes-runtime/tmp/orangespace-ui-v2/menu-owner')
        output.mkdir(parents=True,exist_ok=True)
        source=SOURCE.read_text()
        body='  void node_menu('+source.split('  void node_menu(',1)[1].split('\n  void open_node(',1)[0]
        rebuild='  void rebuild_nodes() {'+source.split('  void rebuild_nodes() {',1)[1].split('\n  std::wstring text(',1)[0]
        harness=r'''
#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <stdexcept>
#include <cstdint>
using UINT=unsigned;using UINT_PTR=std::uintptr_t;using HMENU=int;
struct RECT{int left{},top{},right{},bottom{};};
constexpr int MF_STRING=1,MF_SEPARATOR=2,TPM_RETURNCMD=4,TPM_NONOTIFY=8;
static std::function<void()> during_popup;
static int destroyed=0;static bool fail_title=false;
int CreatePopupMenu(){return 1;}
int DestroyMenu(int){++destroyed;return 1;}
int AppendMenuW(int,int,UINT_PTR,const wchar_t*){return 1;}
int GetWindowRect(int,RECT*){return 1;}
unsigned TrackPopupMenu(int,int,int,int,int,int,void*){if(during_popup)during_popup();return 60000;}
namespace orangespace {std::wstring widen(const std::string& s){if(fail_title)throw std::bad_alloc();return {s.begin(),s.end()};}}
struct Identity{std::string central_user_id="owner";};
struct Session{Identity value;const Identity& identity()const{return value;}};
struct Node{std::string node_id="node-a",display_name="node",alias="node";};
struct MenuHandles:std::vector<int>{
 const int& operator[](std::size_t i)const{return at(i);}
 bool fail_allocation=false;
 void reserve(std::size_t n){if(fail_allocation)throw std::bad_alloc();std::vector<int>::reserve(n);}
 void push_back(int h){if(fail_allocation&&size()==capacity())throw std::bad_alloc();std::vector<int>::push_back(h);}
};
constexpr int WS_TABSTOP=1,BS_OWNERDRAW=2;
int DestroyWindow(int){return 1;}
struct Auth{
 std::shared_ptr<Session> session=std::make_shared<Session>();std::vector<Node> values{Node{}};
 auto retain(int){return session;}
 const auto& nodes()const{return values;}
};
struct Row{std::string user_id="owner",node_id="node-a",state="closed",id="saved",name="sandbox";};
struct App{
 bool busy_{},draining_{},closing_{};int window=1,opened=0;Auth auth_;
 std::vector<Row> sandboxes_{Row{}};std::vector<int> node_buttons_;MenuHandles node_menus_;
 App(){node_menus_.push_back(1);}
 int now()const{return 1;}
 static bool browser_enabled(const std::string& node){return node=="node-a";}
 int control(const wchar_t*,const wchar_t*,int,int id){return id;}
 int button(const wchar_t*,int id){return id;}
 void layout(){}
 void open_node(std::size_t,bool,std::string={}){++opened;}
 MENU_BODY
 REBUILD_BODY
};
void require(bool value){if(!value)throw std::runtime_error("stale native menu affected a new identity/node or leaked its menu");}
int main(){
 {App app;during_popup={};app.node_menu(0);require(app.opened==1);}
 {App app;during_popup=[&]{app.auth_.session=std::make_shared<Session>();};app.node_menu(0);require(app.opened==0);}
 {App app;during_popup=[&]{app.auth_.values[0].node_id="node-b";};app.node_menu(0);require(app.opened==0);}
 {App app;during_popup=[&]{app.auth_.session.reset();};app.node_menu(0);require(app.opened==0);}
 {App app;during_popup={};app.node_menus_.clear();app.node_menu(0);require(app.opened==0);}
 {App app;during_popup={};app.node_menus_.front()=0;app.node_menu(0);require(app.opened==0);}
 {App app;during_popup={};destroyed=0;fail_title=true;try{app.node_menu(0);}catch(const std::bad_alloc&){}fail_title=false;require(destroyed==1);}
 {App app;app.node_menus_.clear();app.node_menus_.shrink_to_fit();app.node_menus_.fail_allocation=true;try{app.rebuild_nodes();}catch(const std::bad_alloc&){}require(app.node_buttons_.size()==app.node_menus_.size());}
}
'''
        src=output/'menu.cpp';src.write_text(harness.replace('MENU_BODY',body).replace('REBUILD_BODY',rebuild))
        exe=output/'menu'
        subprocess.run(['g++','-std=c++20','-Wall','-Wextra','-Werror',str(src),'-o',str(exe)],check=True)
        subprocess.run([str(exe)],check=True)

    def test_actual_default_preference_uses_install_namespace(self):
        import subprocess
        source=SOURCE.read_text()
        method=source[source.index('  static std::string default_preference('):source.index('  void node_menu(')]
        harness=r'''
#include "orangespace/install_identity.hpp"
#include <stdexcept>
#include <string>
#include <map>
#include <vector>
#include <algorithm>
#include <cassert>
using HKEY=int;using DWORD=unsigned long;using BYTE=unsigned char;
constexpr int HKEY_CURRENT_USER=1,KEY_SET_VALUE=2,REG_SZ=3,RRF_RT_REG_SZ=4,ERROR_SUCCESS=0;
static std::map<std::wstring,std::wstring> values;
static std::vector<std::wstring> reads,writes;
int RegCreateKeyExW(int,const wchar_t* key,int,void*,int,int,void*,HKEY* handle,void*){writes.push_back(key);*handle=2;return 0;}
int RegSetValueExW(HKEY,const wchar_t*,int,int,const BYTE* data,DWORD){values[writes.back()]=reinterpret_cast<const wchar_t*>(data);return 0;}
int RegCloseKey(HKEY){return 0;}
int RegGetValueW(HKEY,const wchar_t* key,const wchar_t*,int,void*,void* data,DWORD*){reads.push_back(key);auto i=values.find(key);if(i==values.end())return 1;std::copy(i->second.c_str(),i->second.c_str()+i->second.size()+1,static_cast<wchar_t*>(data));return 0;}
namespace orangespace {
std::wstring widen(const std::string& s){return {s.begin(),s.end()};}
std::string narrow(const std::wstring& s){return {s.begin(),s.end()};}
bool valid_uuid(const std::string& s){return s.size()==36;}
}
struct App { METHOD };
int main(){
 const std::wstring legacy=L"Software\\OrangeSpace\\DefaultSandboxes\\owner";
 const auto suffix=orangespace::install_identity::suffix;
 auto wanted=legacy;
 if(!suffix.empty())wanted=L"Software\\OrangeSpace.Dev."+std::wstring(suffix.begin(),suffix.end())+L"\\DefaultSandboxes\\owner";
 const std::wstring old=L"11111111-1111-4111-8111-111111111111";
 const std::string fresh="22222222-2222-4222-8222-222222222222";
 values[legacy]=old;
 const auto before=App::default_preference("owner","node");
 assert(reads.size()==1 && reads.front()==wanted);
 assert(suffix.empty()?before==orangespace::narrow(old):before.empty());
 assert(App::default_preference("owner","node",fresh)==fresh);
 assert(writes.size()==1 && writes.front()==wanted && App::default_preference("owner","node")==fresh);
 if(!suffix.empty())assert(values.at(legacy)==old);
}
'''
        output=pathlib.Path('/var/tmp/hermes-runtime/tmp/orangespace-ui-v2/preference-scope');output.mkdir(parents=True,exist_ok=True)
        src=output/'preference.cpp';src.write_text(harness.replace('METHOD',method))
        for suffix in ('','ui-v2-p1','other'):
            exe=output/('preference-'+(suffix or 'default'))
            subprocess.run(['g++','-std=c++20','-Wall','-Wextra','-Werror','-I'+str(ROOT.parent/'windows-service/include'),'-DORANGESPACE_DEVELOPMENT_INSTALL_ID="'+suffix+'"',str(src),'-o',str(exe)],check=True)
            subprocess.run([str(exe)],check=True)

    def test_actual_fresh_diagnostic_poll_and_render(self):
        import subprocess
        source=SOURCE.read_text()
        self.assertIn('sc::diagnose_tunnel(',source)
        structs=source[source.index('struct TunnelLease {'):source.index('struct Completion {')]
        # Browser USER/HWND code has its own Windows link/source tests. Retain
        # these exact diagnostic worker bodies and all original stale negatives.
        methods=source[source.index('  bool status_fresh('):source.index('  static bool browser_closed(')]+source[source.index('  void poll_status() {'):source.index('  void poll() {')]
        harness=r'''
#include "orangespace/browser_session.hpp"
#include <cassert>
#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
namespace sc=orangespace::service_client;
namespace ns=orangespace::node_session;
namespace bs=orangespace::browser_session;
static std::uint64_t ticks=1000;
std::uint64_t GetTickCount64(){return ticks;}
namespace orangespace::service_client {
struct Grant {};
static bool throws=false,no_proof=false,wrong=false,local_throws=false;
static chain::Binding expected{"u","s","n","t",1};
std::vector<chain::Binding> active_tunnels(const Grant&){if(local_throws)throw 1;return {expected};}
TunnelDiagnosticDTO diagnose_tunnel(const Grant&,const chain::Binding& b){
 if(throws)throw 1;
 auto copy=b;if(wrong)copy.node="wrong";
 return {copy,100,9000,1000,std::string(node_session::detail::lease_clock),!no_proof,no_proof?"probe_unavailable":"verified"};
}
}
STRUCTS
struct App {
 bool draining_{},closing_{};std::uint64_t generation_=1;
 std::map<std::string,std::shared_ptr<TunnelLease>> tunnels_;
 std::shared_ptr<StatusMailbox> status_mailbox_;std::thread status_worker_;
 METHODS
 ~App(){if(status_worker_.joinable())status_worker_.join();}
 void launch(){for(auto& [k,v]:tunnels_)v->next_status={};poll_status();status_worker_.join();}
};
std::shared_ptr<TunnelLease> lease(){auto p=std::make_shared<TunnelLease>();p->grant=std::make_shared<sc::Grant>();p->binding=sc::expected;p->local="a";return p;}
int main(){
 App a;auto first=lease();a.tunnels_["a"]=first;
 a.launch();a.poll_status();assert(first->status_live && first->diagnostic && first->diagnostic->fresh_proof);
 assert(a.diagnostic_text(*first).find(L"近期转发：已验证")!=std::wstring::npos);
 assert(a.diagnostic_text(*first).find(L"最近观测：刚刚")!=std::wstring::npos);
 assert(a.diagnostic_text(*first).find(L"服务到期值")==std::wstring::npos && a.diagnostic_text(*first).find(L"观测毫秒")==std::wstring::npos);
 assert(first->diagnostic->deadline_ms==9000 && first->diagnostic->server_expiry==100);
 ticks=9000;assert(a.diagnostic_text(*first).find(L"近期转发：未知")!=std::wstring::npos);ticks=1000;
 sc::throws=true;a.launch();a.poll_status();assert(first->status_live && !first->diagnostic);sc::throws=false;
 sc::no_proof=true;a.launch();a.poll_status();assert(first->status_live && first->diagnostic && !first->diagnostic->fresh_proof);
 assert(a.diagnostic_text(*first).find(L"近期转发：未验证")!=std::wstring::npos);sc::no_proof=false;
 sc::wrong=true;a.launch();a.poll_status();assert(first->status_live && !first->diagnostic);sc::wrong=false;
 for(int mode=0;mode<7;++mode){
  a.tunnels_["a"]=first;a.generation_=1;a.launch();auto replacement=lease();
  if(mode==0)a.tunnels_.erase("a");
  if(mode==1)a.tunnels_["a"]=replacement;
  if(mode==2)++a.generation_;
  if(mode==3)a.status_mailbox_->requested-=std::chrono::seconds(6);
  if(mode==4)first->binding.node="changed";
  if(mode==5)a.draining_=true;
  if(mode==6)a.closing_=true;
  first->diagnostic.reset();a.poll_status();assert(!first->diagnostic && !replacement->diagnostic);
  first->binding=sc::expected;a.draining_=false;a.closing_=false;
 }
 a.tunnels_["a"]=first;a.generation_=1;
 auto b=lease();b->local="b";b->status_known=true;b->status_live=true;
 b->next_status=std::chrono::steady_clock::now()+std::chrono::hours(1);a.tunnels_["b"]=b;
 first->next_status={};a.poll_status();a.status_worker_.join();
 first->diagnostic=sc::TunnelDiagnosticDTO{sc::expected,200,15000,1100,std::string(ns::detail::lease_clock),true,"verified"};
 a.poll_status();assert(first->diagnostic->deadline_ms==15000 && b->status_known && b->status_live);
 sc::throws=true;first->next_status={};a.poll_status();a.status_worker_.join();a.poll_status();
 assert(first->status_known && first->status_live && !first->diagnostic && b->status_known && b->status_live);sc::throws=false;
 a.tunnels_.erase("b");
 a.tunnels_["a"]=first;a.generation_=1;sc::local_throws=true;a.launch();a.poll_status();assert(!first->status_known && !first->diagnostic);
}
'''
        output=pathlib.Path('/var/tmp/hermes-runtime/tmp/orangespace-ui-v2/diagnostic')
        output.mkdir(parents=True,exist_ok=True)
        src=output/'diagnostic.cpp';src.write_text(harness.replace('STRUCTS',structs).replace('METHODS',methods))
        exe=output/'diagnostic'
        subprocess.run(['g++','-std=c++20','-Wall','-Wextra','-Werror','-pthread','-I'+str(ROOT/'include'),'-I'+str(ROOT.parent/'windows-service/include'),str(src),'-o',str(exe)],check=True)
        subprocess.run([str(exe)],check=True)

if __name__ == '__main__': unittest.main()
