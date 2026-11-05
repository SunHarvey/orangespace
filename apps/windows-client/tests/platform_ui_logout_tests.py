"""Compile actual central UI cleanup callers with injected OS/IPC seams.
Portable policy evidence, not native HTTPS/DPAPI/Service acceptance.
"""
import argparse
from pathlib import Path
import subprocess
import json
import hashlib
from ui_test_slices import method

ROOT = Path(__file__).resolve().parents[3]
PRELUDE = r'''
#include "orangespace/ui_lifecycle.hpp"
#include "orangespace/platform_workspace.hpp"
#include <algorithm>
#include <chrono>
#include <thread>
#include <cassert>
#include <iostream>
using namespace std::chrono_literals;
static bool disk_down=false,service_down=false,remote_down=false,saved=false;
static void (*during_nodes)()=nullptr;
static int erased=0,central_logouts=0,remote_logouts=0,retired=0,stops=0;
namespace ps {
struct PlatformConfig {static PlatformConfig load(const std::wstring&){return {};}};
inline bool fail_nodes=false;
struct Session {
 static Session login(PlatformConfig&,const std::string&,std::string_view){return {};}
 std::vector<int> nodes(){if(during_nodes)during_nodes();if(fail_nodes)throw 1;return {1};}
 void logout(){++central_logouts;if(remote_down)throw 1;}
};
struct CredentialStore {
 static Session load(PlatformConfig&){return {};}
 static void save(PlatformConfig&,Session&){saved=true;}
 static void erase(PlatformConfig&){++erased;if(disk_down)throw 1;saved=false;}
};
}
struct Grant {std::string id_{"grant"};const std::string& id()const{return id_;}};
struct Binding {std::string node="sg";};
namespace sc {
using Grant=::Grant;
void logout(const Grant&){++remote_logouts;if(service_down)throw 1;}
void retire(const Grant&){++retired;if(service_down)throw 1;}
int stop_tunnel(const Grant&,const Binding&){++stops;if(service_down)throw 1;return 0;}
}
struct TunnelLease {std::shared_ptr<Grant> grant;Binding binding;std::string local;bool browser_close_requested{};};
// Browser transport is separately exercised by browser_worker_tests. These
// seams keep every original credential/retirement assertion below intact.
namespace bs {
enum class Command{status,close};enum class Phase{closed,running,failed};
struct State {Phase phase=Phase::closed;unsigned process_id{};};
static State observed;static bool unknown=false;static int closes=0;
State exchange(const Grant&,const Binding&,Command command){
 if(unknown)throw 1;
 if(command==Command::close)++closes;
 return observed;
}
}
enum class Job {catalog,login};
struct Completion {std::unique_ptr<ps::PlatformConfig> catalog;std::unique_ptr<ps::Session> session;std::shared_ptr<TunnelLease> tunnel;Job job;int login{};std::vector<int> nodes;bool failed{},remember{},automatic{};};
struct Mailbox {std::mutex mutex;std::unique_ptr<Completion> result;bool cancelled{};};
struct Secret {std::string_view view()const{return "password";}};
/*PERSIST_LOGIN*/
static Completion run_login(){
 auto catalog=std::make_shared<ps::PlatformConfig>();int ticket=1;
 std::string username="alice";auto secret=std::make_shared<Secret>();bool remember=true,automatic=false;
 auto work=/*LOGIN_WORKER*/;
 Completion out;Mailbox box;
 try {work(out,box);}catch(...){out.failed=true;}
 return out;
}
struct Worker {bool joinable(){return false;}void join(){}};
int now(){return 10;}
struct Auth {
 struct Identity {std::string username;};struct Session {Identity identity()const{return {};}};
 struct Node {std::string node_id;};
 const Session* active(int)const{return nullptr;}const Node* selected_node(int)const{return nullptr;}
 std::shared_ptr<ps::Session> retain(int){return {};}
 void close(){}void logout(){}
};
namespace orangespace {std::wstring widen(const std::string& s){return {s.begin(),s.end()};}}
void EnableWindow(int,bool){}
void SetWindowTextW(int,const wchar_t*){}
void MessageBoxW(int,const wchar_t*,const wchar_t*,int){}
void SendMessageW(int,int,int,int){}
void DestroyWindow(int){}
void Sleep(int){}
using DWORD=unsigned;
constexpr DWORD WAIT_OBJECT_0=0,WAIT_TIMEOUT=258,WAIT_FAILED=0xffffffff;
static DWORD process_wait=WAIT_OBJECT_0;
DWORD WaitForSingleObject(bool,DWORD){return process_wait;}
constexpr int MB_OK=0,MB_ICONINFORMATION=0,CB_RESETCONTENT=0,EM_EMPTYUNDOBUFFER=0;
struct App {
 Worker browser_worker_;std::shared_ptr<int> browser_mailbox_;bool browser_process_{};
 struct Station {bool active()const{return false;}}station_;
 void browser_view(){}static bool browser_enabled(const std::string& n){return n=="sg";}
 struct Panel {bool ready{true};int requested{},joined{};void request_logout(){++requested;}void logout(){assert(ready);++joined;}void poll(){}bool can_close()const{return ready;}};std::unique_ptr<Panel> file_panel_;
 int window{},notice_{},alias_{},identity_{},node_{},trust_{},load_{},username_{},password_{},login_{},refresh_{},name_{},create_{},bind_{},close_{},delete_{},connect_{},list_{},stop_{},open_{},logout_{},add_{},file_button_{};
 bool had_identity_{},login_page_{},choosing_node_{},file_view_{},open_pending_{};int generation_{};
 std::vector<int> node_buttons_,node_menus_;std::vector<std::string> tabs_;std::string active_sandbox_;
 std::vector<orangespace::Sandbox> sandboxes_;
 std::optional<orangespace::Sandbox> selection(){return {};}
 void clear_rows(){sandboxes_.clear();}void rebuild_nodes(){}void rebuild_tabs(){}void render_proofs(){}void layout(){}
 Worker worker_,status_worker_;Auth auth_;
 std::shared_ptr<int> status_mailbox_;
 bool draining_{},closing_{},destroyed_{},logout_requested_{},busy_{},central_logout_failed_{};
 using GrantDrain=orangespace::ui_lifecycle::Drain<std::shared_ptr<Grant>>;
 std::shared_ptr<GrantDrain> drain_=std::make_shared<GrantDrain>();
 orangespace::ui_lifecycle::LogoutState logout_state_;
 orangespace::ui_lifecycle::Retirement retirement_;
 std::shared_ptr<ps::PlatformConfig> catalog_=std::make_shared<ps::PlatformConfig>();
 std::shared_ptr<ps::Session> central_cleanup_=std::make_shared<ps::Session>();
 std::shared_ptr<Mailbox> mailbox_;
 std::map<std::string,std::shared_ptr<Grant>> grants_;
 std::map<std::string,std::shared_ptr<TunnelLease>> tunnels_;
 std::map<std::string,int> cursors_;
 std::vector<std::shared_ptr<TunnelLease>> pending_stops_;
 orangespace::PlatformRows rows_;
 std::string starting_local_;
 std::optional<std::wstring> pending_catalog_;
 std::chrono::steady_clock::time_point next_cleanup_{},next_stop_{};

 template<class Work>void start(Work){}
 /*METHODS*/
};
static void reset(){during_nodes=nullptr;saved=false;disk_down=service_down=remote_down=false;erased=central_logouts=remote_logouts=retired=stops=0;bs::observed={};bs::unknown=false;bs::closes=0;process_wait=WAIT_OBJECT_0;}
static App* racing=nullptr;
static void blocked_nodes(){racing->logout();racing->cleanup_step();assert(racing->draining_);}
int main(){
 reset();ps::fail_nodes=true;auto failed_login=run_login();
 assert(failed_login.failed && central_logouts==1);
 reset();ps::fail_nodes=false;auto good_login=run_login();
 assert(!good_login.failed && central_logouts==0 && good_login.nodes.size()==1);
 reset();App expired;expired.had_identity_=true;expired.tabs_={"old-user-tab"};expired.active_sandbox_="old-user-tab";
 expired.file_panel_=std::make_unique<App::Panel>();expired.file_panel_->ready=false;
 expired.sync_identity();assert(expired.draining_ && expired.tabs_.empty() && expired.active_sandbox_.empty() && expired.file_panel_->requested>0);
 expired.cleanup_step();assert(expired.draining_ && central_logouts==0);
 expired.file_panel_->ready=true;expired.next_cleanup_={};expired.cleanup_step();assert(!expired.draining_);
 reset();App race;race.central_cleanup_.reset();race.busy_=true;racing=&race;during_nodes=blocked_nodes;
 auto late_saved=run_login();assert(saved && race.draining_);
 race.central_cleanup_=std::shared_ptr<ps::Session>(std::move(late_saved.session));race.busy_=false;race.next_cleanup_={};race.cleanup_step();
 assert(!saved && !race.draining_ && erased==1);
 reset();App a;auto grant=std::make_shared<Grant>();
 auto ticket=*a.drain_->begin();a.drain_->finish(ticket,grant);
 auto proof=a.rows_.begin("A","node-A");a.rows_.complete(proof,true,true,true);
 auto lease=std::make_shared<TunnelLease>();lease->local="A";lease->grant=grant;a.tunnels_["A"]=lease;
 a.logout();disk_down=service_down=true;a.cleanup_step();
 assert(a.logout_state_.restore_blocked() && !a.drain_->ready() && a.draining_);
 assert(erased==1 && central_logouts==0 && remote_logouts==1 && retired==1);
 disk_down=service_down=false;a.next_cleanup_={};a.cleanup_step();
 assert(!a.logout_state_.restore_blocked() && !a.draining_ && erased==2 && retired==2);
 assert(!a.rows_.proven("A")); // Re-login cannot display retired proof as live.
 reset();App transfer;transfer.file_panel_=std::make_unique<App::Panel>();transfer.file_panel_->ready=false;
 transfer.logout();assert(transfer.file_panel_->requested>=1 && transfer.file_panel_->joined==0);
 transfer.cleanup_step();assert(transfer.draining_ && !transfer.logout_state_.restore_blocked() && transfer.file_panel_->joined==0 && central_logouts==0);
 transfer.file_panel_->ready=true;transfer.next_cleanup_={};transfer.cleanup_step();
 assert(!transfer.draining_ && transfer.file_panel_->joined==1);
 reset();App close;close.begin_close();close.cleanup_step();close.finish_before_return();
 assert(erased==0 && central_logouts==0); // Normal close preserves saved login.
 reset();App remote;remote_down=true;remote.logout();remote.cleanup_step();
 assert(remote.central_logout_failed_ && !remote.draining_ && erased==1);
 // Explicit logout while central login is in flight: late session must be
 // retained through the final-return path and receive a remote logout attempt.
 reset();App late;late.central_cleanup_.reset();late.logout();
 late.mailbox_=std::make_shared<Mailbox>();late.mailbox_->result=std::make_unique<Completion>();
 late.mailbox_->result->session=std::make_unique<ps::Session>();late.busy_=true;
 late.finish_before_return();assert(central_logouts==1 && erased==1);
 // Actual close helper: queued close, unknown status, and an unsignalled or
 // failed exact-process wait must never permit grant retirement.
 for(bool pending:{false,true}) {
  reset();App browser;auto owned=std::make_shared<TunnelLease>();owned->grant=std::make_shared<Grant>();
  auto admission=*browser.drain_->begin();browser.drain_->finish(admission,owned->grant);
  if(pending)browser.pending_stops_.push_back(owned);else browser.tunnels_["A"]=owned;
  browser.logout();bs::observed={bs::Phase::running,42};browser.cleanup_step();
  assert(browser.draining_ && !browser.drain_->ready() && retired==0 && remote_logouts==0 && stops==0 && bs::closes==1);
  bs::observed={bs::Phase::closed,42};browser.next_cleanup_={};browser.cleanup_step();assert(retired==0 && remote_logouts==0 && !browser.drain_->ready());
  bs::observed={bs::Phase::failed,0};browser.next_cleanup_={};browser.cleanup_step();assert(retired==0 && remote_logouts==0 && !browser.drain_->ready());
  bs::unknown=true;browser.next_cleanup_={};browser.cleanup_step();assert(retired==0 && remote_logouts==0 && !browser.drain_->ready());
  bs::unknown=false;bs::observed={bs::Phase::closed,0};browser.browser_process_=true;
  for(DWORD wait:{WAIT_TIMEOUT,WAIT_FAILED}){process_wait=wait;browser.next_cleanup_={};browser.cleanup_step();assert(retired==0 && remote_logouts==0);}
  process_wait=WAIT_OBJECT_0;browser.next_cleanup_={};browser.cleanup_step();assert(retired==0 && remote_logouts==1 && browser.drain_->ready());
  browser.browser_process_=false;browser.next_cleanup_={};browser.cleanup_step();assert(!browser.draining_ && bs::closes==1);
 }
 std::cout << "actual central cleanup: failed node-enumeration revoke, successful login retained, disk/service retry, close, remote failure, final late-login logout PASS\n";
}
'''

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=True)
    path=ROOT/'apps/windows-client/src/main_win.cpp';text=path.read_text()
    signatures=['  void logout()', '  void cleanup_step()', '  void begin_close()',
                '  void finish_before_return()', '  void retry_stops()', '  static bool close_browser_step(',
                '  void notice(const std::wstring&', '  void notice(const wchar_t*', '  void sync_identity()', '  void invalidate_ui()']
    source=args.output/'central_callers.cpp'
    worker='[catalog,ticket,username=std::move(username),secret,remember,automatic]'+text.split('start([catalog,ticket,username=std::move(username),secret,remember,automatic]',1)[1].split(');notice(',1)[0]
    source.write_text(PRELUDE.replace('/*METHODS*/','\n'.join(method(text,s) for s in signatures)).replace('/*LOGIN_WORKER*/',worker).replace('/*PERSIST_LOGIN*/',method(text,'  static void persist_login(')))
    exe=args.output/'central_callers'
    cmd=['g++','-std=c++20','-Wall','-Wextra','-Werror','-pthread','-I'+str(ROOT/'apps/windows-client/include'),str(source),'-o',str(exe)]
    result=subprocess.run(cmd,text=True,capture_output=True)
    (args.output/'build.log').write_text(result.stdout+result.stderr)
    if result.returncode:print(result.stderr);raise SystemExit(result.returncode)
    run=subprocess.run([str(exe)],text=True,capture_output=True)
    (args.output/'run.log').write_text(run.stdout+run.stderr)
    (args.output/'evidence.json').write_text(json.dumps({'command':cmd,'exit':run.returncode,'source_sha256':hashlib.sha256(path.read_bytes()).hexdigest()},indent=2))
    print(run.stdout+run.stderr,end='');raise SystemExit(run.returncode)
if __name__=='__main__':main()
