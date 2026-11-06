"""Execute actual UI browser worker with injected OS/Service seams on Linux.
Policy/lifecycle evidence only; does not prove Windows HWND/ACL/CEF behavior.
"""
from pathlib import Path
import subprocess, tempfile, unittest
R=Path(__file__).resolve().parents[1]
class BrowserWorker(unittest.TestCase):
 def test_actual_worker_owner_epoch_close_and_commands(self):
  source=(R/'src/main_win.cpp').read_text()
  structs=source[source.index('struct TunnelLease {'):source.index('struct StatusMailbox {')]
  poll=source[source.index('  void poll_browser() {'):source.index('  void poll_status() {')]
  harness=r'''
#include "orangespace/browser_session.hpp"
#include <cassert>
#include <memory>
#include <thread>
#include <mutex>
#include <map>
#include <chrono>
namespace sc=orangespace::service_client;namespace bs=orangespace::browser_session;
namespace orangespace::service_client {struct Grant {};}
namespace orangespace::browser_session {
static Command last=Command::close;static unsigned calls=0;
static Phase reply=Phase::running;
State exchange(const sc::Grant&,const service::chain::Binding& b,Command c=Command::status){
 ++calls;last=c;State s;s.phase=reply;s.sandbox=b.sandbox;s.node=b.node;s.generation=b.generation;s.process_id=123;return s;
}}
STRUCTS
struct App {
 bool draining_{},closing_{},busy_{},station_ready_{},browser_process_{};
 std::uint64_t generation_=1;
 std::uint32_t retired_pid_{};
 std::string active_sandbox_="s";
 std::map<std::string,std::shared_ptr<TunnelLease>> tunnels_;
 std::thread browser_worker_;std::shared_ptr<BrowserMailbox> browser_mailbox_;
 std::optional<bs::Command> browser_command_;std::shared_ptr<TunnelLease> browser_command_owner_;
 std::chrono::steady_clock::time_point next_browser_{};
 struct Station{int count=0;void grant(const bs::State&,bool){++count;}bool active() const{return count>0;}}station_;
 void browser_view(){} bool retain_browser_process(const bs::State&){return true;}
 static bool browser_closed(const bs::State& s){return s.phase==bs::Phase::closed&&s.process_id==0;}
 bool browser_retired(const bs::State& s) const{return s.process_id&&s.process_id==retired_pid_;}
 static bool browser_enabled(std::string_view n){return n=="sg";}
 void notice(const wchar_t*){}
 POLL
 ~App(){if(browser_worker_.joinable())browser_worker_.join();}
 void launch(){next_browser_={};poll_browser();assert(browser_worker_.joinable());browser_worker_.join();}
};
auto lease(){auto p=std::make_shared<TunnelLease>();p->grant=std::make_shared<sc::Grant>();p->local="s";p->binding={"u","s","sg","t",1};return p;}
int main(){
 App a;auto p=lease();a.tunnels_["s"]=p;a.launch();a.poll_browser();assert(p->browser && p->browser->phase==bs::Phase::running);
 for(int kind=0;kind<5;++kind){
  p->browser.reset();a.tunnels_["s"]=p;a.generation_=1;a.launch();auto replacement=lease();
  if(kind==0)++a.generation_;if(kind==1)a.tunnels_.erase("s");if(kind==2)a.tunnels_["s"]=replacement;
  if(kind==3)a.closing_=true;if(kind==4)a.draining_=true;
  a.poll_browser();assert(!p->browser && !replacement->browser);a.closing_=a.draining_=false;
 }
 a.generation_=1;a.tunnels_["s"]=p;
 a.launch();a.retired_pid_=123;a.poll_browser();assert(!p->browser);a.retired_pid_=0;
 auto replacement=lease();
 a.browser_command_=bs::Command::station_configured;a.browser_command_owner_=p;
 a.tunnels_["s"]=replacement;a.launch();a.poll_browser();assert(bs::last==bs::Command::status);
 replacement->binding.node="hk";auto calls=bs::calls;a.next_browser_={};a.poll_browser();assert(!a.browser_worker_.joinable() && bs::calls==calls);
 replacement->binding.node="sg";bs::reply=bs::Phase::awaiting_desktop;a.launch();a.poll_browser();
 assert(a.station_.count==1 && a.browser_command_==bs::Command::station_configured);
 a.launch();a.poll_browser();assert(bs::last==bs::Command::station_configured && a.station_.count==1);
}
'''
  with tempfile.TemporaryDirectory() as directory:
   out=Path(directory)
   cpp=out/'worker.cpp';cpp.write_text(harness.replace('STRUCTS',structs).replace('POLL',poll))
   subprocess.run(['c++','-std=c++20','-pthread','-I'+str(R/'include'),'-I'+str(R.parent/'windows-service/include'),str(cpp),'-o',str(out/'worker')],check=True)
   subprocess.run([str(out/'worker')],check=True)
if __name__=='__main__':unittest.main()
