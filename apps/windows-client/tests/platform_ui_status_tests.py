"""Production GUI status worker/receiver policy; not native IPC/forwarding proof."""
import argparse
from pathlib import Path
import subprocess
from ui_test_slices import method
ROOT=Path(__file__).resolve().parents[3]
PRELUDE=r'''
#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <thread>
#include <vector>
#include <string>
#include <iostream>
#include "orangespace/browser_session.hpp"
namespace bs=orangespace::browser_session;
using Clock=std::chrono::steady_clock;
namespace sc {
struct Grant {};
using Binding=orangespace::service::chain::Binding;
using TunnelDiagnosticDTO=orangespace::service_client::TunnelDiagnosticDTO;
std::vector<Binding> response;
bool fail=false;
unsigned probes=0;
std::vector<Binding> active_tunnels(const Grant&){if(fail)throw 1;return response;}
// This injected policy fixture cannot observe real forwarding diagnostics.
TunnelDiagnosticDTO diagnose_tunnel(const Grant&,const Binding&){++probes;throw std::runtime_error("diagnostic unavailable");}
}
/*TYPES*/
struct App {
 std::map<std::string,std::shared_ptr<TunnelLease>> tunnels_;
 std::thread status_worker_;
 std::shared_ptr<StatusMailbox> status_mailbox_;
 std::uint64_t generation_{};
 bool draining_{},closing_{};
 /*METHODS*/
 ~App(){if(status_worker_.joinable())status_worker_.join();}
 void settle(){if(status_worker_.joinable())status_worker_.join();poll_status();}
};
int main(){
 App a;auto x=std::make_shared<TunnelLease>();x->local="A";x->grant=std::make_shared<sc::Grant>();
 x->binding={"user","service-A","node-A","helper-A",7};a.tunnels_["A"]=x;
 sc::response={x->binding};a.poll_status();a.settle();assert(x->status_known && x->status_live && sc::probes==1);
 x->next_status={};sc::response[0].generation=8;a.poll_status();a.settle();assert(x->status_known && !x->status_live);
 x->next_status={};sc::fail=true;a.poll_status();a.settle();assert(!x->status_known);sc::fail=false;
 // A late positive cannot resurrect stop or replacement, even same local ID.
 x->next_status={};sc::response={x->binding};a.poll_status();a.tunnels_.erase("A");a.settle();assert(!a.tunnels_.contains("A"));
 a.tunnels_["A"]=x;x->next_status={};a.poll_status();auto y=std::make_shared<TunnelLease>();y->local="A";a.tunnels_["A"]=y;a.settle();assert(!y->status_known);
 a.tunnels_["A"]=x;x->status_known=false;x->next_status={};a.poll_status();++a.generation_;a.settle();assert(!x->status_known);
 x->status_known=true;x->status_live=true;x->status_at=Clock::now()-std::chrono::seconds(6);assert(!a.status_fresh(*x));
 // Independent rows/nodes retain exact ownership across repeated lease cycles.
 a.tunnels_["B"]=y;y->local="B";y->grant=x->grant;y->binding={"user2","service-B","node-B","helper-B",9};
 assert(!y->browser); // Still protected before a browser phase is available.
 const auto previous_probes=sc::probes;
 for(int i=0;i<6;++i){x->next_status={};y->next_status={};sc::response={x->binding,y->binding};a.poll_status();a.settle();a.poll_status();a.settle();assert(x->status_live && y->status_live);}
 assert(sc::probes==previous_probes+6); // Only the non-browser node gets active probes.
 std::cout<<"actual GUI status: exact tuple, stop/replacement/epoch fencing, unknown failure, stale timeout, repeated two-node polls PASS\n";
}
'''
def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
 text=(ROOT/'apps/windows-client/src/main_win.cpp').read_text()
 assert 'void poll_status()' in text,'missing periodic typed GUI status refresh'
 types=text.split('struct TunnelLease {',1)[1].split('struct Completion {',1)[0]
 source=PRELUDE.replace('/*TYPES*/','struct TunnelLease {'+types).replace('/*METHODS*/','\n'.join(method(text,s) for s in ['  static bool same_binding(', '  bool status_fresh(', '  static bool browser_enabled(', '  void poll_status()']))
 src=a.output/'status.cpp';src.write_text(source);exe=a.output/'status'
 subprocess.run(['g++','-std=c++20','-Wall','-Wextra','-Werror','-pthread','-DORANGESPACE_PROTOTYPE_NODE_UUID="node-B"','-I'+str(ROOT/'apps/windows-client/include'),'-I'+str(ROOT/'apps/windows-service/include'),str(src),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True)
if __name__=='__main__':main()
