"""Execute production-extracted GUI close callsites; Linux seams, NOT native acceptance."""
import argparse
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]

def extract(source, begin, end):
    return source[source.index(begin):source.index(end, source.index(begin))]

def run(source, output):
    helpers = ''
    if '  static bool close_browser_step(' in source:
        helpers = extract(source, '  static bool close_browser_step(', '  static void persist_login(')
    cleanup = extract(source, '    drain_->retry([&]', '    browser_view();\n    const bool local=')
    retry = extract(source, '  void retry_stops()', '  static bool close_browser_step(' if helpers else '  static void persist_login(')
    broker = extract(source, '      if(closing) {', '      out.stopped=stopping;')
    late = extract(source, '        if(done) {\n', '      cleanup_step();')
    final = extract(source, '    if(logout_requested_ && mailbox_ && mailbox_->result', '    // Every attempt is bounded')
    cpp = r'''
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include "orangespace/ui_lifecycle.hpp"
using DWORD=unsigned;using HANDLE=int;
constexpr DWORD WAIT_OBJECT_0=0,WAIT_TIMEOUT=258,WAIT_FAILED=0xffffffff;
static DWORD process_wait=WAIT_OBJECT_0;
DWORD WaitForSingleObject(HANDLE,DWORD){return process_wait;}
struct Clock {using time_point=std::chrono::steady_clock::time_point;static inline time_point value{};static time_point now(){return value;}};
void Sleep(unsigned ms){Clock::value+=std::chrono::milliseconds(ms);}
struct Binding{std::string node="browser";};
namespace sc {
struct Grant{std::string id()const{return "grant";}};
static int stops=0,retires=0;static std::vector<std::string> events;
int stop_tunnel(const Grant&,const Binding&){++stops;events.push_back("stop");return 1;}
void retire(const Grant&){++retires;events.push_back("retire");}
void logout(const Grant& g){retire(g);}
}
namespace bs {
enum class Command {status,close};enum class Phase{closed,awaiting_desktop,starting,running,failed};
struct State{Phase phase=Phase::running;unsigned process_id=42;};
static int reads=0,closes=0;static bool unknown=false,close_unknown=false;static int closed_at=-1;
static State observed{};
State exchange(const sc::Grant&,const Binding&,Command command=Command::status){
 if(unknown)throw std::runtime_error("unknown service/identity");
 if(command==Command::close){++closes;sc::events.push_back("queued");if(close_unknown)throw std::runtime_error("lost ACK");return observed;}
 ++reads;if(closed_at>=0&&reads>=closed_at){observed={Phase::closed,0};sc::events.push_back("closed");}
 return observed;
}
}
struct TunnelLease{std::shared_ptr<sc::Grant> grant=std::make_shared<sc::Grant>();Binding binding;std::string local="sandbox";bool browser_close_requested{};};
struct Rows{void stopped(const std::string&) {}};
namespace ps {struct Session{};}
struct Completion {int cursor{};std::shared_ptr<TunnelLease> tunnel;std::unique_ptr<ps::Session> session;};
struct Mailbox {std::unique_ptr<Completion> result;};
struct Fixture {
 using Drain=orangespace::ui_lifecycle::Drain<std::shared_ptr<sc::Grant>>;
 std::shared_ptr<Drain> drain_=std::make_shared<Drain>();
 orangespace::ui_lifecycle::Retirement retirement_;
 std::map<std::string,std::shared_ptr<TunnelLease>> tunnels_;
 std::vector<std::shared_ptr<TunnelLease>> pending_stops_;
 std::map<std::string,int> cursors_;Rows rows_;
 Clock::time_point next_stop_{};bool logout_requested_{};HANDLE browser_process_{};
 static bool browser_enabled(const std::string& node){return node=="browser";}
 void notice(const wchar_t*){}
 /*HELPERS*/
 void cleanup(){/*CLEANUP*/}
 /*RETRY*/
 std::shared_ptr<Mailbox> mailbox_;std::shared_ptr<ps::Session> central_cleanup_;std::thread worker_;bool busy_=true;
 void late(){if(mailbox_) {bool done=true;/*LATE*/}
 void final(){/*FINAL*/}
 void broker(std::shared_ptr<TunnelLease> closing){Completion out;out.tunnel=closing;/*BROKER*/}
 std::shared_ptr<TunnelLease> own(bool pending=false){auto lease=std::make_shared<TunnelLease>();if(pending)pending_stops_.push_back(lease);else tunnels_[lease->local]=lease;auto t=drain_->begin();drain_->finish(*t,lease->grant);drain_->close();return lease;}
};
#define REQUIRE(x) do{if(!(x)){std::fprintf(stderr,"FAIL %s line %d: %s\n",which,__LINE__,#x);return 1;}}while(0)
void reset(){bs::reads=bs::closes=sc::stops=sc::retires=0;bs::unknown=bs::close_unknown=false;bs::closed_at=-1;bs::observed={};Clock::value={};process_wait=WAIT_OBJECT_0;sc::events.clear();}
int main(int argc,char**argv){const char* which=argc>1?argv[1]:"cleanup";std::string mode=which;
 if(mode=="cleanup") {
  reset();Fixture f;f.own();f.cleanup();REQUIRE(bs::closes==1);REQUIRE(sc::retires==0);REQUIRE(!f.drain_->ready());
  for(int i=0;i<8;++i)f.cleanup();REQUIRE(sc::retires==0);REQUIRE(bs::closes==1);
  bs::observed={bs::Phase::closed,42};f.cleanup();REQUIRE(sc::retires==0);
  bs::observed={bs::Phase::failed,0};f.cleanup();REQUIRE(sc::retires==0);
  bs::unknown=true;f.cleanup();REQUIRE(sc::retires==0);REQUIRE(!f.drain_->ready());bs::unknown=false;
  bs::observed={bs::Phase::closed,0};f.browser_process_=1;process_wait=WAIT_TIMEOUT;f.cleanup();REQUIRE(sc::retires==0);
  process_wait=WAIT_FAILED;f.cleanup();REQUIRE(sc::retires==0);
  process_wait=WAIT_OBJECT_0;f.cleanup();REQUIRE(sc::retires==1);REQUIRE(f.drain_->ready());
 } else if(mode=="pending") {
  reset();Fixture f;f.own(true);f.cleanup();REQUIRE(bs::closes==1);REQUIRE(sc::retires==0);
  bs::observed={bs::Phase::closed,0};f.cleanup();REQUIRE(sc::retires==1);
 } else if(mode=="broker") {
  reset();Fixture f;auto lease=f.own();bs::closed_at=4;f.broker(lease);REQUIRE(sc::stops==1);REQUIRE(bs::closes==1);REQUIRE(sc::events.back()=="stop");REQUIRE(std::find(sc::events.begin(),sc::events.end(),"closed")<std::find(sc::events.begin(),sc::events.end(),"stop"));
  reset();lease=f.own();bool failed=false;try{f.broker(lease);}catch(...){failed=true;}REQUIRE(failed);REQUIRE(sc::stops==0);REQUIRE(Clock::now().time_since_epoch()<=std::chrono::seconds(5));
  bs::observed={bs::Phase::closed,0};f.broker(lease);REQUIRE(sc::stops==1);
  reset();lease=f.own();bs::unknown=true;failed=false;try{f.broker(lease);}catch(...){failed=true;}REQUIRE(failed);REQUIRE(sc::stops==0);
 } else if(mode=="retry") {
  reset();Fixture f;f.own(true);f.retry_stops();REQUIRE(sc::stops==0);REQUIRE(f.pending_stops_.size()==1);
  bs::unknown=true;Clock::value+=std::chrono::seconds(1);f.retry_stops();REQUIRE(sc::stops==0);REQUIRE(f.pending_stops_.size()==1);
  bs::unknown=false;bs::observed={bs::Phase::closed,42};Clock::value+=std::chrono::seconds(1);f.retry_stops();REQUIRE(sc::stops==0);
  bs::observed={bs::Phase::closed,0};Clock::value+=std::chrono::seconds(1);f.retry_stops();REQUIRE(sc::stops==1);REQUIRE(f.pending_stops_.empty());
 } else if(mode=="lost_ack") {
  reset();Fixture f;f.own();bs::close_unknown=true;f.cleanup();REQUIRE(sc::retires==0);bs::observed={bs::Phase::closed,0};f.cleanup();REQUIRE(sc::retires==1);
 } else if(mode=="late" || mode=="final") {
  reset();Fixture f;auto lease=std::make_shared<TunnelLease>();f.mailbox_=std::make_shared<Mailbox>();f.mailbox_->result=std::make_unique<Completion>();f.mailbox_->result->tunnel=lease;
  if(mode=="late")f.late();else f.final();REQUIRE(f.pending_stops_.size()==1);REQUIRE(f.pending_stops_.front()==lease);REQUIRE(!f.mailbox_);REQUIRE(!f.busy_);
 } else return 2;
 std::printf("PASS production-extracted %s\n",which);
}
'''
    for key, text in [('HELPERS', helpers), ('CLEANUP', cleanup), ('RETRY', retry), ('BROKER', broker), ('LATE', late), ('FINAL', final)]:
        cpp = cpp.replace('/*' + key + '*/', text)
    # Only substitute the OS clock and IPC/process seams; close ordering is exact.
    cpp = cpp.replace('std::chrono::steady_clock::now()', 'Clock::now()')
    output.mkdir(parents=True, exist_ok=True)
    src = output / 'extracted.cpp'
    src.write_text(cpp)
    exe = output / 'test'
    cmd = ['g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-Wno-misleading-indentation', '-fsanitize=address,undefined', '-fno-pie', '-no-pie', '-pthread', '-I' + str(ROOT / 'apps/windows-client/include'), str(src), '-o', str(exe)]
    build = subprocess.run(cmd, capture_output=True, text=True)
    (output / 'build.log').write_text(' '.join(cmd) + '\n' + build.stdout + build.stderr)
    if build.returncode:
        print(build.stdout + build.stderr)
        return build.returncode
    failed = False
    logs = []
    for case in ('cleanup', 'pending', 'broker', 'retry', 'lost_ack', 'late', 'final'):
        result = subprocess.run([str(exe), case], capture_output=True, text=True)
        logs.append(result.stdout + result.stderr)
        failed |= bool(result.returncode)
    (output / 'result.log').write_text(''.join(logs))
    print(''.join(logs), end='')
    return int(failed)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=ROOT / 'apps/windows-client/src/main_win.cpp')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(run(args.source.read_text(), args.output))
