"""Actual UI caller slices with injected catalog/store/Win32 seams, not native acceptance.
Run: python3 .../ui_logout_recovery_tests.py --case logout --output SCRATCH [--sanitize]
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]


def method(source, signature):
    start = source.index(signature)
    brace = source.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--case', choices=['logout', 'notice'], default='logout')
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--sanitize', action='store_true')
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    source = ROOT / 'apps/windows-client/src/main_win.cpp'
    node = ROOT / 'apps/windows-client/src/node_session_win.cpp'
    text = source.read_text()
    names = method(node.read_text(), 'std::vector<std::string> TrustedCatalog::names() const').replace('TrustedCatalog::', '')
    slices = '\n'.join(method(text, sig) for sig in [
        '  void logout()', '  void cleanup_step()', '  void begin_close()',
        '  void finish_before_return()', '  void retry_stops()',
        '  void notice(const std::wstring&'])
    if '  void notice(const wchar_t*' in text:
        slices += '\n' + method(text, '  void notice(const wchar_t*')
    poll_prefix = text.split('  void poll() {', 1)[1].split('    if (!busy_)', 1)[0]
    timer_case = text.split('      case WM_TIMER:', 1)[1].split('\n', 1)[0]
    idle = text.split('    if (!busy_)', 1)[1].split('\n', 1)[0]
    slices += '\n  void poll() {' + poll_prefix + '\n    if (!busy_)' + idle + '\n  }'
    slices += '\n  long long message(unsigned int message, unsigned long long, long long) {switch(message) {case 2:' + timer_case + '}return 0;}'
    callback = method(text, 'LRESULT CALLBACK window_procedure(')
    cpp = (PRELUDE.replace('/*NAMES*/', names).replace('/*SLICES*/', slices)
           + CALLBACK_STUBS + callback + TESTS)
    generated = args.output / 'actual_callers.cpp'
    generated.write_text(cpp)
    exe = args.output / 'actual_callers'
    cmd = ['g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pthread',
           '-fno-elide-constructors', '-g', '-I' + str(ROOT / 'apps/windows-client/include')]
    if args.sanitize:
        cmd += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie']
    cmd += [str(generated), '-o', str(exe)]
    build = subprocess.run(cmd, text=True, capture_output=True)
    (args.output / 'build.log').write_text(build.stdout + build.stderr)
    if build.returncode:
        print(build.stderr)
        raise SystemExit(build.returncode)
    run = subprocess.run([str(exe), args.case], text=True, capture_output=True,
                         env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=1:halt_on_error=1'})
    (args.output / 'run.log').write_text(run.stdout + run.stderr)
    (args.output / 'evidence.json').write_text(json.dumps({
        'command': cmd, 'case': args.case, 'exit': run.returncode,
        'sources': {str(f): hashlib.sha256(f.read_bytes()).hexdigest() for f in [
            source, node, ROOT / 'apps/windows-client/include/orangespace/ui_lifecycle.hpp', Path(__file__)]}}, indent=2))
    print(run.stdout + run.stderr, end='')
    raise SystemExit(run.returncode)


PRELUDE = r'''
#include "orangespace/ui_lifecycle.hpp"
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstdio>
#include <new>
#include <string_view>
static int allocations=-1;
static bool sticky=false;
static int allocation_count=0;
void* operator new(std::size_t n) {
  ++allocation_count;
  if(allocations==0) {if(!sticky)allocations=-1;throw std::bad_alloc();}
  if(allocations>0)--allocations;
  if(auto* p=std::malloc(n?n:1))return p;
  throw std::bad_alloc();
}
void operator delete(void* p) noexcept {std::free(p);}
void operator delete(void* p,std::size_t) noexcept {std::free(p);}
static int checks=0;
#define REQUIRE(x) do {++checks;if(!(x)){allocations=-1;std::fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);return 1;}}while(false)
struct Node {std::string name;};
struct Catalog {static Catalog load(const std::wstring&){return {};}
std::vector<Node> nodes_{{"node-a"},{"node-b"}};/*NAMES*/};
struct Grant {std::string identity="grant-a";const std::string& id()const{return identity;}};
struct Binding {int exact=7;};struct Cursor {int exact=7;};
struct TunnelLease {std::string local="sandbox-a";std::shared_ptr<Grant> grant;Binding binding;};
static bool service_down=false,remote_down=false,stop_down=false;
static int remote_attempts=0,local_attempts=0,stop_attempts=0;
namespace sc {
using Grant=::Grant;
void logout(Grant&){++remote_attempts;if(service_down||remote_down)throw 1;}
void retire(Grant&){++local_attempts;if(service_down)throw 2;}
Cursor stop_tunnel(Grant&,const Binding& b){++stop_attempts;if(stop_down)throw 3;return {b.exact};}
}
static int erase_a=0,erase_b=0;
static bool disk_down=false,delete_a_down=false,marker_a=false,blob_a=true,blob_b=true;
namespace ns {using TrustedCatalog=::Catalog;struct CredentialStore {
static void erase(Catalog&,const std::string& name) {
 if(name.starts_with("node-a")) {++erase_a;if(disk_down)throw 4;marker_a=true;if(delete_a_down)throw 5;blob_a=false;marker_a=false;}
 else {++erase_b;if(disk_down)throw 4;blob_b=false;}
}};}
static bool notice_throw=false,sync_throw=false;
static int notices=0;
static void (*notice_hook)()=nullptr;
void SetWindowTextW(int,const wchar_t*) {++notices;if(notice_hook)notice_hook();if(notice_throw)throw 6;}
constexpr int MB_OK=0,MB_ICONINFORMATION=0,CB_RESETCONTENT=0;
void MessageBoxW(int,const wchar_t*,const wchar_t*,int){if(notice_throw)throw 7;}
void SendMessageW(int,int,int,int){}
struct Completion {int job{};std::unique_ptr<Catalog> catalog;};
struct Mailbox{std::mutex mutex;std::unique_ptr<Completion> result;};struct Job{static constexpr int catalog=0;};
static int destroyed_windows=0;
void DestroyWindow(int){++destroyed_windows;}
struct Worker {bool joinable()const{return false;}void join(){}};
struct Auth {void close(){}};
static void (*sleep_hook)()=nullptr;
void Sleep(int){if(sleep_hook)sleep_hook();}
struct Fixture {
 bool closing_=false,draining_=false,logout_requested_=false,busy_=false;
 int notice_=0,window=0,alias_=0,invalidations=0;
 Auth auth_;Worker worker_;std::shared_ptr<Mailbox> mailbox_;
 orangespace::ui_lifecycle::Retirement retirement_;
 orangespace::ui_lifecycle::LogoutState logout_state_;
 std::shared_ptr<Catalog> catalog_=std::make_shared<Catalog>();
 using GrantDrain=orangespace::ui_lifecycle::Drain<std::shared_ptr<Grant>>;
 std::shared_ptr<GrantDrain> drain_=std::make_shared<GrantDrain>();
 std::chrono::steady_clock::time_point next_cleanup_{},next_stop_{};
 std::vector<std::shared_ptr<TunnelLease>> pending_stops_;
 std::map<std::string,Cursor> cursors_;
 std::map<std::string,std::shared_ptr<Grant>> grants_;
 std::map<std::string,std::shared_ptr<TunnelLease>> tunnels_;
 std::optional<std::wstring> pending_catalog_;
 void invalidate_ui(){++invalidations;}
 void sync_identity(){if(sync_throw){auto value=std::wstring(80,L'x');(void)value;}}
 template<class Work>void start(Work){}
 /*SLICES*/
};
'''

CALLBACK_STUBS = r'''
using Application=Fixture;
using LRESULT=long long;using WPARAM=unsigned long long;using LPARAM=long long;
using LONG_PTR=long long;using HWND=int;using UINT=unsigned int;
#define CALLBACK
constexpr int GWLP_USERDATA=0,WM_NCCREATE=1,WM_TIMER=2;
struct CREATESTRUCTW {void* lpCreateParams;};
static Fixture* callback_app=nullptr;
LONG_PTR GetWindowLongPtrW(HWND,int){return reinterpret_cast<LONG_PTR>(callback_app);}
LONG_PTR SetWindowLongPtrW(HWND,int,LONG_PTR value){callback_app=reinterpret_cast<Fixture*>(value);return 0;}
LRESULT DefWindowProcW(HWND,UINT,WPARAM,LPARAM){return 0;}
'''

TESTS = r'''
static Fixture* active=nullptr;
static int sleeps=0;
static bool finish_gate_valid=true;
static void reentrant_close() {notice_hook=nullptr;active->begin_close();active->begin_close();}
static void finish_retry() {
 ++sleeps;
 finish_gate_valid=finish_gate_valid && active->logout_state_.restore_blocked()
   && active->logout_requested_ && blob_a && blob_b;
 active->logout();active->begin_close();
 // Simulate a persistent allocation failure for two complete timer intervals.
 if(sleeps==2)allocations=-1;
 if(sleeps>3)std::abort();
 active->next_cleanup_={};
}
static void reset() {
 allocations=-1;sticky=false;service_down=false;remote_down=false;stop_down=false;
 erase_a=erase_b=remote_attempts=local_attempts=stop_attempts=0;
 disk_down=delete_a_down=marker_a=false;blob_a=blob_b=true;
 notice_throw=sync_throw=false;notice_hook=nullptr;sleep_hook=nullptr;
}
int main(int argc,char** argv) {
 if(argc!=2)return 2;
 if(std::string_view(argv[1])=="logout") {
  Fixture f;
  allocations=0;sticky=true;
  try{f.logout();}catch(...){}
  allocations=-1;
  REQUIRE(f.draining_ && f.logout_requested_);
  REQUIRE(f.logout_state_.restore_blocked());
  REQUIRE(f.invalidations==1);
  // A repeated command must not lose the original intent or skip setup forever.
  try{f.logout();}catch(...){}
  f.next_cleanup_={};f.cleanup_step();
  REQUIRE(erase_a==1 && erase_b==1 && !blob_a && !blob_b);
  REQUIRE(!f.logout_state_.restore_blocked() && !f.logout_requested_ && !f.draining_);
  reset();
  // Sweep every allocation in actual catalog enumeration, one-shot and sticky.
  Catalog catalog;for(auto& node:catalog.nodes_)node.name.append(80,'x');
  int before=allocation_count;{auto names=catalog.names();(void)names;}
  const int enumeration_allocations=allocation_count-before;
  REQUIRE(enumeration_allocations>0);
  for(bool persistent:{false,true})for(int point=0;point<enumeration_allocations;++point) {
   reset();Fixture h;h.catalog_->nodes_=catalog.nodes_;
   h.logout();h.begin_close();
   allocations=point;sticky=persistent;bool escaped=false;
   try{h.cleanup_step();}catch(...){escaped=true;}
   allocations=-1;
   REQUIRE(!escaped);
   REQUIRE(h.logout_state_.restore_blocked() && h.logout_requested_);
   REQUIRE(erase_a==0 && erase_b==0 && blob_a && blob_b);
   h.logout();h.begin_close();h.next_cleanup_={};h.cleanup_step();
   REQUIRE(erase_a==1 && erase_b==1 && !h.logout_state_.restore_blocked());
   REQUIRE(h.drain_->ready() && h.closing_);
  }
  reset();
  // A reentrant close during the logout notice preserves erase and drain intent.
  Fixture h;active=&h;notice_hook=reentrant_close;h.logout();
  REQUIRE(h.closing_ && h.logout_requested_ && h.logout_state_.restore_blocked());
  h.cleanup_step();REQUIRE(!blob_a && !blob_b && h.drain_->ready());
  // The actual final-return loop cannot exit with uninitialized saved processing.
  reset();Fixture final;active=&final;final.logout();
  sleep_hook=finish_retry;allocations=0;sticky=true;final.finish_before_return();
  allocations=-1;sleep_hook=nullptr;
  REQUIRE(sleeps==2 && finish_gate_valid);
  REQUIRE(!blob_a && !blob_b && !final.logout_state_.restore_blocked() && final.drain_->ready());
  // Disk failure before marker commit is not a durable offline revocation.
  reset();Fixture disk;auto grant=std::make_shared<Grant>();
  const auto ticket=*disk.drain_->begin();disk.drain_->finish(ticket,grant);
  disk.logout();disk_down=true;service_down=true;disk.cleanup_step();
  REQUIRE(erase_a==1 && erase_b==1 && !marker_a && blob_a && blob_b);
  REQUIRE(disk.logout_state_.restore_blocked() && !disk.drain_->ready());
  REQUIRE(remote_attempts==1 && local_attempts==1 && disk.retirement_.remote_failed());
  // Successful marker commit + failed deletion stays blocked; B still erases.
  disk_down=false;delete_a_down=true;disk.next_cleanup_={};disk.cleanup_step();
  REQUIRE(marker_a && blob_a && !blob_b && erase_a==2 && erase_b==2);
  REQUIRE(disk.logout_state_.restore_blocked() && !disk.drain_->ready());
  delete_a_down=false;disk.next_cleanup_={};disk.cleanup_step();
  REQUIRE(!marker_a && !blob_a && erase_b==2 && !disk.logout_state_.restore_blocked());
  REQUIRE(disk.draining_ && disk.logout_requested_ && !disk.drain_->ready());
  service_down=false;disk.next_cleanup_={};disk.cleanup_step();
  REQUIRE(!disk.draining_ && !disk.logout_requested_ && remote_attempts==1);
  REQUIRE(local_attempts==4 && disk.retirement_.remote_failed());
  // A late grant's unresolved ticket prevents cleanup completion even after erase.
  reset();Fixture late;const auto pending=*late.drain_->begin();late.logout();late.cleanup_step();
  REQUIRE(!blob_a && !blob_b && late.draining_ && !late.drain_->ready());
  grant=std::make_shared<Grant>();late.drain_->finish(pending,grant);late.next_cleanup_={};late.cleanup_step();
  REQUIRE(!late.draining_ && remote_attempts==1 && local_attempts==0);
  // Ordinary close never erases or issues remote logout.
  reset();Fixture ordinary;const auto owned=*ordinary.drain_->begin();ordinary.drain_->finish(owned,grant);
  ordinary.begin_close();ordinary.cleanup_step();ordinary.finish_before_return();
  REQUIRE(ordinary.drain_->ready() && erase_a==0 && erase_b==0 && blob_a && blob_b);
  REQUIRE(remote_attempts==0 && local_attempts==1);
  // Empty catalog still completes after admitting explicit intent.
  reset();Fixture empty;empty.catalog_.reset();empty.logout();empty.cleanup_step();
  REQUIRE(!empty.draining_ && !empty.logout_requested_ && !empty.logout_state_.restore_blocked());
  std::printf("actual logout allocation/retry/finish/close/disk/service/late/positive PASS checks=%d enumeration_allocations=%d\n",checks,enumeration_allocations);
 } else {
  Fixture f;auto lease=std::make_shared<TunnelLease>();lease->grant=std::make_shared<Grant>();
  f.pending_stops_.push_back(lease);stop_down=true;
  allocations=0;sticky=true;bool escaped=false;
  try{f.retry_stops();}catch(...){escaped=true;}
  allocations=-1;
  REQUIRE(!escaped);
  REQUIRE(f.pending_stops_.size()==1 && f.pending_stops_[0]==lease);
  for(bool persistent:{false,true}) {
   reset();Fixture g;callback_app=&g;
   auto a=std::make_shared<TunnelLease>(),b=std::make_shared<TunnelLease>();
   a->grant=std::make_shared<Grant>();b->grant=a->grant;b->local="sandbox-b";b->binding.exact=9;
   g.pending_stops_={a,b};g.cursors_["control"]={11};
   g.cursors_[a->local]={7};g.cursors_[b->local]={9};stop_down=true;
   allocations=0;sticky=persistent;escaped=false;
   try{window_procedure(0,WM_TIMER,0,0);}catch(...){escaped=true;}
   allocations=-1;
   if(escaped || stop_attempts!=2)std::fprintf(stderr,"timer escaped=%d stop_attempts=%d persistent=%d pending=%zu notices=%d\n",escaped,stop_attempts,persistent,g.pending_stops_.size(),notices);
   REQUIRE(!escaped && stop_attempts==2);
   REQUIRE(g.pending_stops_.size()==2 && g.pending_stops_[0]==a && g.pending_stops_[1]==b);
   REQUIRE(g.cursors_.size()==3 && g.cursors_.at("control").exact==11);
   // Construction succeeds but a notice-body exception still cannot escape.
   notice_throw=true;g.next_stop_={};escaped=false;
   try{window_procedure(0,WM_TIMER,0,0);}catch(...){escaped=true;}
   REQUIRE(!escaped && stop_attempts==4 && g.pending_stops_.size()==2);
   notice_throw=false;
   // Reentrant close preserves both leases and the outstanding grant ticket.
   auto ticket=*g.drain_->begin();active=&g;notice_hook=reentrant_close;g.next_stop_={};
   window_procedure(0,WM_TIMER,0,0);
   REQUIRE(g.closing_ && !g.drain_->ready() && g.pending_stops_[0]==a && g.pending_stops_[1]==b);
   REQUIRE(!g.logout_state_.restore_blocked()); // ordinary close retains credentials
   g.drain_->finish(ticket,a->grant);g.next_cleanup_={};window_procedure(0,WM_TIMER,0,0);
   REQUIRE(g.drain_->ready() && g.pending_stops_.empty() && destroyed_windows>0);
   REQUIRE(remote_attempts==0 && local_attempts==1);
  }
  // Failure evaluating the actual cursor/stop expression retains the exact lease.
  reset();Fixture g;callback_app=&g;g.pending_stops_.push_back(lease);
  allocations=0;sticky=true;escaped=false;
  try{window_procedure(0,WM_TIMER,0,0);}catch(...){escaped=true;}
  allocations=-1;
  REQUIRE(!escaped && g.pending_stops_.size()==1 && g.pending_stops_[0]==lease && g.cursors_.empty());
  g.next_stop_={};window_procedure(0,WM_TIMER,0,0);
  REQUIRE(g.pending_stops_.empty() && g.cursors_.at(lease->local).exact==lease->binding.exact);
  REQUIRE(stop_attempts>=1 && stop_attempts<=2);
  // Sticky OOM may continue into the real idle-poll identity update after the
  // notice was contained; the actual Win32 entry boundary must contain it too.
  reset();Fixture boundary;callback_app=&boundary;boundary.pending_stops_.push_back(lease);
  boundary.cursors_[lease->local]={7};auto pending=*boundary.drain_->begin();
  stop_down=true;sync_throw=true;allocations=0;sticky=true;escaped=false;
  try{window_procedure(0,WM_TIMER,0,0);}catch(...){escaped=true;}
  REQUIRE(!escaped);
  REQUIRE(boundary.pending_stops_.size()==1 && boundary.pending_stops_[0]==lease);
  REQUIRE(!boundary.drain_->ready());
  allocations=-1;sync_throw=false;
  boundary.drain_->finish(pending,lease->grant);boundary.begin_close();boundary.cleanup_step();
  REQUIRE(boundary.drain_->ready() && boundary.pending_stops_.empty());
  // Positive display, including MessageBox error reporting, remains functional.
  int count=notices;g.notice(L"ordinary error notice",true);REQUIRE(notices==count+1);
  std::printf("actual timer/retry_stops report-construction/body/ownership/reentrant/positive PASS checks=%d\n",checks);
 }
}
'''

if __name__ == '__main__':
    main()
