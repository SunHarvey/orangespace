"""Extracted production worker + injected OS/proof seams; not native Windows evidence.
Run directly with Python; requires a C++20 compiler. No product test switches.
Root-private secret/ACK branch is compiled intact, but not executed here;
these child interleavings do not cover the Root-only secret path.
"""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]
SOURCE = (ROOT / 'apps/windows-service/prototype/service_win.cpp').read_text()
WFP = (ROOT / 'drivers/wfp-prototype/network_policy_win.cpp').read_text()

class Concurrency(unittest.TestCase):
    def test_accept_has_no_full_proof(self):
        accept = SOURCE.split('while(live(root.process.get())', 1)[1].split('workers.emplace_back([&,pipe=', 1)[0]
        self.assertNotIn('native_mechanism_validated(', accept)
        self.assertIn('admission-watchdog-exception', SOURCE)

    def test_actual_workers_overlap_and_fail_closed(self):
        worker = SOURCE.split('workers.emplace_back([&,pipe=std::move(listener)]()mutable{', 1)[1].split('});listener=std::move(next);', 1)[0]
        fence = 'void admission_fence(' + SOURCE.split('void admission_fence(',1)[1].split('void status(',1)[0]
        harness = r'''
#include "service_binding.hpp"
#include "../../windows-client/prototype/private_channel.hpp"
#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <set>
#include <thread>
using namespace std::chrono_literals;
namespace p=orangespace::prototype;
using HANDLE=unsigned;using DWORD=unsigned;using ULONG=unsigned;using BYTE=unsigned char;using ULONGLONG=unsigned long long;
constexpr unsigned WAIT_TIMEOUT=258,WAIT_OBJECT_0=0,ERROR_INVALID_DATA=13,FALSE=0;
struct Failure{unsigned code;};void need(bool b){if(!b)throw Failure{13};}
struct Handle{unsigned h=1;unsigned get()const{return h;}};
thread_local const char*stage="test";thread_local unsigned who=0;thread_local unsigned local_proofs=0;
std::atomic<bool>stopped=false;std::atomic<unsigned>kills=0,commits=0,proofs=0;
std::mutex seam;std::condition_variable cv;bool entered=false,released=false;
int fault=0;unsigned stop_event=1;
std::atomic<unsigned>service_stop_event{9};
unsigned GetTickCount64(){return 0;}void report_fixed(const char*,unsigned){}
void SetEvent(unsigned){stopped=true;}void TerminateJobObject(unsigned,unsigned){++kills;}
unsigned WaitForSingleObject(unsigned,unsigned ms){return stopped||ms==200?0:WAIT_TIMEOUT;}
unsigned WaitForMultipleObjects(unsigned,const HANDLE*,unsigned,unsigned){assert(false);return WAIT_TIMEOUT;}
bool live(unsigned){return true;}unsigned long long birth(unsigned h){return h+100;}
unsigned GetProcessId(unsigned h){return h;}
bool GetNamedPipeClientProcessId(unsigned h,unsigned*p){*p=h;who=h;return true;}
bool PeekNamedPipe(unsigned,void*,unsigned,void*,unsigned*p,void*){*p=0;return true;}
struct Root{Handle process{99},job{99};unsigned pid=99;unsigned long long created_at=199;bool contained(unsigned){return true;}}root;
bool scm_self(){return true;}
int session=0,runtime=0,inspections=0;
// Compile-only seams for the intact, unexecuted Root-private branch. Fail if
// a child interleaving unexpectedly enters it; never simulate secret success.
namespace orangespace::service::chain::nd { long long monotonic_ms(){return 0;} }
struct LocalChannel {
 struct Binding {std::string user,sandbox,node,tunnel;unsigned long long generation{};long long server_expiry{},deadline_ms{};} binding;
 struct Budget {long long request_started_ms{},remaining_ttl_ms{},deadline_ms{};} budget;
 struct Secret {std::string_view view()const{return {};}} username,password;
 long long proof_observed_at_ms{};unsigned short port{};
} local_channel;
auto*channel=&local_channel;
struct Control {
 void verify_live(const LocalChannel&){assert(false&&"Root-private branch is outside child fixture coverage");}
 long long fresh_forwarding_proof(const LocalChannel&){assert(false);return 0;}
 p::BrowserFrame next_command(){assert(false);return {};}
 void observe(const p::BrowserFrame&){assert(false);}
}control;
void diagnose_private_offer(const p::PrivateOffer&,long long){assert(false);}
using BCRYPT_ALG_HANDLE=void*;using PUCHAR=unsigned char*;
constexpr unsigned BCRYPT_USE_SYSTEM_PREFERRED_RNG=2;
constexpr auto BCRYPT_SHA256_ALGORITHM=L"SHA256";
int BCryptGenRandom(void*,PUCHAR,unsigned,unsigned){assert(false);return -1;}
int BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE*,const wchar_t*,const wchar_t*,unsigned){assert(false);return -1;}
int BCryptHash(BCRYPT_ALG_HANDLE,PUCHAR,unsigned,PUCHAR,unsigned,PUCHAR,unsigned){assert(false);return -1;}
int BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE,unsigned){assert(false);return -1;}
p::Binding peer(unsigned h,int&,decltype(root)&,int&,Handle&retained,const p::Request&q,bool){
 need(!(fault==3&&h==2));retained.h=h;need(q.pid==h);return {h,1,birth(h)};
}
p::Reply baseline{};
p::Reply native_mechanism_validated(int&,int&,decltype(root)&,int&){
 ++proofs;++local_proofs;
 if(who==1&&(fault!=8||local_proofs==2)){std::unique_lock l(seam);entered=true;cv.notify_all();cv.wait(l,[]{return released;});}
 if(who==2&&fault==1)throw Failure{13};
 if(who==2&&(fault==2||(fault==5&&local_proofs==2)))stopped=true;
 if(who==2&&fault==4&&local_proofs==2)throw Failure{13};
 auto reply=baseline;if(who==2&&fault==6&&local_proofs==2)++reply.rules_epoch;return reply;
}
FENCE
bool io(unsigned h,void*data,unsigned size,bool write){
 if(write){if(size==sizeof(p::Reply)&&static_cast<p::Reply*>(data)->status==2)++commits;return true;}
 if(size==1){*static_cast<BYTE*>(data)=(fault==7&&h==2)?0:6;return true;}
 auto&q=*static_cast<p::Request*>(data);q.magic=p::kMagic;q.version=p::kVersion;q.size=sizeof(q);q.pid=h;q.session=1;q.created=birth(h);q.nonce[0]=h;return true;
}
int main(int argc,char**argv){
 fault=argc>1?argv[1][0]-'0':0;
 std::mutex gate;bool root_committed=true;std::set<std::pair<DWORD,std::uint64_t>>admitted;
 auto start=[&](unsigned id){return std::thread([&,pipe=Handle{id}]()mutable{WORKER});};
 auto slow=start(1);
 {std::unique_lock l(seam);assert(cv.wait_for(l,1s,[]{return entered;}));}
 auto fast=start(2);
 bool progressed=false;
 for(int i=0;i<100;i++){if((fault&&fault!=8)?stopped.load():commits.load()==1){progressed=true;break;}std::this_thread::sleep_for(5ms);}
 {std::lock_guard l(seam);released=true;}cv.notify_all();slow.join();fast.join();
 assert(progressed&&"slow proof serialized unrelated admission");
 if(fault&&fault!=8){assert(commits==0);assert(kills>0);}else{assert(commits==2);assert(proofs==4);}
 std::cout<<"worker interleaving fault="<<fault<<" passed\n";
}
'''.replace('WORKER', worker).replace('FENCE',fence)
        with tempfile.TemporaryDirectory(prefix='admission-', dir=os.environ.get('TMPDIR')) as tmp:
            cpp=Path(tmp)/'test.cpp';exe=Path(tmp)/'test';cpp.write_text(harness)
            subprocess.run(['c++','-std=c++20','-pthread','-I'+str(ROOT/'apps/windows-service/prototype'),str(cpp),'-o',str(exe)],check=True)
            for fault in range(9):
                subprocess.run([str(exe),str(fault)],check=True,timeout=5)

    def test_actual_fresh_rule_scheduler(self):
        with tempfile.TemporaryDirectory(prefix='fresh-rules-',dir=os.environ.get('TMPDIR')) as tmp:
            exe=Path(tmp)/'test'
            subprocess.run(['c++','-std=c++20','-pthread','-Wall','-Wextra','-Werror',
                            '-I'+str(ROOT/'apps/windows-service/prototype'),
                            str(Path(__file__).with_name('fresh_rule_inspection_tests.cpp')),
                            '-o',str(exe)],check=True)
            subprocess.run([str(exe)],check=True,timeout=15)

    def test_fresh_scheduler_integrated_each_proof_and_lifetime(self):
        proof=SOURCE.split('p::Reply native_mechanism_validated',1)[1].split('void admission_fence',1)[0]
        self.assertIn('proof.rules_digest=inspections.snapshot()',proof)
        self.assertNotIn('rules_snapshot(r,net)',proof)
        main=SOURCE.split('void WINAPI main_service',1)[1]
        self.assertLess(main.index('p::FreshRuleInspection inspections('),main.index('auto baseline='))
        capture=main.split('p::FreshRuleInspection inspections([&]{',1)[1].split('});',1)[0]
        checks=['control.verify_live(*channel)',
                'OwnedLoopbackExemption::read(actual)==ERROR_SUCCESS',
                'EqualSid(const_cast<BYTE*>(entry.sid.data()),root.package)',
                'need(entry.attributes==0)', 'need(owned==1)',
                'return rules_snapshot(runtime,network,package_network,channel->port)']
        end=0
        for check in checks:
            end=capture.index(check,end)+len(check)
        self.assertLess(main.index('p::FreshRuleInspection inspections('),main.index('struct Join {'))
        self.assertIn('join{workers,root,inspections}',main)
        join=main.split('struct Join {',1)[1].split('join{workers,root,inspections}',1)[0]
        self.assertLess(join.index('t.thread.join()'),join.index('inspections.stop()'))

    def test_wfp_restored_single_engine(self):
        body=WFP.split('NetworkPolicy::verifyExactPolicy(',1)[1].split('void NetworkPolicy::cleanupAfterExactTreeExit',1)[0]
        self.assertIn('std::lock_guard lock(s.mutex)',body)
        self.assertIn('Transaction tx(s.engine)',body)
        self.assertIn('s.inventory(expected,port)',body)
        self.assertNotIn('FwpmEngineOpen0(',body)
        self.assertNotIn('FWPM_TXN_READ_ONLY',body)
        self.assertNotIn('shared_mutex',WFP)

    def test_existing_peer_checks_and_shutdown_ownership_retained(self):
        peer=SOURCE.split('p::Binding peer(',1)[1].split('std::array<BYTE,32> hashbytes',1)[0]
        for check in ['root_committed&&opener==r.pid', 'r.contained(retained.get())&&runtime.image(retained.get())',
                      'actual.sid==s.peer.sid&&actual.session==s.id&&actual.logon==s.peer.logon',
                      'ImpersonateNamedPipeClient(pipe)', 'pipepeer.logon==actual.logon']:
            self.assertIn(check,peer)
        join=SOURCE.split('struct Join {',1)[1].split('join{workers,root,inspections}',1)[0]
        self.assertLess(join.index('SetEvent(stop_event)'),join.index('t.thread.join()'))
        self.assertLess(join.index('TerminateJobObject('),join.index('t.thread.join()'))

if __name__=='__main__':unittest.main()
