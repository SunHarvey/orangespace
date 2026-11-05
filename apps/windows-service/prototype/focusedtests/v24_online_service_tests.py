"""Actual production slices with injected OS seams; not Windows acceptance."""
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / 'service_win.cpp').read_text()

class V24Online(unittest.TestCase):
    def test_auth_wfp_and_root_only_secret_order(self):
        body = SOURCE.split('void WINAPI main_service', 1)[1]
        markers = ['network.installOffline(runtime.exe.wstring())', 'control.start()',
                   'control.wait_channel(200)', 'root.create(runtime,session)',
                   'package_network.installOffline(root.package)', 'network.switchToProxyOnly(channel->port)',
                   'package_network.switchToProxyOnly(channel->port)', 'exemption.appendAfterVerifiedWfp()',
                   'auto baseline=native_mechanism_validated', 'ResumeThread(root.thread.get())']
        for marker in markers:
            self.assertIn(marker, body)
        positions = [body.index(x) for x in markers]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('need(pipe_opener==root.pid)', body)
        self.assertIn('p::PrivateOwner private_owner', body)
        self.assertLess(body.index('p::PrivateOwner private_owner'), body.index('stage="private-ack-read"'))
        self.assertIn('commit.ack(ack,q,again)', body)
        self.assertIn('reply.version=p::kVersion', body)
        self.assertNotIn('TokenLinkedToken', SOURCE)
        self.assertNotIn('CreateRestrictedToken', SOURCE)

    def test_actual_job_member_verifier(self):
        self.assertIn('void verify_job_members(', SOURCE)
        start = SOURCE.index('void verify_job_members(')
        end = SOURCE.index('\np::Reply native_mechanism_validated', start)
        implementation = SOURCE[start:end]
        harness = r'''
#include <vector>
#include <cstdint>
#include <cassert>
#include <stdexcept>
using DWORD=unsigned;using ULONG_PTR=std::uintptr_t;using HANDLE=ULONG_PTR;using BOOL=int;
constexpr DWORD WAIT_OBJECT_0=0,WAIT_TIMEOUT=258,PROCESS_QUERY_LIMITED_INFORMATION=1,SYNCHRONIZE=2,TOKEN_QUERY=4;
constexpr int JobObjectBasicProcessIdList=3;
struct JOBOBJECT_BASIC_PROCESS_ID_LIST {DWORD NumberOfAssignedProcesses,NumberOfProcessIdsInList;ULONG_PTR ProcessIdList[1];};
struct Handle {HANDLE h;Handle(HANDLE v=0):h(v){}HANDLE get(){return h;}explicit operator bool(){return h!=0;}};
struct Peer {int sid=1,session=2,logon=3;};
struct Session {Peer peer;int id=2;};
bool wrong=false,exited=false,unknown=false,missing=false,overflow=false,recycled=false;
bool wrong_session=false,wrong_logon=false,bad_image=false,bad_package=false,exit_during_query=false;unsigned checked=0;
void need(bool x){if(!x)throw std::runtime_error("denied");}
DWORD WaitForSingleObject(HANDLE h,int){return unknown?999:((exited&&h==20)?WAIT_OBJECT_0:WAIT_TIMEOUT);}
BOOL QueryInformationJobObject(HANDLE,int,void*p,DWORD,void*){auto*x=(JOBOBJECT_BASIC_PROCESS_ID_LIST*)p;x->NumberOfAssignedProcesses=overflow?3:2;x->NumberOfProcessIdsInList=2;x->ProcessIdList[0]=10;x->ProcessIdList[1]=20;return 1;}
HANDLE OpenProcess(DWORD,BOOL,DWORD pid){return missing&&pid==20?0:pid;}
constexpr BOOL FALSE=0;
DWORD GetProcessId(HANDLE h){return recycled&&h==20?21:DWORD(h);}
std::uint64_t birth(HANDLE h){return h+100;}
BOOL OpenProcessToken(HANDLE h,DWORD,HANDLE*out){*out=h;return 1;}
Peer token_peer(HANDLE h){Peer p;if(wrong&&h==20)p.sid=9;if(wrong_session&&h==20)p.session=9;if(wrong_logon&&h==20)p.logon=9;if(exit_during_query&&h==20){exited=true;throw std::runtime_error("exited");}return p;}
struct Runtime {bool image(HANDLE h){return !(bad_image&&h==20);}};
struct Root {Handle job{1},process{10};DWORD pid=10;std::uint64_t created_at=110;bool contained(HANDLE h){++checked;return !(bad_package&&h==20);}};
'''
        cases = r'''
int main(){Runtime r;Session s;Root root;
auto accepts=[&]{try{verify_job_members(r,s,root);return true;}catch(...){return false;}};
assert(accepts()&&checked==2);wrong=true;assert(!accepts());wrong=false;
exited=true;wrong=true;assert(accepts());wrong=false;exited=false;
unknown=true;assert(!accepts());unknown=false;missing=true;assert(!accepts());missing=false;
overflow=true;assert(!accepts());overflow=false;recycled=true;assert(!accepts());recycled=false;
wrong_session=true;assert(!accepts());wrong_session=false;wrong_logon=true;assert(!accepts());wrong_logon=false;
bad_image=true;assert(!accepts());bad_image=false;bad_package=true;assert(!accepts());bad_package=false;
exit_during_query=true;assert(accepts());
}
'''
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root/'test.cpp').write_text(harness+implementation+cases)
            subprocess.run(['g++','-std=c++20','-Wall','-Wextra','-Werror',str(root/'test.cpp'),'-o',str(root/'test')],check=True)
            subprocess.run([str(root/'test')],check=True)
        proof = SOURCE.split('p::Reply native_mechanism_validated',1)[1]
        self.assertIn('verify_job_members(r,s,root)',proof)

if __name__ == '__main__':
    unittest.main()
