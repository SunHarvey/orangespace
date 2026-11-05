"""Production-extracted UI cleanup ordering, injected seams; NOT native."""
import argparse
from pathlib import Path
import subprocess
import json
import hashlib
import shlex
import os
import shutil
ROOT=Path(__file__).resolve().parents[3]
def between(s,a,b):return s.split(a,1)[1].split(b,1)[0]
def main():
 p=argparse.ArgumentParser();p.add_argument('--output',required=True,type=Path);p.add_argument('--slice',choices=['receive','adopt','dispatch','broker'],required=True);p.add_argument('--sanitize',action='store_true');a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
 source=(ROOT/'apps/windows-client/src/main_win.cpp').read_text()
 receive='    std::unique_ptr<Completion> out;'+between(source,'    std::unique_ptr<Completion> out;','    if (out->generation != generation_)')
 adopt=between(source,'        if(!out->tunnel) throw std::runtime_error("tunnel proof absent");','        notice(L"独立 helper')
 # Keep exact dispatch and first completion statements; replace only execution seams.
 dispatch='      std::shared_ptr<TunnelLease> old;'+between(source,'      std::shared_ptr<TunnelLease> old;','        // A start with a prior service cursor')
 dispatch=dispatch+'      (void)box;});'+between(source,'        out.cursor=orangespace::service::chain::Cursor{out.tunnel->binding.sandbox,out.tunnel->binding.generation};\n      });','\n    }')
 broker='    std::shared_ptr<TunnelLease> closing;'+between(source,'    std::shared_ptr<TunnelLease> closing;','      if (box.cancelled || now() >= op.expiry)')
 broker+='      (void)box;});'+between(source,'      out.process = orangespace::run_broker(args); // UUIDs only; no password/token IPC.\n    });','    notice(L"正在处理已认证工作区的本机元数据……");')
 cpp=r'''
#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <cstdio>
#include <memory>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>
#include <stdexcept>
#include <functional>
#include <new>
static long fail=-1;static bool sticky=true;
void* operator new(std::size_t n){if(fail==0){if(!sticky)fail=-1;throw std::bad_alloc();}if(fail>0)--fail;if(auto p=std::malloc(n?n:1))return p;throw std::bad_alloc();}
void operator delete(void* p)noexcept{std::free(p);}void operator delete(void* p,std::size_t)noexcept{std::free(p);}
struct Cursor{std::string sandbox;unsigned generation;};
namespace orangespace::service::chain{using Cursor=::Cursor;}
struct TunnelLease{int generation=73;};
struct Operation{std::string user;};
enum class Job{tunnel,broker};
struct Selected{std::string id;};enum{Bind=1,Close,Delete};
struct Completion{std::shared_ptr<TunnelLease> tunnel;Job job{};Operation operation;std::string local_sandbox;bool refresh=false;};
struct Mailbox{std::mutex mutex;std::unique_ptr<Completion> result;};
struct Fixture{
 std::shared_ptr<Mailbox> mailbox_=std::make_shared<Mailbox>();std::thread worker_;bool busy_=true;
 std::vector<std::shared_ptr<TunnelLease>> pending_stops_;
 std::map<std::string,std::shared_ptr<TunnelLease>> tunnels_;
 std::map<std::string,Cursor> cursors_;
 std::string local=std::string(100,'L');Operation op{std::string(100,'U')};int grant=1;
 std::unique_ptr<Completion> captured;bool dispatch_fail=false;
 void sync_identity(){}void notice(const wchar_t*){}
 void receive(){/*RECEIVE*/}
 void adopt(Completion* out){(void)out;/*ADOPT*/}
 template<class W>void start(W work){if(dispatch_fail)throw std::bad_alloc();captured=std::make_unique<Completion>();Mailbox box;try{work(*captured,box);}catch(...){}}
 void dispatch(){auto local=this->local;auto op=this->op;auto grant=this->grant;(void)grant;/*DISPATCH*/}
 void broker(){auto op=this->op;std::optional<Selected> selected{Selected{local}};int id=Close;bool refresh=true;std::vector<int> args{1};(void)id;(void)refresh;/*BROKER*/}
};
#define REQUIRE(x) do{if(!(x)){fail=-1;std::fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(){
 for(bool persistent:{false,true})for(int n=0;n<12;++n){
  Fixture f;auto lease=std::make_shared<TunnelLease>();auto sibling=std::make_shared<TunnelLease>();f.tunnels_["sibling"]=sibling;
  /*CASE*/
  REQUIRE(f.tunnels_.at("sibling")==sibling);
 }
 std::puts("extracted caller persistent/transient allocation sweep PASS");
}
'''
 cases={
 'receive':r'''f.mailbox_->result=std::make_unique<Completion>();f.mailbox_->result->tunnel=lease;
 sticky=persistent;fail=n;bool escaped=false;try{f.receive();}catch(...){escaped=true;}
 REQUIRE(!escaped);
 bool retained=std::find(f.pending_stops_.begin(),f.pending_stops_.end(),lease)!=f.pending_stops_.end();
 REQUIRE(retained || (f.mailbox_ && f.mailbox_->result && f.mailbox_->result->tunnel==lease));
 fail=-1;if(f.busy_)f.receive();REQUIRE(std::find(f.pending_stops_.begin(),f.pending_stops_.end(),lease)!=f.pending_stops_.end());''',
 'adopt':r'''Completion out;out.tunnel=lease;out.local_sandbox=f.local;f.pending_stops_.push_back(lease);
 sticky=persistent;fail=n;try{f.adopt(&out);}catch(...){}
 auto it=f.tunnels_.find(f.local);bool adopted=it!=f.tunnels_.end() && it->second==lease;
 REQUIRE(adopted || std::find(f.pending_stops_.begin(),f.pending_stops_.end(),lease)!=f.pending_stops_.end());
 if(adopted)REQUIRE(std::find(f.pending_stops_.begin(),f.pending_stops_.end(),lease)==f.pending_stops_.end());fail=-1;''',
 'dispatch':r'''f.tunnels_[f.local]=lease;f.cursors_[f.local]=Cursor{std::string(100,'S'),72};
 sticky=persistent;fail=n;try{f.dispatch();}catch(...){}
 auto it=f.tunnels_.find(f.local);REQUIRE((it!=f.tunnels_.end() && it->second==lease) || (f.captured && f.captured->tunnel==lease));fail=-1;'''}
 cases['broker']=cases['dispatch'].replace('f.dispatch()','f.broker()')
 # Only compile the selected slice, avoiding unrelated definitions under test.
 for tag,value in [('RECEIVE',receive if a.slice=='receive' else ''),('ADOPT',adopt if a.slice=='adopt' else ''),('DISPATCH',dispatch if a.slice=='dispatch' else ''),('BROKER',broker if a.slice=='broker' else ''),('CASE',cases[a.slice])]:cpp=cpp.replace('/*'+tag+'*/',value)
 src=a.output/'extracted.cpp';src.write_text(cpp);exe=a.output/'test';dep=a.output/'test.d'
 cmd=['g++','-std=c++20','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-g','-fno-elide-constructors','-pthread','-MD','-MF',str(dep),'-Wl,-t',str(src),'-o',str(exe)]
 if a.sanitize:cmd+=['-fsanitize=address,undefined','-fno-omit-frame-pointer','-fno-pie','-no-pie']
 b=subprocess.run(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT);(a.output/'build.log').write_text(shlex.join(cmd)+'\n'+b.stdout)
 if b.returncode:print(b.stdout);raise SystemExit(b.returncode)
 cc=shutil.which('g++')
 if cc is None:raise SystemExit('g++ missing; no fallback')
 files=[src,exe,Path(__file__).resolve(),ROOT/'apps/windows-client/src/main_win.cpp',dep,Path(cc).resolve()]
 files += [Path(s) for s in shlex.split(dep.read_text().replace('\\\n',' ').split(':',1)[1])]
 files += [Path(s.strip()).resolve() for s in b.stdout.splitlines() if Path(s.strip()).is_file()]
 (a.output/'sha256.json').write_text(json.dumps({str(x):hashlib.sha256(x.read_bytes()).hexdigest() for x in sorted(set(files))},indent=2))
 r=subprocess.run([str(exe)],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=1:halt_on_error=1'});(a.output/'result.log').write_text(r.stdout);print(r.stdout,end='');raise SystemExit(r.returncode)
if __name__=='__main__':main()
