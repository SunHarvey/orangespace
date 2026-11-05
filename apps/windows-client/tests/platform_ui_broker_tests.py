"""Production broker worker proof accounting; injected broker/stop, not native."""
from pathlib import Path
import subprocess
import argparse
ROOT=Path(__file__).resolve().parents[3]
CPP=r'''
#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <cassert>
#include <iostream>
namespace orangespace {int run_broker(const std::vector<std::wstring>&){return 0;}}
namespace sc {int stop_tunnel(int,int){return 99;}}
struct Lease {int grant_storage{};int* grant=&grant_storage;int binding{};};
struct Op {int expiry{1000};};
int now(){return 10;}
enum class Job {broker};
struct Completion {std::shared_ptr<Lease> tunnel;Job job;Op operation;bool refresh{},failed{},stopped{};std::string local_sandbox;std::optional<int> cursor;int process;};
struct Mailbox {bool cancelled{};};
Completion run(bool stopping,std::shared_ptr<Lease> closing={}) {
 Completion out;Mailbox box;std::vector<std::wstring> args;Op op;bool refresh=false;std::string local="A";
 /*WORKER*/
 return out;
}
int main(){
 auto list=run(false);assert(!list.stopped); // Listing A must not clear A's proof.
 auto create=run(false);assert(!create.stopped);
 auto close=run(true,std::make_shared<Lease>());assert(close.stopped && close.cursor==99 && !close.tunnel);
 std::cout << "actual broker worker: list/create preserve proof; close records exact acknowledged stop PASS\n";
}
'''
def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
 text=(ROOT/'apps/windows-client/src/main_win.cpp').read_text()
 marker='(Completion& out, Mailbox& box) {\n      out.tunnel=closing;'
 body='      out.tunnel=closing;'+text.split(marker,1)[1].split('    });',1)[0]
 # The injected bool is the production captured stopping predicate.
 src=a.output/'broker.cpp';src.write_text(CPP.replace('/*WORKER*/','auto work=[&]() { (void)stopping;\n'+body+'\n};work();'))
 exe=a.output/'broker';cmd=['g++','-std=c++20','-Wall','-Wextra','-Werror',str(src),'-o',str(exe)]
 b=subprocess.run(cmd,capture_output=True,text=True);(a.output/'build.log').write_text(b.stdout+b.stderr)
 if b.returncode:print(b.stderr);raise SystemExit(b.returncode)
 r=subprocess.run([str(exe)],capture_output=True,text=True);(a.output/'run.log').write_text(r.stdout+r.stderr);print(r.stdout+r.stderr,end='');raise SystemExit(r.returncode)
if __name__=='__main__':main()
