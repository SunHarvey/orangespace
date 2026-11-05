"""Execute the production platform start worker against injected typed seams.
This is caller/ownership policy evidence, NOT native service/HTTPS forwarding.
"""
import argparse
from pathlib import Path
import subprocess
import hashlib
import json

ROOT=Path(__file__).resolve().parents[3]
PRELUDE=r'''
#include "orangespace/platform_workspace.hpp"
#include "orangespace/ui_lifecycle.hpp"
#include <atomic>
#include <cassert>
#include <iostream>
namespace ps {
struct Session {std::string central="central";};
struct NodeRef {std::string node_id,remote_legacy_user_id;};
}
namespace orangespace::service::chain {
struct Cursor {std::string sandbox;std::uint64_t generation;};
struct Binding {std::string user,sandbox,node,tunnel;std::uint64_t generation;};
}
namespace sc {
struct Grant {
 std::string central,legacy,node;
 Grant(std::string c,std::string l,std::string n):central(std::move(c)),legacy(std::move(l)),node(std::move(n)){}
 Grant(Grant&&)noexcept=default;
};
static int authorizations=0,registrations=0,starts=0;
static bool fail_start=false;
Grant authorize_platform(const ps::Session& s,const ps::NodeRef& n) {
 ++authorizations;return Grant{s.central,n.remote_legacy_user_id,n.node_id};
}
orangespace::service::chain::Cursor register_sandbox(const Grant& g,std::string_view local) {
 ++registrations;assert(g.central=="central");return {"service-"+std::string(local),99};
}
orangespace::service::chain::Binding start_registered_tunnel(const Grant& g,std::string_view local) {
 ++starts;if(fail_start)throw 1;
 return {g.legacy,"service-"+std::string(local),g.node,"exact-helper",100};
}
}
namespace Auth {struct Operation {std::int64_t expiry{1000};};}
std::int64_t now(){return 10;}
enum class Job {tunnel};
struct TunnelLease {
 std::shared_ptr<sc::Grant> grant;
 orangespace::service::chain::Binding binding;
 std::string local;
};
struct Completion {
 std::shared_ptr<TunnelLease> tunnel;
 std::shared_ptr<sc::Grant> grant;
 Job job{};Auth::Operation operation;
 std::string local_sandbox;
 orangespace::PlatformRows::Ticket row_ticket;
 std::optional<orangespace::service::chain::Cursor> cursor;
 bool failed{};
};
struct Mailbox {std::atomic<bool> cancelled{false};};
Completion run(std::shared_ptr<sc::Grant> grant,std::string local,ps::NodeRef node,
               std::shared_ptr<TunnelLease> old={},bool cancelled=false) {
 auto session=std::make_shared<ps::Session>();
 Auth::Operation op;orangespace::PlatformRows::Ticket row_ticket{local,node.node_id,1};
 Completion out;Mailbox box;box.cancelled=cancelled;
 try {
 /*WORKER*/
 }catch(...){out.failed=true;}
 return out;
}
int main(){
 auto a=run({},"A",{"node-A","legacy-A"});
 assert(!a.failed && a.grant && a.tunnel && a.tunnel->local=="A");
 assert(a.grant->central=="central" && a.tunnel->binding.user=="legacy-A");
 auto b=run({},"B",{"node-B","legacy-B"});
 assert(!b.failed && b.grant->central==a.grant->central);
 assert(b.tunnel->binding.user=="legacy-B" && b.tunnel->binding.node=="node-B");
 assert(a.tunnel->binding.sandbox=="service-A" && b.tunnel->binding.sandbox=="service-B");
 assert(a.cursor->generation==100); // Service result, never UI generation.
 auto sibling=run(a.grant,"A2",{"node-A","legacy-A"});
 assert(!sibling.failed && !sibling.grant && sc::authorizations==2);
 sc::fail_start=true;
 auto failed=run(a.grant,"A",{"node-A","legacy-A"},a.tunnel);
 assert(failed.failed && failed.tunnel==a.tunnel); // exact old owner survives.
 assert(b.tunnel->binding.node=="node-B" && b.tunnel->binding.generation==100);
 int before=sc::registrations;
 auto cancelled=run(a.grant,"A",{"node-A","legacy-A"},a.tunnel,true);
 assert(cancelled.failed && cancelled.tunnel==a.tunnel && sc::registrations==before);
 std::cout << "actual platform start worker: central/legacy split, node grants cached, ledger cursor, failure/cancel exact owner and sibling preservation PASS\n";
}
'''

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True,type=Path);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
    main=ROOT/'apps/windows-client/src/main_win.cpp';text=main.read_text()
    marker='start([grant,local,op,node=std::move(node),session,row_ticket,old=std::move(old)](Completion& out,Mailbox& box) mutable {'
    worker=text.split(marker,1)[1].split('      });',1)[0]
    # Return in the real lambda returns void. Keep it in a lambda here too.
    worker='auto work=[&]() {\n'+worker+'\n};work();'
    src=a.output/'start_worker.cpp';src.write_text(PRELUDE.replace('/*WORKER*/',worker));exe=a.output/'start_worker'
    cmd=['g++','-std=c++20','-Wall','-Wextra','-Werror','-pthread','-fno-elide-constructors','-I'+str(ROOT/'apps/windows-client/include'),str(src),'-o',str(exe)]
    build=subprocess.run(cmd,text=True,capture_output=True);(a.output/'build.log').write_text(build.stdout+build.stderr)
    if build.returncode:print(build.stderr);raise SystemExit(build.returncode)
    run=subprocess.run([str(exe)],text=True,capture_output=True);(a.output/'run.log').write_text(run.stdout+run.stderr)
    (a.output/'evidence.json').write_text(json.dumps({'command':cmd,'exit':run.returncode,'source_sha256':hashlib.sha256(main.read_bytes()).hexdigest()},indent=2))
    print(run.stdout+run.stderr,end='');raise SystemExit(run.returncode)
if __name__=='__main__':main()
