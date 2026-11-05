"""Injected exact Connect caller policy evidence; NOT native Windows UI."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from platform_ui_tunnel_tests import PRELUDE, ROOT

HARNESS = r'''
struct Identity {std::string central_user_id="central";std::int64_t expires_at=100;};
struct Session : ps::Session {Identity identity_;const Identity& identity()const{return identity_;}};
using Workspace=orangespace::PlatformWorkspace<Session,ps::NodeRef>;
static std::int64_t clock_value=10;
static bool expire_query=false;
namespace sc {
enum class ClientError {service_missing,other};
struct Status {bool status=true;ClientError error=ClientError::other;};
Status query_foundation_status(){if(expire_query)clock_value=100;return {};}
}
struct Row {std::string user_id="central",node_id="node-A",id="A";};
struct Caller {
 Workspace auth_;orangespace::PlatformRows rows_;
 std::vector<std::shared_ptr<TunnelLease>> pending_stops_;
 std::map<std::string,std::shared_ptr<sc::Grant>> grants_;
 std::map<std::string,std::shared_ptr<TunnelLease>> tunnels_;
 std::string starting_local_;
 int notices=0,dispatches=0,renders=0;
 static std::int64_t now(){return clock_value;}
 void notice(const wchar_t*,bool=false){++notices;}
 void render_proofs(){++renders;}
 template<class F>void start(F){++dispatches;}
 void connect(){std::optional<Row> selected=Row{};
 /*CALLER*/
 }
};
void require(bool ok,const char* message){if(!ok){std::cerr<<message<<'\n';std::exit(1);}}
int main(int argc,char**){
 expire_query=argc>1;
 Caller c;
 auto login=c.auth_.begin_login();
 require(c.auth_.finish_login(login,std::make_unique<Session>(),{{"node-A","legacy-A","A"},{"node-B","legacy-B","B"}},10),"login");
 auto a=c.rows_.begin("A","node-A");c.rows_.complete(a,true,true,true);
 auto b=c.rows_.begin("B","node-B");c.rows_.complete(b,true,true,true);
 auto old=std::make_shared<TunnelLease>();c.tunnels_["A"]=old;c.tunnels_["B"]=old;
 c.connect();
 require(c.rows_.proven("B") && c.tunnels_.at("B")==old,"sibling changed");
 require(sc::authorizations==0 && sc::registrations==0 && sc::starts==0,"caller issued service mutation");
 if(expire_query){
 require(c.notices==1 && c.dispatches==0 && c.renders==0,"expired caller must reject with notice before dispatch");
 require(c.rows_.proven("A") && c.tunnels_.at("A")==old && c.starting_local_.empty(),"expired row proof/owner changed");
 }else require(c.dispatches==1 && c.notices==0 && c.rows_.state("A")==orangespace::PlatformRows::State::starting,"live caller must dispatch");
 std::cout<<(expire_query?"expiry rejection":"live dispatch")<<" PASS (injected production Connect caller)\n";
}
'''

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',required=True,type=Path)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
    main=ROOT/'apps/windows-client/src/main_win.cpp';text=main.read_text()
    caller=text.split('    if(id==Connect) {',1)[1].split('\n    }\n    if(selected',1)[0]
    # The complete production caller/lambda compiles; dispatch is intercepted.
    prefix=PRELUDE.split('Completion run(',1)[0]
    prefix=prefix.replace('struct NodeRef {std::string node_id,remote_legacy_user_id;};','struct NodeRef {std::string node_id,remote_legacy_user_id,alias;};')
    declarations, harness=HARNESS.split('static std::int64_t clock_value=10;',1)
    prefix=prefix.replace('namespace Auth {struct Operation {std::int64_t expiry{1000};};}', declarations+'\nnamespace Auth {using Operation=Workspace::Operation;}')
    src=a.output/'connect.cpp';src.write_text(prefix+'static std::int64_t clock_value=10;'+harness.replace('/*CALLER*/',caller))
    exe=a.output/'connect'
    cmd=['g++','-std=c++20','-Wall','-Wextra','-Werror','-pthread','-fsanitize=undefined','-fno-sanitize-recover=all','-I'+str(ROOT/'apps/windows-client/include'),str(src),'-o',str(exe)]
    build=subprocess.run(cmd,capture_output=True,text=True);(a.output/'build.log').write_text(build.stdout+build.stderr)
    if build.returncode:print(build.stderr);raise SystemExit(build.returncode)
    results=[]
    for args in [[],['expiry']]:
        run=subprocess.run([str(exe),*args],capture_output=True,text=True)
        label='expiry' if args else 'live';(a.output/(label+'.log')).write_text(run.stdout+run.stderr)
        print(label,run.returncode,run.stdout+run.stderr);results.append(run.returncode)
    (a.output/'evidence.json').write_text(json.dumps({'label':'injected-production-Connect-caller-policy-not-native','command':cmd,'exits':results,'source_sha256':hashlib.sha256(main.read_bytes()).hexdigest()},indent=2))
    raise SystemExit(any(results))
if __name__=='__main__':main()
