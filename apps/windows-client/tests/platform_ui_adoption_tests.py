"""Execute production GUI login adoption and rejection handoff (injected disk/SDK)."""
import argparse
from pathlib import Path
import subprocess
from ui_test_slices import method
ROOT=Path(__file__).resolve().parents[3]
PRELUDE=r'''
#include "orangespace/platform_workspace.hpp"
#include <mutex>
#include <cassert>
#include <iostream>
namespace ps {
struct NodeRef {std::string alias,node_id;};
struct Session {struct Identity {std::string central_user_id="central";int expires_at=100;};Identity id;const Identity& identity(){return id;}};
struct PlatformConfig {};
struct CredentialStore {static inline bool fail=false,saved=false;static void erase(PlatformConfig&){}static void save(PlatformConfig&,Session&){saved=true;if(fail)throw 1;}};
}
using Auth=orangespace::PlatformWorkspace<ps::Session,ps::NodeRef>;
struct Completion {std::unique_ptr<ps::Session> session;Auth::LoginTicket login;std::vector<ps::NodeRef> nodes;};
struct Mailbox {std::mutex mutex;std::unique_ptr<Completion> result;};
int now(){return 10;}
struct App {
 Auth auth_;bool busy_{},logout_called{};
 std::shared_ptr<Mailbox> mailbox_=std::make_shared<Mailbox>();
 std::shared_ptr<ps::PlatformConfig> catalog_=std::make_shared<ps::PlatformConfig>();
 void logout(){logout_called=true;}
 /*METHODS*/
};
int main(){
 for(int mode=0;mode<3;++mode){App a;auto out=std::make_unique<Completion>();out->session=std::make_unique<ps::Session>();out->login=a.auth_.begin_login();
 ps::CredentialStore::fail=(mode==0);if(mode==1)a.auth_.logout();
 try {a.persist_login(*a.catalog_,*out->session,true);a.adopt_login(*out);}catch(...){assert(out->session);a.reject_login(out);}
 if(mode<2){assert(a.logout_called && a.busy_ && !out && a.mailbox_->result->session);assert(!a.auth_.active(10));}
 else {assert(a.auth_.active(10) && !out->session && !a.logout_called);}
 }
 std::cout<<"actual GUI login adoption: save failure/rejected adoption retain session in existing logout/erase drain; success adopted PASS\n";
}
'''
def main():
 p=argparse.ArgumentParser();p.add_argument('--output',required=True,type=Path);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
 text=(ROOT/'apps/windows-client/src/main_win.cpp').read_text()
 assert 'void adopt_login(' in text,'missing adoption cleanup handoff'
 source=PRELUDE.replace('/*METHODS*/','\n'.join(method(text,s) for s in ['  static void persist_login(', '  void adopt_login(', '  void reject_login(']))
 src=a.output/'adoption.cpp';src.write_text(source);exe=a.output/'adoption'
 subprocess.run(['g++','-std=c++20','-Wall','-Wextra','-Werror','-pthread','-I'+str(ROOT/'apps/windows-client/include'),str(src),'-o',str(exe)],check=True);subprocess.run([str(exe)],check=True)
if __name__=='__main__':main()
