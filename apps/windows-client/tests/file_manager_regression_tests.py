#!/usr/bin/env python3
"""Compile exact production admission/callback/dialog-fence slices with injected OS seams.
Portable policy evidence only, not native Windows GUI acceptance. Caller holds build lock.
"""
from pathlib import Path
import subprocess, sys
ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / 'apps/windows-client/src/file_manager_win.cpp'
OUT = Path('/var/tmp/hermes-runtime/tmp/orangespace-ui-v2/file-panel-regression')
OUT.mkdir(parents=True, exist_ok=True)
s = SRC.read_text()
def block(signature):
    start = s.index(signature)
    import re
    opening = s.index('{', start) if 'struct ' in signature else start + re.search(r'\)\s*\{', s[start:]).end() - 1
    # These bodies have balanced braces, including their string literals.
    depth = 1; end = opening + 1
    while depth:
        depth += (s[end] == '{') - (s[end] == '}'); end += 1
    return s[start:end]
common = r'''
#include <atomic>
#include <memory>
#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <stdexcept>
#include <iostream>
#include <functional>
using HWND=long; using UINT=unsigned; using WPARAM=unsigned long; using LPARAM=long; using LRESULT=long; using LONG_PTR=long;
#define CALLBACK
constexpr int GWLP_USERDATA=1,WM_NCCREATE=2,WM_COMMAND=3,WM_CLOSE=4,IDOK=5,IDCANCEL=6;
unsigned LOWORD(WPARAM a){return a;}
struct CREATESTRUCTW{void* lpCreateParams;};
void* dialog{}; long GetWindowLongPtrW(HWND,int){return reinterpret_cast<long>(dialog);} void SetWindowLongPtrW(HWND,int,long){} long DefWindowProcW(HWND,UINT,WPARAM,LPARAM){return 0;}
bool fail_text=false; std::wstring text(HWND){if(fail_text)throw std::bad_alloc();return L"folder";}
using BOOL=int;constexpr int FALSE=0;
bool enabled=true;int destroyed=0;BOOL IsWindowEnabled(HWND){return enabled;}void EnableWindow(HWND,BOOL e){enabled=e;}void DestroyWindow(HWND){++destroyed;}
struct Context {int central_envelope=1,platform=1; std::string central_user_id,sandbox_id,node_id;struct Session{void reset(){}}session;};
namespace panel_detail{struct Scope{std::string user_id,sandbox_id,node_id,directory;unsigned long epoch;};}
enum class Kind{List,Mkdir,Upload,Download};enum class State{Queued,Failed,Cancelled};
struct Job{panel_detail::Scope scope;Kind kind;Context context;std::string remote;std::wstring local,name;std::atomic<bool> done{false},cancel{false};std::atomic<State> state{State::Queued};Job(panel_detail::Scope s,Kind k,Context c):scope(s),kind(k),context(c){}};
template<class T>struct Items:std::vector<T>{bool fail=false;void push_back(const T& x){if(fail)throw std::bad_alloc();std::vector<T>::push_back(x);}};
struct Queue:std::deque<std::shared_ptr<Job>>{bool fail=false;void push_back(const std::shared_ptr<Job>& x){if(fail)throw std::bad_alloc();std::deque<std::shared_ptr<Job>>::push_back(x);}};
struct Wake{void notify_one(){}};
int failures=0;void check(bool ok,const char* msg){if(!ok){++failures;std::cout<<"FAIL "<<msg<<'\n';}}
'''
admit = block('  void admit(') if '  void admit(' in s else ''
enqueue = block('  std::shared_ptr<Job> enqueue(')
command = block('  void command(')
# Execute the exact retry admission statements, preserving surrounding production guard separately.
retry = command[command.index('auto next='):command.index('\n        break;')].rstrip().removesuffix('}')
code = common + '''struct Panel{Context current;std::string directory="d";unsigned long epoch=1;Items<std::shared_ptr<Job>> jobs;Queue queue;std::mutex mutex;Wake wake;bool fail_start=false;void start(){if(fail_start)throw std::runtime_error("thread");}
''' + admit + '\n' + enqueue + '''
void retry_job(std::shared_ptr<Job> j){'''+retry+'''}
};
int main(){for(int retry=0;retry<2;++retry)for(int fault=0;fault<3;++fault){Panel p;auto old=std::make_shared<Job>(panel_detail::Scope{"u","s","n","d",1},Kind::Upload,p.current);p.fail_start=fault==0;p.queue.fail=fault==1;p.jobs.fail=fault==2;try{if(retry)p.retry_job(old);else p.enqueue(Kind::Upload,"d/f");}catch(...){}for(auto& j:p.jobs)check(j->done&&j->state==State::Failed,"unsubmitted job must be terminal Failed");check(p.queue.empty(),"failed admission must not retain queue ownership");check(!old->done,"exact unsubmitted failure must not mutate original");}
Panel p;p.enqueue(Kind::Upload,"d/f");check(p.jobs.size()==1&&p.queue.size()==1&&!p.jobs[0]->done,"successful admission retained");return failures?1:0;}
'''
# Callback is executed unchanged with text() allocation failure.
callback = common + 'struct Panel{'+block('  struct NameDialog')+';'+block('  static LRESULT CALLBACK name_proc')+'''};
int main(){Panel::NameDialog d;dialog=&d;fail_text=true;bool escaped=false;try{Panel::name_proc(1,WM_COMMAND,IDOK,0);}catch(...){escaped=true;}check(!escaped,"callback exception escaped");check(d.done&&!d.accepted,"callback failure must cancel and finish");return failures?1:0;}
'''
# Retain exact opening captures and final production acceptance/fence; inject modal outcome/context changes.
body = block('  void make_dir()')
prefix = body[body.index('{')+1:body.index('    WNDCLASSW')]
suffix = body[body.index('    if(d.accepted)'):body.rfind('}')]
fence = common + '''std::string utf8(const std::wstring&){return "folder";}std::string joined(const std::string& d,const std::string& n){return d+"/"+n;}
struct Panel{Context current;std::string directory="d";unsigned long epoch=1;int submitted=0;void error(const wchar_t*){}void enqueue(Kind,const std::string&){++submitted;}
void run(int change){'''+prefix+'''struct {bool accepted=true;std::wstring value=L"folder";}d;
switch(change){case 1:current.central_user_id="other";break;case 2:current.sandbox_id="other";break;case 3:current.node_id="other";break;case 4:directory="other";break;case 5:++epoch;break;}
'''+suffix+'''}};
int main(){for(int i=0;i<6;++i){Panel p;p.run(i);check(p.submitted==(i==0?1:0),"modal ownership changed but mkdir submitted");}return failures?1:0;}
'''
logout_sig = 'void FilePanel::request_logout()' if 'void FilePanel::request_logout()' in s else 'void FilePanel::logout()'
logout_body = block(logout_sig).split('{',1)[1].rsplit('}',1)[0]
logout = common + r'''
void ListView_DeleteAllItems(HWND){} void TreeView_DeleteAllItems(HWND){} void SetWindowTextW(HWND,const wchar_t*){}
struct Impl{unsigned long epoch=1;int joins=0;Context current;std::string directory="d";std::vector<int> entries,visible,taskrows;std::vector<std::shared_ptr<Job>> jobs;std::shared_ptr<Job> listing;HWND list=0,tasklist=0,tree=0,subtitle=0,crumb=0,filter=0,note=0;void stop(){++joins;}};
struct FilePanel{std::unique_ptr<Impl> impl_=std::make_unique<Impl>();void hide(){}void run(){
''' + logout_body + r'''}};
int main(){FilePanel p;p.impl_->current.central_user_id="u";auto j=std::make_shared<Job>(panel_detail::Scope{"u","s","n","d",1},Kind::Upload,p.impl_->current);p.impl_->jobs.push_back(j);auto original=j->context.central_user_id;p.run();check(p.impl_->joins==0,"request logout joined worker");check(p.impl_->epoch!=j->scope.epoch&&p.impl_->current.central_user_id.empty(),"late publish not fenced");check(j->cancel,"running job not cancelled");check(j->context.central_user_id==original,"running context scrubbed");return failures?1:0;}
'''
# Old logout uses fields absent from the simplified job only for completed scrubbing.
logout = logout.replace('j->client.reset();', '').replace('j->entries.clear();', '')
modal = common + 'struct Panel{'+block('  struct ModalOwner')+''';};
int main(){for(int prior=0;prior<2;++prior)for(int fault=0;fault<2;++fault){enabled=prior;destroyed=0;try{Panel::ModalOwner m(1,2);check(!enabled,"modal parent not disabled");if(fault)throw std::bad_alloc();}catch(...){}check(enabled==bool(prior)&&destroyed==1,"modal owner not restored on exit");}return failures?1:0;}
'''
results=[]
for name, source in [('admission',code),('callback',callback),('dialog_fence',fence),('request_logout',logout),('modal_owner',modal)]:
    f=OUT/(name+'.cpp');f.write_text(source)
    build=subprocess.run(['g++','-std=c++20','-Wall','-Wextra','-Werror',str(f),'-o',str(OUT/name)],capture_output=True,text=True)
    if build.returncode: print(build.stderr);sys.exit(2)
    run=subprocess.run([str(OUT/name)],capture_output=True,text=True)
    print(name, 'PASS' if run.returncode==0 else 'FAIL',run.stdout.strip());results.append(run.returncode)
sys.exit(1 if any(results) else 0)
