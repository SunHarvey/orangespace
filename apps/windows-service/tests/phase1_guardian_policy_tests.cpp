#include "phase1_guardian_policy.hpp"
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
using namespace phase1_guardian;
void require(bool v,const char* s){if(!v)throw std::runtime_error(s);}
struct Forced : Adapter {
 std::vector<Status> sequence{{State::start_pending,71},{State::stop_pending,71},{State::stopped,0}};
 unsigned tick=0; bool held=false,dead=false,attempted=true; std::vector<std::string> trace;
 Status query() override {return sequence[tick<sequence.size()?tick:sequence.size()-1];}
 bool capture(std::uint32_t p) override {trace.push_back("capture");held=p==71;return held;}
 bool has_root()const override{return held;}
 bool start_attempted()const override{return attempted;}
 bool valid_root()override{return held;}
 bool root_exited()override{return dead;}
 unsigned helpers()const override{return 0;}
 bool valid_helper(unsigned)override{return false;}
 bool helper_exited(unsigned)override{return false;}
 bool before(Action,unsigned)override{trace.push_back("journal");return true;}
 bool stop()override{trace.push_back("stop");return true;}
 bool terminate_root()override{trace.push_back("terminate");dead=true;return true;}
 bool terminate_helper(unsigned)override{return false;}
 bool remove_and_verify_absence()override{trace.push_back("delete");return dead||!attempted;}
 void pause()override{++tick;}
 bool record(Code)override{return true;}
};
struct Unknown : Forced {
 Unknown(){sequence={{State::start_pending,0},{State::stop_pending,0},{State::stopped,0}};}
};
struct Failures : Forced {
 unsigned helper_kills=0; bool helper_dead=false;
 Status query()override{throw std::runtime_error("inspection fault");}
 unsigned helpers()const override{return 2;}
 bool helper_exited(unsigned i)override{return i==1&&helper_dead;}
 bool valid_helper(unsigned)override{return true;}
 bool terminate_helper(unsigned i)override{++helper_kills;if(i==0)throw std::runtime_error("first helper fault");helper_dead=true;return true;}
 bool record(Code)override{throw std::runtime_error("report fault");}
};
struct LostJournal : Forced {bool before(Action,unsigned)override{return false;}};
struct IndependentClaim : Forced {
 IndependentClaim(){sequence={{State::start_pending,0},{State::stop_pending,0},{State::stopped,0}};}
 bool capture(std::uint32_t)override{trace.push_back("claim");held=true;return true;}
};
int main(){try{
 Forced a;auto r=cleanup(a,3);require(a.held,"pending PID must be captured without waiting for RUNNING");require(a.dead,"SCM STOPPED is not process exit");require(r.removed,"actual exit must precede delete/readback");
 Unknown u;auto ur=cleanup(u,3);require(!ur.removed&&!u.held,"PID zero cannot mean absent after start");require(std::find(u.trace.begin(),u.trace.end(),"terminate")==u.trace.end()&&std::find(u.trace.begin(),u.trace.end(),"delete")==u.trace.end(),"unknown root must not be killed/deleted");
 Failures f;auto fr=cleanup(f,2);require(f.helper_kills==2&&f.helper_dead,"inspection/report/first helper failure must not suppress other owned helper");require(!fr.removed&&!fr.errors.empty(),"UNKNOWN must be reported, not absence");
 LostJournal j;auto jr=cleanup(j,2);require(!jr.removed&&!j.dead,"no risky action without protected prewrite");
 Forced s;s.sequence={{State::running,71},{State::stop_pending,71},{State::stopped,0}};require(cleanup(s,3).removed,"running to stop_pending cleanup");require(s.trace[0]=="capture"&&s.trace[1]=="journal"&&s.trace[2]=="stop","write-ahead before stop");
 IndependentClaim claim;require(cleanup(claim,3).removed&&claim.held,"independent self-claim must capture actual root even when pending SCM PID is zero");
 Forced restart;auto rr=cleanup(restart,3,false);require(rr.quiesced&&!rr.removed,"restart quiesce must retain registration and first-provision ledger");
 std::cout<<"7 portable forced-sequence cases GREEN; native_scm_evidence=false\n";
 }catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}
