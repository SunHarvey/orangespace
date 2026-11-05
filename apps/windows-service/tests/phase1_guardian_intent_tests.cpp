#include "phase1_guardian_policy.hpp"
#include <iostream>
#include <stdexcept>
using namespace phase1_guardian;
void require(bool x,const char*s){if(!x)throw std::runtime_error(s);}
int main(){try{
 IntentSet p;unsigned writes=0;
 p.prepare(true,3,[&](Action,unsigned){++writes;return true;});
 require(writes==5&&p.permits(Action::terminate_root)&&p.permits(Action::terminate_helper,0)&&p.permits(Action::terminate_helper,1)&&p.permits(Action::stop)&&p.permits(Action::remove),"all exact owned cleanup intents must be durable before the first risk");
 p.prepare(true,3,[&](Action,unsigned)->bool{throw std::runtime_error("disk/report fault after first effect");});
 require(p.permits(Action::terminate_helper,1)&&writes==5,"subsequent journal failure cannot revoke previously durable exact cleanup intent");
 IntentSet partial;unsigned attempts=0;
 partial.prepare(true,3,[&](Action a,unsigned i){++attempts;if(a==Action::terminate_helper&&i==0)throw std::runtime_error("one intent failure");return true;});
 require(attempts==5&&!partial.permits(Action::terminate_helper,0)&&partial.permits(Action::terminate_helper,1),"failed intent is isolated but cannot authorize its own mutation");
 require(!partial.permits(Action::terminate_helper,2),"unknown helper index has no authority");
 std::cout<<"writeahead intent/failure isolation GREEN; native_disk_evidence=false\n";
}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}
