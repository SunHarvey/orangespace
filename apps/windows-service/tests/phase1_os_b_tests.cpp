#include "phase1_os_b_policy.hpp"
#include <iostream>
#include <stdexcept>
using namespace phase1_os_b;
std::size_t checks=0;
void check(bool b,const char* s){++checks;if(!b)throw std::runtime_error(s);}
int main(){try{
 check(!pipe_denied(231,true),"busy is not denial");
 check(!pipe_denied(2,true),"missing is not denial");
 check(!pipe_denied(5,false),"listener prerequisite mandatory");
 check(pipe_denied(5,true),"actual access denied on ready listener accepted");
 std::array<std::string_view,field_count> fields{}; fields.fill("x");
 auto packet=encode(fields); auto parsed=decode(packet);
 check(parsed[0]=="x" && parsed[field_count-1]=="x","typed frame roundtrip");
 auto bad=packet; bad.push_back('x');
 bool failed=false;try{(void)decode(bad);}catch(...){failed=true;}
 check(failed,"trailing bytes rejected");
 for(std::size_t n=0;n<packet.size();++n){failed=false;try{(void)decode(std::string_view(packet).substr(0,n));}catch(...){failed=true;}check(failed,"every truncation rejected");}
 bad=packet;bad[4]=char(255);bad[5]=char(255);bad[6]=char(255);bad[7]=char(255);
 failed=false;try{(void)decode(bad);}catch(...){failed=true;}check(failed,"oversize field rejected before allocation");
 struct Ops{std::string calls;char fail=0;bool step(char c){calls+=c;return c!=fail;}
 bool reap(){return step('R');}bool unload(){return step('U');}bool erase_profile(){return step('P');}bool profile_absent(){return step('V');}bool no_profile(){return step('N');}
 bool account_matches(){return step('M');}bool erase_account(){return step('A');}bool account_absent(){return step('Z');}};
 CleanupFacts facts{true,true,true,true,true,ProfileState::owned_loaded};Ops ops;
 check(cleanup(facts,ops)&&ops.calls=="RUPVMAZ","ordered cleanup");
 for(char c:std::string("RUPVMAZ")){Ops fault;fault.fail=c;check(!cleanup(facts,fault),"cleanup failure propagates");check(fault.calls.back()==c,"cleanup stops at failed dependency");}
 Ops mismatch;auto unknown=facts;unknown.sid_owned=false;check(!cleanup(unknown,mismatch)&&mismatch.calls=="R","unknown SID preserves account/profile after reaping");
 std::array<std::string_view,field_count> valid={"a","b","11111111-1111-4111-8111-111111111111","C:\\Users\\A\\AppData\\Local\\OrangeSpace-Credentials-v1\\11111111-1111-4111-8111-111111111111.dpapi","cipher","22222222-2222-4222-8222-222222222222","33333333-3333-4333-8333-333333333333","1","apiuser","apipassword","S-1-5-21-1-2-3-1001","20","2","456"};
 check(valid_fields(valid),"valid typed input");
 for(auto i:{0u,1u,2u,3u,4u,5u,6u,7u,8u,9u,10u,11u,12u,13u}){auto v=valid;v[i]="";check(!valid_fields(v),"required typed field");}
 for(auto s:{"0","-1","18446744073709551616","1x"}){auto v=valid;v[7]=s;check(!valid_fields(v),"generation bounds");}
 auto v=valid;v[1]=v[0];check(!valid_fields(v),"aliases distinct");v=valid;v[12]="0";check(!valid_fields(v),"session zero rejected");
 auto invalid_uuid=valid;invalid_uuid[5]="00000000-0000-0000-0000-000000000000";check(!valid_fields(invalid_uuid),"nil learned authorization rejected");
 Observations observed{};check(!observed.complete(),"default result never succeeds");
 for(auto& b:observed.flags)b=true;
 check(observed.complete(),"all observations required");
 auto reply=observed.encode();check(Observations::decode(reply).complete(),"typed booleans roundtrip");
 reply.back()='x';failed=false;try{(void)Observations::decode(reply);}catch(...){failed=true;}check(failed,"untyped result rejected");
 AuditSequence sequence;check(!sequence.raw_begin(),"raw cannot skip before-copy audit");
 check(sequence.copy_begin()&&!sequence.copy_begin(),"copy audit exactly once");check(!sequence.complete_allowed(),"copy audit alone cannot complete");
 check(sequence.raw_begin()&&!sequence.raw_begin()&&sequence.complete_allowed(),"raw audit follows copy exactly once");
 std::cout<<"policy framing cleanup typed-input result audit-sequence passed; checks="<<checks<<"\n";
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
