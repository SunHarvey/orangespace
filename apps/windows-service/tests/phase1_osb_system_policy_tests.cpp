#include "phase1_osb_system_policy.hpp"
#include <cassert>
#include <string>
#include <vector>
struct Fake {
 std::vector<std::string> calls; std::string fail; bool cleaned=false;
 bool step(const char* s){calls.push_back(s);return fail!=s;}
 bool authority(){return step("authority");} bool protect(){return step("protect");}
 bool receipt(){return step("receipt");} bool token(){return step("token");}
 bool atomic_create(){return step("atomic_create");} bool child_identity(){return step("child_identity");}
 bool resume_wait(){return step("resume_wait");} bool cleanup(){cleaned=true;return step("cleanup");}
};
int main(){
 using namespace osbs;
 Fake ok; assert(admit(ok)); assert(ok.cleaned); assert(ok.calls.size()==8);
 for(auto stage:{"authority","protect","receipt","token","atomic_create","child_identity","resume_wait","cleanup"}) {
  Fake f; f.fail=stage; assert(!admit(f)); assert(f.cleaned);
  if(std::string(stage)=="authority") assert(f.calls.size()==2);
 }
 assert(valid_nonce("0123456789abcdef01234567"));
 assert(!valid_nonce("../0123456789abcdef012345"));
 assert(!valid_nonce("0123456789abcdef0123456G"));
 assert(!valid_nonce("0123456789abcdef012345678"));
 assert(admission_identity("S-1-5-21-1-2-3-1001","S-1-5-21-1-2-3-1001",2,true));
 assert(!admission_identity("S-1-5-18","S-1-5-18",2,true));
 assert(!admission_identity("a","b",2,true));
 assert(!admission_identity("S-1-5-21-1-2-3-1001","S-1-5-21-1-2-3-1001",1,true));
 assert(!admission_identity("S-1-5-21-1-2-3-1001","S-1-5-21-1-2-3-1001",2,false));
 assert(trusted_owner("S-1-5-18",false));
 assert(trusted_owner("S-1-5-32-544",false));
 const std::string ti="S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
 assert(trusted_owner(ti,true));assert(!trusted_owner(ti,false));
 assert(!trusted_owner("S-1-5-21-1-2-3-1001",true));
 assert(acl_ace_safe(0,0,0x120089,"S-1-1-0"));
 assert(!acl_ace_safe(0,0,2,"S-1-1-0")); // FILE_WRITE_DATA
 assert(!acl_ace_safe(0,0,0x10000000,"S-1-1-0")); // GENERIC_ALL
 assert(!acl_ace_safe(0,0,0x40,"S-1-1-0")); // DELETE_CHILD
 assert(acl_ace_safe(0,8,2,"S-1-1-0")); // inherit only
 assert(acl_ace_safe(0,0,0x1f01ff,"S-1-5-18"));
 assert(!acl_ace_safe(5,0,0,"S-1-5-18")); // unsupported object ACE
 assert(child_proof(true,true,true,63));
 assert(!child_proof(false,true,true,63));
 assert(!child_proof(true,false,true,63));
 assert(!child_proof(true,true,false,63));
 assert(!child_proof(true,true,true,0));
 Plan plan{};std::string nonce="0123456789abcdef01234567",sid="S-1-5-21-1-2-3-1001",hash(64,'a');
 std::string text=nonce+"\n"+sid+"\n2\n"+hash+"\n";
 assert(parse_plan(text,nonce,plan));assert(plan.sid==sid&&plan.worker_hash==hash);
 assert(!parse_plan(text+"extra\n",nonce,plan));
 assert(!parse_plan(text,"ffffffffffffffffffffffff",plan));
 assert(!parse_plan(nonce+"\nS-1-5-18\n2\n"+hash+"\n",nonce,plan));
 assert(!parse_plan(nonce+"\n"+sid+"\n3\n"+hash+"\n",nonce,plan));
 assert(!parse_plan(nonce+"\n"+sid+"\n2\n"+std::string(64,'g')+"\n",nonce,plan));
}
