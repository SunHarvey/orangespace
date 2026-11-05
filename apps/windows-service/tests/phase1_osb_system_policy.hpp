#pragma once
#include <string>
#include <sstream>
namespace osbs {
inline bool trusted_owner(const std::string& s,bool ancestor){
 return s=="S-1-5-18"||s=="S-1-5-32-544"||(ancestor&&s=="S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
}
inline bool acl_ace_safe(unsigned type,unsigned flags,unsigned mask,const std::string& trustee){
 if(flags&8)return true;
 if(type==1)return true;
 if(type!=0)return false;
 constexpr unsigned writes=2|4|16|256|64|0x10000|0x40000|0x80000|0x40000000|0x10000000|0x02000000;
 return !(mask&writes)||trusted_owner(trustee,false);
}
inline bool valid_nonce(const std::string& n) {
 if(n.size()!=24) return false;
 for(char c:n) if(!((c>='0'&&c<='9')||(c>='a'&&c<='f'))) return false;
 return true;
}
inline bool admission_identity(const std::string& actual,const std::string& approved,unsigned session,bool limited) {
 return actual.rfind("S-1-5-21-",0)==0 && actual==approved && session==2 && limited;
}
struct Plan {std::string sid,worker_hash;};
inline bool parse_plan(const std::string& text,const std::string& expected_nonce,Plan& out){
 if(text.empty()||text.size()>1024||text.back()!='\n')return false;
 std::istringstream in(text);std::string nonce,sid,session,hash,extra;
 if(!std::getline(in,nonce)||!std::getline(in,sid)||!std::getline(in,session)||!std::getline(in,hash)||std::getline(in,extra))return false;
 if(!valid_nonce(nonce)||nonce!=expected_nonce||session!="2"||sid.rfind("S-1-5-21-",0)!=0||hash.size()!=64)return false;
 for(char c:hash)if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return false;
 std::istringstream parts(sid.substr(9));std::string part;unsigned count=0;
 while(std::getline(parts,part,'-')){if(part.empty()||part.size()>10)return false;unsigned long long v=0;for(char c:part){if(c<'0'||c>'9')return false;v=v*10+unsigned(c-'0');}if(v>4294967295ULL)return false;++count;}
 if(count!=4||sid.back()=='-')return false;
 out={sid,hash};return true;
}
inline bool child_proof(bool exact_object,bool actual_identity,bool job_member,unsigned exit_code){
 return exact_object&&actual_identity&&job_member&&exit_code==63;
}
template<class A> bool admit(A& a) {
 bool result=a.authority() && a.protect() && a.receipt() && a.token() && a.atomic_create() && a.child_identity() && a.resume_wait();
 bool clean=a.cleanup(); return result && clean;
}
}
