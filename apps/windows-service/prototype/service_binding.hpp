#pragma once
#include "../../windows-client/prototype/admission_protocol.hpp"
#include <vector>
namespace orangespace::prototype {
inline bool TrustedAuthority(bool system_or_admin,bool trusted_installer,bool ancestor){
 return system_or_admin||(ancestor&&trusted_installer);
}
inline bool ValidRelative(std::string_view path){
 if(path.empty()||path.size()>=240||path=="runtime.inventory.tsv"||path.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./-+")!=std::string_view::npos)return false;
 for(std::size_t pos=0;pos<path.size();){auto end=path.find('/',pos);if(end==std::string_view::npos)end=path.size();auto c=path.substr(pos,end-pos);if(c.empty()||c=="."||c==".."||c.back()=='.')return false;
 auto base=c.substr(0,c.find('.'));char upper[240]{};for(std::size_t i=0;i<base.size();i++)upper[i]=base[i]>='a'&&base[i]<='z'?char(base[i]-32):base[i];std::string_view b(upper,base.size());if(b=="CON"||b=="PRN"||b=="AUX"||b=="NUL"||(b.size()==4&&(b.substr(0,3)=="COM"||b.substr(0,3)=="LPT")&&b[3]>='0'&&b[3]<='9'))return false;
 if(end==path.size())return true;
 pos=end+1;if(pos==path.size())return false;}return false;
}
struct BoundedSnapshot {
 std::vector<std::uint8_t> bytes;
 bool put(const void* data,std::size_t n){
  if(n>65536||bytes.size()+n+4>1048576||(!data&&n))return false;
  for(unsigned shift=0;shift<32;shift+=8)bytes.push_back(std::uint8_t(n>>shift));
  if(n){auto*p=static_cast<const std::uint8_t*>(data);bytes.insert(bytes.end(),p,p+n);}return true;
 }
};
inline bool SameSnapshot(const Reply&a,const Reply&b){return a.server_pid==b.server_pid&&a.server_created==b.server_created&&a.root_pid==b.root_pid&&a.root_created==b.root_created&&a.generation==b.generation&&a.rules_epoch==b.rules_epoch&&a.job_cookie==b.job_cookie&&a.rules_digest==b.rules_digest&&a.evidence==b.evidence;}
struct Binding {std::uint32_t pid,session;std::uint64_t created;};
inline bool Matches(const Request&q,const Binding&b){return q.magic==kMagic&&q.version==kVersion&&q.size==sizeof(Request)&&!q.reserved&&q.pid==b.pid&&q.session==b.session&&q.created==b.created&&b.pid&&b.session&&b.created&&Nonzero(q.nonce);}
class Commit {
 Request offered_{};bool offered=false,done=false,failed=false;
public:
 bool offer(const Request&q,const Binding&b){if(offered||done||failed||!Matches(q,b))return false;offered_=q;offered=true;return true;}
 bool ack(unsigned char a,const Request&q,const Binding&b){if(!offered||done||failed||a!=6||!Matches(q,b)||std::memcmp(&q,&offered_,sizeof(q))){failed=true;return false;}done=true;return true;}
 bool committed()const{return done&&!failed;}
};
}
