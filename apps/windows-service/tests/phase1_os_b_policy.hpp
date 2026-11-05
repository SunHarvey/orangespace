#pragma once
#include <cstdint>
#include <array>
#include <string>
#include <string_view>
#include <stdexcept>
#include <atomic>
#include <memory>
namespace phase1_os_b {
inline constexpr std::size_t field_count=14, max_frame=98304;
using Fields=std::array<std::string_view,field_count>;
inline void require(bool ok){if(!ok)throw std::runtime_error("os_b contract rejected");}
inline void put32(std::string& out,std::uint32_t n){for(unsigned i=0;i<4;++i)out.push_back(char(n>>(i*8)));}
inline std::uint32_t get32(std::string_view s,std::size_t& pos){
 require(pos<=s.size()&&s.size()-pos>=4);std::uint32_t n=0;
 for(unsigned i=0;i<4;++i)n|=std::uint32_t(static_cast<unsigned char>(s[pos++]))<<(i*8);
 return n;
}
// Body only: the transport adds a uint32 LE body length. Views borrow the wiped body.
inline std::string encode(const Fields& fields){
 std::size_t total=4+field_count*4;for(auto s:fields){require(!s.empty()&&s.size()<=65536);total+=s.size();}require(total<=max_frame);
 std::string out;out.reserve(total);out="OSB1";for(auto s:fields){put32(out,static_cast<std::uint32_t>(s.size()));out.append(s);}return out;
}
inline Fields decode(std::string_view s){
 require(s.size()<=max_frame && s.starts_with("OSB1"));std::size_t p=4;Fields out;
 for(auto& f:out){auto n=get32(s,p);require(n>0&&n<=65536&&n<=s.size()-p);f=s.substr(p,n);p+=n;}
 require(p==s.size());return out;
}
// Shared capture-positive protocol; callbacks are test-only orchestration seams.
inline std::string capture_entropy(std::string_view sid,std::string_view node,std::string_view origin){
 std::string out="OrangeSpace/CredentialStore/v1/api-session";
 for(auto part:{sid,node,origin}){out.push_back('\0');out+=part;}return out;
}
template<class StorePositive,class BufferPositive>
void capture_positive(std::string_view cipher,StorePositive&& store,BufferPositive&& exact){
 store();exact(cipher);
}
enum class CancelOutcome { completed,retained };
template<class Operation> CancelOutcome cancel_pending(Operation& op){
 op.cancel();op.wait_cancel(50);
 return op.completed()?CancelOutcome::completed:CancelOutcome::retained;
}
// One process-wide outstanding operation. Reserve BEFORE issuing kernel I/O.
// A retained operation permanently poisons admission, even if later reaped.
// Raw retained pointer deliberately has no static-destruction delete: OS process
// teardown is the final boundary if native completion is never observed.
template<class Operation> struct IoBudget {
 std::atomic<bool> busy{false},poisoned{false};std::atomic<Operation*> retained{nullptr};std::atomic_flag reaping=ATOMIC_FLAG_INIT;
 bool reserve()noexcept{if(poisoned.load())return false;bool expected=false;return busy.compare_exchange_strong(expected,true);}
 void release()noexcept{busy.store(false);}
 void quarantine(std::unique_ptr<Operation> op)noexcept{poisoned.store(true);retained.store(op.release());}
 bool has_retained()const noexcept{return retained.load()!=nullptr;}
 bool reap_retained()noexcept{
  if(reaping.test_and_set())return false;
  auto* op=retained.load();bool done=!op||op->completed();
  if(done&&op){delete op;retained.store(nullptr);}reaping.clear();return done;
 }
};
inline std::uint32_t remaining_ms(std::uint64_t now,std::uint64_t deadline){
 if(now>=deadline)return 0;
 const auto left=deadline-now;return left>=UINT32_MAX?UINT32_MAX-1:static_cast<std::uint32_t>(left);
}
struct IoProgress {
 std::uint32_t total,done=0;std::uint64_t deadline;
 IoProgress(std::uint32_t n,std::uint64_t end):total(n),deadline(end){require(n>0&&n<=max_frame+4);}
 bool complete()const noexcept{return done==total;}
 std::uint32_t left()const noexcept{return total-done;}
 std::uint32_t remaining(std::uint64_t now)const{return remaining_ms(now,deadline);}
 bool advance(std::uint32_t n)noexcept{if(!n||n>left())return false;done+=n;return true;}
};
enum class Presence { absent,present,unknown };
enum class ProfileState { unknown,unexpected_present,verified_no_profile,attempted,owned_loaded,owned_removed };
inline ProfileState profile_probe(Presence list,Presence hive){
 if(list==Presence::present||hive==Presence::present)return ProfileState::unexpected_present;
 if(list==Presence::unknown||hive==Presence::unknown)return ProfileState::unknown;
 return ProfileState::verified_no_profile;
}
struct CleanupFacts {bool account_created,sid_owned,profile_attempted,profile_loaded,profile_path_owned;ProfileState profile_state=ProfileState::unknown;};
template<class Ops> bool cleanup(CleanupFacts f,Ops& ops){
 if(!ops.reap())return false;
 if(!f.account_created)return true;
 if(!f.sid_owned)return false;
 switch(f.profile_state){
 case ProfileState::verified_no_profile:
  if(f.profile_attempted||!ops.no_profile())return false;
  break;
 case ProfileState::owned_loaded:
  if(!f.profile_attempted||!f.profile_loaded||!f.profile_path_owned)return false;
  if(!ops.unload()||!ops.erase_profile()||!ops.profile_absent())return false;
  break;
 case ProfileState::owned_removed:
  if(!f.profile_path_owned||!ops.profile_absent())return false;
  break;
 default:return false; // Unknown/preexisting/attempted is a recovery gate.
 }
 return ops.account_matches() && ops.erase_account() && ops.account_absent();
}
// Fixed order, versioned; no caller-selected store path or entropy override.
enum Field : std::size_t {alias_a,alias_b,node_a,original_a,cipher_a,auth_a,sandbox_a,generation_a,username_b,password_b,sid_a,luid_a,session_id,service_pid};
inline bool decimal(std::string_view s,std::uint64_t& out){
 if(s.empty()||s.size()>20)return false;
 out=0;
 for(char c:s){if(c<'0'||c>'9'||out>(UINT64_MAX-std::uint64_t(c-'0'))/10)return false;out=out*10+std::uint64_t(c-'0');}return out>0;
}
inline bool valid_fields(const Fields& f){
 auto alias=[](std::string_view s){if(s.empty()||s.size()>64)return false;for(char c:s)if(!((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-'||c=='_'))return false;return true;};
 auto uuid=[](std::string_view s){if(s.size()!=36||s=="00000000-0000-0000-0000-000000000000")return false;for(std::size_t i=0;i<s.size();++i){if(i==8||i==13||i==18||i==23){if(s[i]!='-')return false;}else if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return false;}return true;};
 for(auto s:f)if(s.empty()||s.size()>65536)return false;
 if(!alias(f[alias_a])||!alias(f[alias_b])||f[alias_a]==f[alias_b]||!uuid(f[node_a])||!uuid(f[auth_a])||!uuid(f[sandbox_a]))return false;
 if(f[original_a].size()>960||f[original_a].find('\0')!=std::string_view::npos||f[username_b].size()>256||f[password_b].size()>256)return false;
 for(auto i:{username_b,password_b})for(unsigned char c:f[i])if(c<32||c==127)return false;
 if(!f[sid_a].starts_with("S-1-")||f[sid_a].size()>184)return false;
 for(char c:f[sid_a])if((c<'0'||c>'9')&&c!='S'&&c!='-')return false;
 std::uint64_t n=0;if(!decimal(f[generation_a],n)||!decimal(f[luid_a],n)||!decimal(f[service_pid],n)||n>UINT32_MAX)return false;
 return f[session_id]=="2";
}
enum Observation : std::size_t {not_admin,same_session,different_sid,different_luid,profile_loaded,real_login,store_roundtrip,a_load_rejected,a_copy_purged,a_acl_denied,listener_ready,raw_osp2_denied,store_clean};
struct Observations{
 std::array<bool,13> flags{};
 bool complete()const{for(bool b:flags)if(!b)return false;return true;}
 std::string encode()const{std::string out="OSBR1";for(bool b:flags)out.push_back(b?'1':'0');return out;}
 static Observations decode(std::string_view s){require(s.size()==18&&s.starts_with("OSBR1"));Observations out;for(std::size_t i=0;i<13;++i){require(s[5+i]=='0'||s[5+i]=='1');out.flags[i]=s[5+i]=='1';}return out;}
};
struct AuditSequence {
 unsigned state=0;
 bool copy_begin(){if(state!=0)return false;state=1;return true;}
 bool raw_begin(){if(state!=1)return false;state=2;return true;}
 bool complete_allowed()const{return state==2;}
};
inline bool pipe_denied(std::uint32_t error,bool listener_ready){return error==5 && listener_ready;}
}
