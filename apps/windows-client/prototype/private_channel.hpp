#pragma once
#include "admission_protocol.hpp"
#include <type_traits>
#include <string>
#include <mutex>
#include <functional>
namespace orangespace::prototype {
// Fixed x64/LE prototype-private wire. No padding, unchecked tails or heap buffers.
#pragma pack(push,1)
struct PrivateOffer {
 std::uint32_t magic=0x32564350,version=2,size=sizeof(PrivateOffer),phase=1;
 Reply base{};std::array<std::uint8_t,32> nonce{};
 std::array<char,36> user{},sandbox{},node{},tunnel{};
 std::uint64_t generation{};
 std::int64_t expiry{},binding_deadline{},started{},ttl{},deadline{},proof{};
 std::uint16_t port{},username_size{},password_size{};
 std::array<char,255> username{},password{};
};
struct PrivateReceipt {
 std::uint32_t magic=0x32524350,version=2,size=sizeof(PrivateReceipt),phase=2;
 Reply base{};std::array<std::uint8_t,32> nonce{},digest{};
};
struct BrowserFrame {
 std::uint32_t magic=0x3357424f,version=3,size=sizeof(BrowserFrame),command=0;
 std::uint64_t sequence=0;
 std::uint32_t phase=2,url_size=0,title_size=0;
 std::uint8_t loading=0,back=0,forward=0;
 std::array<char,2048> url{};
 std::array<char,512> title{};
};
#pragma pack(pop)
inline bool OnlineNavigation(std::string_view url){
 if(url.size()>2048 || !(url.starts_with("https://")||url.starts_with("http://")))return false;
 const auto host=url.find("://")+3;if(host>=url.size()||url[host]=='/'||url[host]=='\\')return false;
 for(unsigned char c:url)if(c<32||c==127)return false;
 return true;
}
inline bool ValidBrowserFrame(const BrowserFrame& f){
 if(f.magic!=0x3357424f||f.version!=3||f.size!=sizeof(f)||f.command>5||f.phase>4||f.url_size>f.url.size()||f.title_size>f.title.size()||f.loading>1||f.back>1||f.forward>1)return false;
 for(std::size_t i=0;i<f.url.size();++i)if(i<f.url_size ? (static_cast<unsigned char>(f.url[i])<32||f.url[i]==127) : f.url[i]!=0)return false;
 for(std::size_t i=f.title_size;i<f.title.size();++i)if(f.title[i])return false;
 return f.command!=1||OnlineNavigation({f.url.data(),f.url_size});
}
static_assert(sizeof(BrowserFrame)<4096&&std::is_trivially_copyable_v<BrowserFrame>);
static_assert(sizeof(PrivateOffer)<=4096 && std::is_trivially_copyable_v<PrivateOffer>);
inline void PrivateWipe(void* ptr,std::size_t n) noexcept {auto* p=static_cast<volatile unsigned char*>(ptr);while(n--)*p++=0;}
struct PrivateOwner final {
 PrivateOffer offer{};
 mutable std::mutex browser_mutex;
 mutable BrowserFrame browser_state;
 mutable std::function<void(BrowserFrame)> browser_command;
 BrowserFrame exchange(BrowserFrame command) const {
  std::lock_guard lock(browser_mutex);
  if(browser_command && command.command)browser_command(command);
  auto out=browser_state;out.sequence=command.sequence;out.command=0;return out;
 }
 PrivateOwner()=default;PrivateOwner(const PrivateOwner&)=delete;PrivateOwner& operator=(const PrivateOwner&)=delete;
 ~PrivateOwner(){PrivateWipe(&offer,sizeof(offer));}
};
inline bool CanonicalUuid(const std::array<char,36>& v){for(std::size_t i=0;i<v.size();++i){if(i==8||i==13||i==18||i==23){if(v[i]!='-')return false;}else if(!((v[i]>='0'&&v[i]<='9')||(v[i]>='a'&&v[i]<='f')))return false;}return true;}
inline bool PrivateSecret(const std::array<char,255>& s,std::uint16_t n){if(n<16||n>s.size())return false;for(std::size_t i=0;i<s.size();i++){if(i<n){if(s[i]<33||s[i]>126)return false;}else if(s[i])return false;}return true;}
inline bool ValidPrivateOffer(const PrivateOffer& o,const Reply& base,std::int64_t now){
 return o.magic==0x32564350&&o.version==2&&o.size==sizeof(o)&&o.phase==1&&base.status==2&&base.pid==base.root_pid&&base.created==base.root_created&&
 !std::memcmp(&o.base,&base,sizeof(base))&&Nonzero(o.nonce)&&CanonicalUuid(o.user)&&CanonicalUuid(o.sandbox)&&CanonicalUuid(o.node)&&CanonicalUuid(o.tunnel)&&o.generation&&o.expiry>0&&o.binding_deadline>=o.deadline&&o.port&&
 o.started>=0&&o.ttl>0&&o.ttl<=30000&&o.started<=INT64_MAX-o.ttl&&o.deadline==o.started+o.ttl&&now>=o.started&&now<o.deadline&&o.proof>=o.started&&o.proof<=now&&now-o.proof<3000&&PrivateSecret(o.username,o.username_size)&&PrivateSecret(o.password,o.password_size);
}
inline bool ValidPrivateReceipt(const PrivateReceipt& expected,const PrivateReceipt& actual,std::uint32_t phase){auto copy=actual;copy.phase=expected.phase;return actual.phase==phase&&expected.magic==0x32524350&&expected.version==2&&expected.size==sizeof(expected)&&Nonzero(expected.digest)&&!std::memcmp(&expected,&copy,sizeof(copy));}
inline bool ProxyChallenge(bool isProxy,std::string_view host,int port,std::string_view scheme,std::uint16_t owned){return isProxy&&host=="127.0.0.1"&&port==owned&&owned&&scheme=="basic";}
}
