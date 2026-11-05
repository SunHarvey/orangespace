#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <string_view>
namespace orangespace::prototype {
inline constexpr wchar_t kPipe[]=LR"(\\.\pipe\OrangeSpace.SinglePrototype.SG.v25.Admission.v1)";
inline constexpr wchar_t kService[]=L"OrangeSpaceSinglePrototype.SG.v25";
inline constexpr std::uint32_t kMagic=0x3150534f;
inline constexpr std::uint32_t kVersion=2;
// Each bit is a server-side OS/readback proof, never a caller readiness flag:
// caller token/session; exact process object; protected EXE+runtime tree;
// single root no-breakaway Job; persistent IPv4/6 TCP/UDP/loopback deny;
// DNS delegation containment native proof; SCM instance; live revocation owner.
inline constexpr std::uint32_t kRequiredEvidence=0x1ff;
inline constexpr char kOfflineUrl[]="data:text/html,%3Cmeta%20http-equiv%3D%22Content-Security-Policy%22%20content%3D%22default-src%20%27none%27%3B%20base-uri%20%27none%27%3B%20form-action%20%27none%27%22%3E%3Ctitle%3EOrangeSpace%20offline%3C%2Ftitle%3E%3Ch1%3EOrangeSpace%3C%2Fh1%3E%3Cp%3EOffline%20prototype%20-%20network%20disabled%3C%2Fp%3E";
#pragma pack(push,1)
struct Request {
  std::uint32_t magic=kMagic, version=kVersion, size=sizeof(Request), reserved=0;
  std::uint32_t pid=0, session=0;
  std::uint64_t created=0;
  std::array<std::uint8_t,32> nonce{};
};
struct Reply {
  std::uint32_t magic=0, version=0, size=0, status=0;
  std::uint32_t pid=0, session=0;
  std::uint64_t created=0;
  std::array<std::uint8_t,32> nonce{};
  std::uint32_t server_pid=0, root_pid=0;
  std::uint64_t server_created=0, root_created=0, generation=0, rules_epoch=0;
  std::array<std::uint8_t,16> job_cookie{};
  std::array<std::uint8_t,32> rules_digest{};
  std::uint32_t evidence=0, reserved=0;
};
#pragma pack(pop)
static_assert(sizeof(Request)==64 && sizeof(Reply)==160);
template<std::size_t N> inline bool Nonzero(const std::array<std::uint8_t,N>& a) {
  for(auto b:a) if(b) return true;
  return false;
}
inline bool ValidProvisionalReply(const Reply& r,const Request& q,std::uint32_t server,std::uint64_t birth) {
  return r.magic==kMagic && r.version==kVersion && r.size==sizeof(Reply) && r.status==1 &&
    !r.reserved && r.pid==q.pid && r.session==q.session && r.created==q.created &&
    r.nonce==q.nonce && Nonzero(q.nonce) && r.server_pid==server &&
    r.server_created==birth && r.root_pid && r.root_created && r.generation &&
    r.rules_epoch && Nonzero(r.job_cookie) && Nonzero(r.rules_digest) &&
    r.evidence==kRequiredEvidence;
}
// COMMITTED is a second complete Reply frame, never an evidence/readiness bit.
// Only the authenticated Service may send status 2, after post-ACK commit.
inline bool ValidReply(const Reply& provisional,const Request& q,std::uint32_t server,
                       std::uint64_t birth,const Reply* committed=nullptr) {
  if(!committed || !ValidProvisionalReply(provisional,q,server,birth) || committed->status!=2) return false;
  Reply exact=*committed; exact.status=1;
  return ValidProvisionalReply(exact,q,server,birth) &&
    std::memcmp(&exact,&provisional,sizeof(Reply))==0;
}
inline bool AllowedNavigation(std::string_view url) { return url==kOfflineUrl; }
}
