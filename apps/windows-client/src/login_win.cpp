#include "orangespace/node_session.hpp"
#include "orangespace/credential_store.hpp"
#include "orangespace/service_client.hpp"
#include "orangespace/platform_session.hpp"
#include <optional>
#include <utility>

// PLATFORM_HTTPS_PORTABLE_BEGIN
namespace platform_diag {
namespace ps = orangespace::platform_session;
namespace nd = orangespace::node_session::detail;
struct Input {
  std::vector<char> bytes;
  Input() = default;
  Input(const Input&) = delete;
  Input(Input&& other) noexcept { bytes.swap(other.bytes); }
  ~Input() { nd::wipe(bytes.data(), bytes.size()); }
  std::string_view view() const { return {bytes.data(),bytes.size()}; }
};
template<class Read> Input line(Read read, std::size_t limit) {
  Input value; value.bytes.reserve(limit);
  struct Byte { char c{}; ~Byte(){nd::wipe(&c,1);} } byte;
  for(std::size_t n=0;n<=limit;++n) {
    nd::require(read(byte.c));
    if(byte.c=='\n') {
      nd::require(!value.bytes.empty() && nd::safe_utf8(value.view(),true));
      return value;
    }
    nd::require(n<limit && static_cast<unsigned char>(byte.c)>=32 && byte.c!=127);
    value.bytes.push_back(byte.c);
  }
  throw std::runtime_error("invalid diagnostic input");
}
template<class Config,class Caller>
std::size_t run(const Config& config,std::string_view username,std::string_view password,
                std::string_view expected,Caller caller,const char*& stage) {
  using Session=decltype(caller.login(config,username,password));
  std::optional<Session> owned;
  bool logged_out=false;
  try {
    stage="wrong-password";
    // Same byte length, valid UTF-8, provably unequal even for a one-byte secret.
    Input wrong; wrong.bytes.assign(password.size(),'x');
    if(wrong.view()==password) wrong.bytes.front()='y';
    bool rejected=false;
    try { owned.emplace(caller.login(config,username,wrong.view())); }
    catch(const ps::HttpStatusError& e) { if(e.status_code()!=401) throw; rejected=true; }
    nd::require(rejected);
    stage="login";
    owned.emplace(caller.login(config,username,password));
    stage="revalidate"; owned->revalidate();
    stage="nodes"; const auto nodes=owned->nodes();
    if(!expected.empty()) {
      bool found=false; for(const auto& node:nodes) found=found || node.node_id==expected;
      nd::require(found);
    }
    stage="export"; auto envelope=owned->export_envelope();
    stage="restore"; auto restored=caller.restore(config,envelope.view());
    const auto& a=owned->identity(); const auto& b=restored.identity();
    nd::require(a.central_user_id==b.central_user_id && a.central_session_id==b.central_session_id &&
      a.username==b.username && a.role==b.role && a.user_epoch==b.user_epoch && a.expires_at==b.expires_at);
    stage="logout"; owned->logout(); logged_out=true;
    stage="stale-restore"; rejected=false;
    try { (void)caller.restore(config,envelope.view()); }
    catch(const ps::HttpStatusError& e) { if(e.status_code()!=401) throw; rejected=true; }
    nd::require(rejected);
    return nodes.size();
  } catch(...) {
    // Only the exact session returned by our own login. Unknown logout stays failure.
    if(owned && !logged_out) { try { owned->logout(); } catch(...) {} }
    throw;
  }
}
}
// PLATFORM_HTTPS_PORTABLE_END

// PLATFORM_CHAIN_PORTABLE_BEGIN
namespace platform_chain_diag {
namespace nd = orangespace::node_session::detail;
template<class Config,class Caller>
void run(const Config& config,std::string_view username,std::string_view password,
         std::string_view expected,Caller caller,const char*& stage,bool& cleanup_complete) {
  using Session=decltype(caller.login(config,username,password));
  using Node=typename decltype(std::declval<Session&>().nodes())::value_type;
  using Grant=decltype(caller.authorize(std::declval<Session&>(),std::declval<const Node&>()));
  using Binding=decltype(caller.start(std::declval<const Grant&>(),expected));
  static_assert(std::is_nothrow_move_constructible_v<Session>);
  static_assert(std::is_nothrow_move_constructible_v<Grant>);
  static_assert(std::is_nothrow_move_constructible_v<Binding>);
  std::optional<Session> session;
  std::optional<Grant> grant;
  std::optional<Binding> a,b;
  bool central_done=false,grant_done=false;
  cleanup_complete=true;
  try {
    stage="login"; session.emplace(caller.login(config,username,password));
    stage="nodes"; const auto nodes=session->nodes();
    const Node* selected=nullptr;
    for(const auto& node:nodes) if(node.node_id==expected) {nd::require(!selected);selected=&node;}
    nd::require(selected);
    stage="authorize"; grant.emplace(caller.authorize(*session,*selected));
    stage="workspace-ids";
    // Diagnostic fresh workspaces only: no SQLite rows, UI profiles or browser.
    const auto local_a=caller.uuid(),local_b=caller.uuid();
    nd::require(nd::uuid(local_a)&&nd::uuid(local_b)&&local_a!=local_b);
    stage="start-a"; a.emplace(caller.start(*grant,local_a));
    nd::require(a->sandbox==local_a && a->user==grant->user() && a->node==expected);
    stage="start-b"; b.emplace(caller.start(*grant,local_b));
    nd::require(b->sandbox==local_b && b->user==grant->user() && b->node==expected && a->tunnel!=b->tunnel && *a!=*b);
    // The real typed start/active APIs validate all three establishment proof bits.
    stage="active-two"; auto active=caller.active(*grant);
    nd::require(active.size()==2 && ((active[0]==*a && active[1]==*b)||(active[0]==*b && active[1]==*a)));
    stage="stop-a"; caller.stop(*grant,*a); a.reset();
    stage="active-b"; active=caller.active(*grant);
    nd::require(active.size()==1 && active.front()==*b);
    // A separate fresh Service status poll, not the start-time proof or cursor.
    stage="status-b"; active=caller.active(*grant);
    nd::require(active.size()==1 && active.front()==*b);
    stage="stop-b"; caller.stop(*grant,*b); b.reset();
    stage="active-zero"; nd::require(caller.active(*grant).empty());
    stage="grant-logout"; caller.logout(*grant); grant_done=true;
    stage="central-logout"; session->logout(); central_done=true;
    stage="complete";
  } catch(...) {
    // Preserve each exact binding until confirmed stop; never inspect/stop other grants.
    // All failures remain failures even if compensating cleanup succeeds.
    if(grant && !grant_done) {
      if(a) {try {caller.stop(*grant,*a);a.reset();}catch(...) {}}
      if(b) {try {caller.stop(*grant,*b);b.reset();}catch(...) {}}
      try {caller.logout(*grant);grant_done=true;a.reset();b.reset();}catch(...) {
        // Retire is local-only; it does NOT count as successful remote logout.
        try {caller.retire(*grant);}catch(...) {}
        cleanup_complete=false;
      }
    }
    if(session && !central_done) {try {session->logout();central_done=true;}catch(...) {cleanup_complete=false;}}
    throw;
  }
}
}
// PLATFORM_CHAIN_PORTABLE_END

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#include <iostream>
#include <string>
#include <vector>

namespace ns = orangespace::node_session;
namespace {
// No secret output, environment credential input, or browser launch. Ordinary
// password login uses a console; explicit native acceptance modes read only
// bounded authenticated envelopes from a parent-owned anonymous stdin pipe.
struct Secret {
  std::vector<char> bytes;
  Secret() = default;
  Secret(const Secret&) = delete;
  Secret& operator=(const Secret&) = delete;
  Secret(Secret&&) = default;
  ~Secret() { ns::detail::wipe(bytes.data(), bytes.size()); }
  std::string_view view() const { return {bytes.data(), bytes.size()}; }
};
struct ConsoleMode {
  HANDLE handle;
  DWORD original{};
  explicit ConsoleMode(bool hidden) : handle(GetStdHandle(STD_INPUT_HANDLE)) {
    if (!GetConsoleMode(handle, &original)) throw std::runtime_error("interactive console stdin required");
    if (hidden && !SetConsoleMode(handle, (original | ENABLE_LINE_INPUT) & ~(ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT)))
      throw std::runtime_error("cannot disable password echo");
  }
  ~ConsoleMode() { SetConsoleMode(handle, original); }
};
Secret read_line(bool hidden, std::size_t limit) {
  ConsoleMode mode(hidden);
  struct WideBuffer {
    std::vector<wchar_t> data;
    ~WideBuffer() { ns::detail::wipe(data.data(), data.size() * sizeof(wchar_t)); }
  } buffer{std::vector<wchar_t>(limit + 2)};
  DWORD count = 0;
  if (!ReadConsoleW(mode.handle, buffer.data.data(), static_cast<DWORD>(buffer.data.size()), &count, nullptr))
    throw std::runtime_error("console input failed");
  if (!count || buffer.data[count - 1] != L'\n') throw std::runtime_error("input line exceeds limit");
  while (count && (buffer.data[count - 1] == L'\n' || buffer.data[count - 1] == L'\r')) --count;
  if (!count || count > limit) throw std::runtime_error("invalid input length");
  // Ctrl-C is read as input while echo is off, so normal unwinding restores the
  // console mode rather than terminating the process with echo disabled.
  for (DWORD i = 0; i < count; ++i) if (buffer.data[i] < 32) throw std::runtime_error("input cancelled or contains controls");
  const int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, buffer.data.data(), static_cast<int>(count), nullptr, 0, nullptr, nullptr);
  if (!needed) throw std::runtime_error("invalid Unicode input");
  Secret result;
  result.bytes.resize(static_cast<std::size_t>(needed));
  if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, buffer.data.data(), static_cast<int>(count), result.bytes.data(), needed, nullptr, nullptr))
    throw std::runtime_error("cannot encode console input");
  return result;
}
std::string alias(const wchar_t* arg) {
  std::string value;
  for (; *arg; ++arg) {
    if (*arg > 127) throw std::runtime_error("invalid node alias");
    value.push_back(static_cast<char>(*arg));
  }
  return value;
}
}
int wmain(int argc, wchar_t** argv) {
  if(argc>=2 && std::wstring_view(argv[1])==L"--platform-chain-login-stdin") {
    if(argc!=4) {std::cerr<<"Platform chain diagnostic failed stage=arguments cleanup=complete\n";return 2;}
    const char* stage="token";
    bool cleanup_complete=true;
    try {
      namespace sc=orangespace::service_client;
      namespace ps=orangespace::platform_session;
      ns::detail::require(sc::current_interactive_session().has_value());
      struct Token {HANDLE h{};~Token(){if(h)CloseHandle(h);}} token;
      ns::detail::require(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token.h));
      TOKEN_ELEVATION elevation{};DWORD size{};
      ns::detail::require(GetTokenInformation(token.h,TokenElevation,&elevation,sizeof(elevation),&size) && !elevation.TokenIsElevated);
      // Reject noninteractive logons even in a nonzero session. Service still
      // independently validates the OS peer; no supplied SID/session/peer data.
      BYTE sid[SECURITY_MAX_SID_SIZE];DWORD sid_size=sizeof(sid);BOOL interactive=FALSE;
      ns::detail::require(CreateWellKnownSid(WinInteractiveSid,nullptr,sid,&sid_size) &&
        CheckTokenMembership(nullptr,sid,&interactive) && interactive);
      stage="arguments";const auto expected=alias(argv[3]);ns::detail::require(ns::detail::uuid(expected));
      stage="config";const auto config=ps::PlatformConfig::load(argv[2]);
      stage="stdin";const auto input=GetStdHandle(STD_INPUT_HANDLE);
      ns::detail::require(GetFileType(input)==FILE_TYPE_PIPE);
      auto read=[&](char& c){DWORD n{};return ReadFile(input,&c,1,&n,nullptr)&&n==1;};
      auto username=platform_diag::line(read,256),password=platform_diag::line(read,1024);
      struct Caller {
        ps::Session login(const ps::PlatformConfig& c,std::string_view u,std::string_view p){return ps::Session::login(c,u,p);}
        sc::Grant authorize(const ps::Session& s,const ps::NodeRef& n){return sc::authorize_platform(s,n);}
        std::string uuid(){
          std::array<unsigned char,16> bytes{};
          ns::detail::require(BCryptGenRandom(nullptr,bytes.data(),static_cast<ULONG>(bytes.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG)==0);
          bytes[6]=(bytes[6]&15)|64;bytes[8]=(bytes[8]&63)|128;
          constexpr char hex[]="0123456789abcdef";std::string out;out.reserve(36);
          for(std::size_t i=0;i<bytes.size();++i){if(i==4||i==6||i==8||i==10)out+='-';out+=hex[bytes[i]>>4];out+=hex[bytes[i]&15];}
          return out;
        }
        auto start(const sc::Grant& g,std::string_view id){return sc::start_registered_tunnel(g,id);}
        auto active(const sc::Grant& g){return sc::active_tunnels(g);}
        void stop(const sc::Grant& g,const sc::chain::Binding& b){(void)sc::stop_tunnel(g,b);}
        void logout(const sc::Grant& g){sc::logout(g);}
        void retire(const sc::Grant& g){sc::retire(g);}
      };
      platform_chain_diag::run(config,username.view(),password.view(),expected,Caller{},stage,cleanup_complete);
      std::cout<<"Platform chain diagnostic passed stage=complete browser_allowed=false wfp_verified=false renewal_tested=false\n";
      return 0;
    }catch(...){
      std::cerr<<"Platform chain diagnostic failed stage="<<stage<<" cleanup="<<(cleanup_complete?"complete":"pending")<<'\n';
      return cleanup_complete?1:3;
    }
  }
  // This branch owns its complete exception boundary: no SDK/server text escapes.
  if (argc>=2 && std::wstring_view(argv[1])==L"--platform-https-stdin") {
    if(argc!=3 && argc!=4) {
      std::cerr << "Platform HTTPS diagnostic failed stage=arguments\n"; return 2;
    }
    const char* stage="config";
    try {
      namespace ps=orangespace::platform_session;
      const auto config=ps::PlatformConfig::load(argv[2]);
      stage="arguments";
      const auto expected=argc==4?alias(argv[3]):std::string{};
      ns::detail::require(argc!=4 || ns::detail::uuid(expected));
      stage="stdin";
      const auto input=GetStdHandle(STD_INPUT_HANDLE);
      if(GetFileType(input)!=FILE_TYPE_PIPE) throw std::runtime_error("pipe required");
      auto read=[&](char& c) { DWORD count{}; return ReadFile(input,&c,1,&count,nullptr) && count==1; };
      auto username=platform_diag::line(read,256);
      auto password=platform_diag::line(read,1024);
      struct Caller {
        ps::Session login(const ps::PlatformConfig& c,std::string_view u,std::string_view p) { return ps::Session::login(c,u,p); }
        ps::Session restore(const ps::PlatformConfig& c,std::string_view e) { return ps::Session::restore(c,e); }
      };
      const auto count=platform_diag::run(config,username.view(),password.view(),expected,Caller{},stage);
      std::cout << "Platform HTTPS diagnostic passed nodes=" << count << '\n';
      return 0;
    } catch (...) {
      std::cerr << "Platform HTTPS diagnostic failed stage=" << stage << '\n';
      return 1;
    }
  }
  const char* chain_failure_stage = nullptr;
  try {
    if (argc == 5 && std::wstring_view(argv[1]) == L"--service-switch-stdin") {
      const auto catalog=ns::TrustedCatalog::load(argv[2]); const auto node_a=alias(argv[3]),node_b=alias(argv[4]);
      orangespace::service::chain::Text input; input.value.reserve(32768);
      struct Buffer {std::array<char,1024> bytes{};~Buffer(){ns::detail::wipe(bytes.data(),bytes.size());}} buffer;
      DWORD count{};
      for(;;) {
        if(!ReadFile(GetStdHandle(STD_INPUT_HANDLE),buffer.bytes.data(),static_cast<DWORD>(buffer.bytes.size()),&count,nullptr)) {
          if(GetLastError()==ERROR_BROKEN_PIPE)break;
          throw std::runtime_error("fixture stdin failed");
        }
        if(!count)break;
        ns::detail::require(input.value.size()+count<=32768); input.value.append(buffer.bytes.data(),count);
      }
      const auto split=input.value.find('\n'); ns::detail::require(split!=std::string::npos);
      auto session_a=ns::NodeSession::restore_envelope(catalog,node_a,std::string_view(input.value).substr(0,split));
      auto session_b=ns::NodeSession::restore_envelope(catalog,node_b,std::string_view(input.value).substr(split+1));
      auto ga=orangespace::service_client::authorize(node_a,session_a);
      auto gb=orangespace::service_client::authorize(node_b,session_b);
      try {
        auto a=orangespace::service_client::start_tunnel(ga);
        auto sibling=orangespace::service_client::start_tunnel(ga);
        auto switched=orangespace::service_client::start_tunnel(gb,orangespace::service::chain::Cursor{a.sandbox,a.generation});
        ns::detail::require(switched.sandbox==a.sandbox && switched.generation>a.generation && switched.node==gb.node() && switched.user==gb.user());
        auto active_a=orangespace::service_client::active_tunnels(ga);
        auto active_b=orangespace::service_client::active_tunnels(gb);
        ns::detail::require(active_a.size()==1 && active_a.front()==sibling && active_b.size()==1 && active_b.front()==switched);
        bool stale=false;
        try {(void)orangespace::service_client::start_tunnel(ga,orangespace::service::chain::Cursor{a.sandbox,a.generation});}catch(...){stale=true;}
        ns::detail::require(stale);
        (void)orangespace::service_client::stop_tunnel(gb,switched);
        orangespace::service_client::logout(gb);
        active_a=orangespace::service_client::active_tunnels(ga);
        ns::detail::require(active_a.size()==1 && active_a.front()==sibling);
        orangespace::service_client::logout(ga);
      }catch(...) {
        try {orangespace::service_client::logout(gb);}catch(...){}
        try {orangespace::service_client::logout(ga);}catch(...){}
        throw;
      }
      std::cout<<"PASS: native two-node/per-auth runtime switch; service CAS rejects captured A start; A sibling survives B stop/logout. Logical node identities, not distinct public egress; browser denied.\n";
      return 0;
    }
    if (argc == 4 && std::wstring_view(argv[1]) == L"--service-chain-stdin") {
      // Opt-in native acceptance: protected catalog path + alias are public;
      // authenticated envelope arrives only via an anonymous stdin pipe. Never
      // argv/environment/plaintext fixture files and never echoed on error.
      chain_failure_stage = "catalog";
      const auto catalog=ns::TrustedCatalog::load(argv[2]); const auto node=alias(argv[3]);
      chain_failure_stage = "stdin";
      orangespace::service::chain::Text envelope; envelope.value.reserve(16384);
      struct Buffer { std::array<char,1024> bytes{}; ~Buffer(){ns::detail::wipe(bytes.data(),bytes.size());} } buffer;
      DWORD count{};
      for(;;) {
        if(!ReadFile(GetStdHandle(STD_INPUT_HANDLE),buffer.bytes.data(),static_cast<DWORD>(buffer.bytes.size()),&count,nullptr)) {
          if(GetLastError()==ERROR_BROKEN_PIPE) break;
          throw std::runtime_error("fixture stdin failed");
        }
        if(!count) break;
        ns::detail::require(envelope.value.size()+count<=16384);
        envelope.value.append(buffer.bytes.data(),count);
      }
      chain_failure_stage = "restore";
      const auto session=ns::NodeSession::restore_envelope(catalog,node,envelope.value);
      chain_failure_stage = "save";
      ns::CredentialStore::save(catalog,node,session);
      try {
        chain_failure_stage = "load";
        const auto restored=ns::CredentialStore::load(catalog,node);
        chain_failure_stage = "authorize";
        auto grant=orangespace::service_client::authorize(node,restored);
        try {
          chain_failure_stage = "start-a";
          auto a=orangespace::service_client::start_tunnel(grant);
          chain_failure_stage = "start-b";
          auto b=orangespace::service_client::start_tunnel(grant);
          ns::detail::require(a.sandbox!=b.sandbox && a.tunnel!=b.tunnel);
          chain_failure_stage = "active-two";
          auto active=orangespace::service_client::active_tunnels(grant);
          ns::detail::require(active.size()==2);
          chain_failure_stage = "stop-a";
          orangespace::service_client::stop_tunnel(grant,a);
          chain_failure_stage = "active-one";
          active=orangespace::service_client::active_tunnels(grant);
          ns::detail::require(active.size()==1 && active.front()==b);
          // Local credential removal is unconditional and precedes remote logout.
          chain_failure_stage = "erase";
          ns::CredentialStore::erase(catalog,node);
          chain_failure_stage = "logout";
          orangespace::service_client::logout(grant);
          chain_failure_stage = "stale-status";
          bool stale=false;
          try {orangespace::service_client::check_status(grant);} catch (...) {stale=true;}
          ns::detail::require(stale);
        } catch (...) {
          try {ns::CredentialStore::erase(catalog,node);} catch (...) {}
          try {orangespace::service_client::logout(grant);} catch (...) {}
          throw;
        }
      } catch (...) {try {ns::CredentialStore::erase(catalog,node);} catch (...) {} throw;}
      std::cout << "PASS: native HTTPS restore/DPAPI/service authorization; A/B forwarding proofs; exact A stop retains B; logout rejects stale auth. Browser remains denied; not WFP acceptance.\n";
      return 0;
    }
    if (argc == 3 && std::wstring_view(argv[1]) == L"--check-trust") {
      const auto catalog = ns::TrustedCatalog::load(argv[2]);
      const auto names = catalog.names();
      std::cout << "Protected trust configuration accepted; nodes=" << names.size() << '\n';
      for (const auto& name : names) std::cout << "node alias: " << name << '\n';
      return 0;
    }
    if (argc != 3) {
      std::cerr << "Usage: OrangeSpaceLogin.exe <absolute-trust-path> <pinned-alias>\n"
                   "       OrangeSpaceLogin.exe --check-trust <absolute-trust-path>\n"
                   "       OrangeSpaceLogin.exe --service-chain-stdin <absolute-trust-path> <pinned-alias>\n"
                   "Passwords require interactive console; opt-in chain test reads a bounded credential envelope only from stdin.\n";
      return 2;
    }
    const auto catalog = ns::TrustedCatalog::load(argv[1]);
    const auto node = alias(argv[2]);
    const auto names = catalog.names();
    bool present = false;
    for (const auto& name : names) present = present || name == node;
    if (!present) throw std::runtime_error("node alias is not administrator pinned");
    std::cout << "Username: " << std::flush;
    auto username = read_line(false, 64);
    std::cout << "Password (not echoed): " << std::flush;
    auto password = read_line(true, 1024);
    std::cout << '\n';
    const auto session = ns::NodeSession::login(catalog, node, username.view(), password.view());
    ns::detail::wipe(password.bytes.data(), password.bytes.size());
    password.bytes.clear();
    std::cout << "Authenticated user_id=" << session.identity().user_id
              << " node_id=" << session.identity().node_id
              << " expires_at=" << session.expires_at() << '\n'
              << "Node HTTPS session verified. Browser remains blocked.\n";
    const auto grant=orangespace::service_client::authorize(node,session);
    ns::CredentialStore::save(catalog,node,session);
    orangespace::service_client::check_status(grant);
    std::cout << "Service authorization verified; current-user DPAPI credential saved. No helper/browser started.\n";
    return 0;
  } catch (const std::exception& error) {
    // All component exceptions are constant diagnostics; never server bodies,
    // request headers, passwords, access tokens, or serialized JSON.
    if (chain_failure_stage)
      std::cerr << "Native service-chain failed stage=" << chain_failure_stage << '\n';
    else
    std::cerr << "Login diagnostic failed: " << error.what() << '\n';
    return 1;
  }
}
#endif
