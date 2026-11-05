// Opt-in native acceptance TEST, never a production privileged entry point.
// Binary stdin/stdout: uint32 little-endian length then UTF-8 JSON, <=32768.
#include "phase1_native.hpp"
#include "phase1_contract.hpp"
#include "orangespace/credential_store.hpp"
#include "orangespace/service_client.hpp"
#include <sddl.h>
#include <shlobj.h>
#include <ctime>
#include <memory>
namespace ns=orangespace::node_session;
namespace sc=orangespace::service_client;
namespace ch=orangespace::service::chain;
using namespace phase1;
namespace {
void event(const char* stage) {send_frame(GetStdHandle(STD_OUTPUT_HANDLE),std::string("{\"schema\":1,\"kind\":\"pass\",\"stage\":\"")+stage+"\",\"ok\":true}");}
void control(const char* action){
 send_frame(GetStdHandle(STD_OUTPUT_HANDLE),std::string("{\"schema\":1,\"kind\":\"control\",\"action\":\"")+action+"\"}");
 need(read_frame(GetStdHandle(STD_INPUT_HANDLE),30000)=="{\"schema\":1,\"kind\":\"ack\",\"ok\":true}","control_ack");
}
// Production APIs do not expose a typed semantic-error/status boundary here.
// An arbitrary exception therefore cannot establish any expected rejection.
// Stop at a proof gap, even when the control path might otherwise be healthy.
struct NegativeProofGap {};
template<class F> bool rejected(F&& f){try{f();return false;}catch(...){throw NegativeProofGap{};}}
void limited(DWORD expected){
 Handle token;need(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token.h),"client_token");
 DWORD n=0,session=0;TOKEN_ELEVATION elevation{};
 need(GetTokenInformation(token.h,TokenSessionId,&session,sizeof(session),&n)&&session!=0&&session==expected,"client_session");
 need(GetTokenInformation(token.h,TokenElevation,&elevation,sizeof(elevation),&n)&&!elevation.TokenIsElevated,"client_not_elevated");
 GetTokenInformation(token.h,TokenIntegrityLevel,nullptr,0,&n);std::vector<BYTE>b(n);
 need(GetTokenInformation(token.h,TokenIntegrityLevel,b.data(),n,&n),"client_integrity");
 auto* sid=reinterpret_cast<TOKEN_MANDATORY_LABEL*>(b.data())->Label.Sid;
 auto rid=*GetSidSubAuthority(sid,*GetSidSubAuthorityCount(sid)-1);
 need(rid==SECURITY_MANDATORY_MEDIUM_RID,"client_medium_integrity");
 BOOL admin=TRUE;SID_IDENTIFIER_AUTHORITY nt=SECURITY_NT_AUTHORITY;PSID a=nullptr;
 need(AllocateAndInitializeSid(&nt,2,SECURITY_BUILTIN_DOMAIN_RID,DOMAIN_ALIAS_RID_ADMINS,0,0,0,0,0,0,&a),"admin_sid");
 BOOL ok=CheckTokenMembership(nullptr,a,&admin);FreeSid(a);need(ok&&!admin,"client_admin_disabled");
}
std::wstring store_path(const std::string& node){
 PWSTR local=nullptr;need(SHGetKnownFolderPath(FOLDERID_LocalAppData,0,nullptr,&local)==S_OK,"local_appdata");
 std::wstring p=std::wstring(local)+L"\\OrangeSpace-Credentials-v1\\"+std::wstring(node.begin(),node.end())+L".dpapi";CoTaskMemFree(local);return p;
}
bool absent(const std::wstring& p){DWORD a=GetFileAttributesW(p.c_str());DWORD e=GetLastError();return a==INVALID_FILE_ATTRIBUTES&&(e==ERROR_FILE_NOT_FOUND||e==ERROR_PATH_NOT_FOUND);}
void only(const sc::Grant& g,const ch::Binding& b){auto a=sc::active_tunnels(g);need(a.size()==1&&a.front()==b,"exact_survivor");}
struct StoreCleanup {
 const ns::TrustedCatalog& catalog;const Bootstrap& b;bool a=false,bb=false;
 bool clear()noexcept{bool ok=true;for(auto x:{std::pair{&a,&b.alias_a},std::pair{&bb,&b.alias_b}})if(*x.first)try{ns::CredentialStore::erase(catalog,*x.second);*x.first=false;}catch(...){ok=false;}return ok;}
 ~StoreCleanup(){clear();}
};
struct GrantCleanup {
 std::vector<const sc::Grant*> grants;
 ~GrantCleanup(){for(auto*g:grants)try{sc::logout(*g);}catch(...){}}
};
}
int wmain(int argc,wchar_t** argv){
 return ERROR_ACCESS_DISABLED_BY_POLICY; // phase1 fixture quarantine; no override
 const char* stage="arguments";DWORD error=0;bool complete=false,cleanup_ok=false;
 try{
  need(argc==3,"arguments");need(std::wstring_view(argv[2])==L"2","expected_session_argument");limited(2);event("limited_identity");
  stage="bootstrap";auto raw=read_frame(GetStdHandle(STD_INPUT_HANDLE),15000);
  struct Wipe {std::string& s;~Wipe(){ns::detail::wipe(s.data(),s.size());}} wipe{raw};
  auto bootstrap=parse_bootstrap(raw);ns::detail::wipe(raw.data(),raw.size());raw.clear();
  if(std::wstring_view(argv[1])==L"--selftest") {
   event("protected_bootstrap_parsed");
   send_frame(GetStdHandle(STD_OUTPUT_HANDLE),"{\"schema\":1,\"kind\":\"bootstrap_result\",\"ok\":true,\"browser_allowed\":false}");return 0;
  }
  stage="catalog";const auto catalog=ns::TrustedCatalog::load(argv[1]);
  stage="fresh_login_a";auto a=ns::NodeSession::login(catalog,bootstrap.alias_a,bootstrap.username_a,bootstrap.password_a);
  stage="fresh_login_b";auto b=ns::NodeSession::login(catalog,bootstrap.alias_b,bootstrap.username_b,bootstrap.password_b);
  need(a.identity().node_id!=b.identity().node_id&&a.identity().user_id!=b.identity().user_id,"independent_node_realms");event("fresh_login_me_both_nodes");
  const auto pa=store_path(a.identity().node_id),pb=store_path(b.identity().node_id);
  need(absent(pa)&&absent(pb),"never_overwrite_existing_store");StoreCleanup store{catalog,bootstrap};
  stage="bad_password";std::string wrong="phase1-invalid-password-A";if(std::string_view(bootstrap.password_a)==wrong)wrong.back()='B';Wipe wipe_wrong{wrong};
  need(rejected([&]{(void)ns::NodeSession::login(catalog,bootstrap.alias_a,bootstrap.username_a,wrong);}),"bad_password_rejected");event("bad_password_rejected");
  stage="dpapi_roundtrip";store.a=true;ns::CredentialStore::save(catalog,bootstrap.alias_a,a);
  store.bb=true;ns::CredentialStore::save(catalog,bootstrap.alias_b,b);
  auto loaded=ns::CredentialStore::load(catalog,bootstrap.alias_a);
  need(loaded.identity().user_id==a.identity().user_id&&loaded.identity().node_id==a.identity().node_id,"loaded_identity");event("dpapi_save_load");
  stage="logout_relogin";loaded.logout();need(rejected([&]{(void)ns::CredentialStore::load(catalog,bootstrap.alias_a);}),"logged_out_restore_rejected");
  need(absent(pa),"revoked_store_purged");
  auto anew=ns::NodeSession::login(catalog,bootstrap.alias_a,bootstrap.username_a,bootstrap.password_a);
  ns::CredentialStore::save(catalog,bootstrap.alias_a,anew);event("logout_purge_fresh_relogin");
  stage="service_authorize";auto ga=sc::authorize(bootstrap.alias_a,anew);auto gb=sc::authorize(bootstrap.alias_b,b);GrantCleanup grants{{&ga,&gb}};
  need(ga.user()==anew.identity().user_id&&gb.user()==b.identity().user_id&&ga.node()!=gb.node(),"grant_realms");
  stage="two_helpers_proof";auto a1=sc::start_tunnel(ga);auto a2=sc::start_tunnel(ga);auto b1=sc::start_tunnel(gb);
  need(a1.sandbox!=a2.sandbox&&a1.tunnel!=a2.tunnel&&a1.node==ga.node()&&b1.node==gb.node(),"distinct_bindings");event("three_helpers_all_proofs");
  stage="close_a_keeps_b";sc::stop_tunnel(ga,a1);only(ga,a2);only(gb,b1);event("close_a_keeps_b");
  stage="node_switch";auto sibling=sc::start_tunnel(ga);auto switched=sc::start_tunnel(gb,ch::Cursor{a2.sandbox,a2.generation});
  need(switched.sandbox==a2.sandbox&&switched.node==gb.node()&&switched.generation>a2.generation,"switch_new_generation");
  need(rejected([&]{(void)sc::start_tunnel(ga,ch::Cursor{a2.sandbox,a2.generation});}),"captured_old_cas_rejected");
  only(ga,sibling);sc::stop_tunnel(gb,switched);only(gb,b1);only(ga,sibling);event("switch_old_cas_rejected_sibling_alive");
  stage="renew";const auto until=GetTickCount64()+bootstrap.renew_seconds*1000ull;
  while(GetTickCount64()<until){Sleep(1000);only(ga,sibling);only(gb,b1);}event("proofs_alive_beyond_initial_30s");
  stage="owned_helper_crash";control("kill_one_owned_helper");
  bool dead_a=false,dead_b=false;const auto poll_until=GetTickCount64()+15000;
  while(GetTickCount64()<poll_until){dead_a=rejected([&]{sc::check_status(ga);});dead_b=rejected([&]{sc::check_status(gb);});if(dead_a||dead_b)break;Sleep(200);}
  need(dead_a!=dead_b,"one_failed_auth_only");if(dead_a)only(gb,b1);else only(ga,sibling);event("owned_helper_crash_invalidates_exact_realm");
  // Close the survivor; never assume an intentionally invalidated grant still works.
  if(!dead_a)sc::logout(ga);else anew.logout();
  if(!dead_b)sc::logout(gb);else b.logout();
  stage="before_service_crash";
  auto ca_session=ns::NodeSession::login(catalog,bootstrap.alias_a,bootstrap.username_a,bootstrap.password_a);
  auto cb_session=ns::NodeSession::login(catalog,bootstrap.alias_b,bootstrap.username_b,bootstrap.password_b);
  auto ga2=sc::authorize(bootstrap.alias_a,ca_session);auto gb2=sc::authorize(bootstrap.alias_b,cb_session);
  GrantCleanup grants2{{&ga2,&gb2}};auto ca=sc::start_tunnel(ga2);auto cb=sc::start_tunnel(gb2);(void)cb;
  control("crash_restart_owned_service");
  stage="restart_old_auth";need(rejected([&]{sc::check_status(ga2);})&&rejected([&]{sc::check_status(gb2);}),"old_auth_rejected_after_restart");
  auto after=ns::NodeSession::login(catalog,bootstrap.alias_a,bootstrap.username_a,bootstrap.password_a);
  auto ga3=sc::authorize(bootstrap.alias_a,after);GrantCleanup grants3{{&ga3}};
  need(ga3.id()!=ga2.id(),"fresh_service_auth_epoch");
  auto resumed=sc::start_tunnel(ga3,ch::Cursor{ca.sandbox,ca.generation});
  need(resumed.generation>ca.generation&&resumed.sandbox==ca.sandbox,"durable_generation_advanced");
  need(rejected([&]{(void)sc::start_tunnel(ga3,ch::Cursor{ca.sandbox,ca.generation});}),"precrash_cas_rejected");
  sc::stop_tunnel(ga3,resumed);sc::logout(ga3);ca_session.logout();cb_session.logout();event("restart_old_auth_cas_rejected_durable_generation");
  stage="expiry";auto expiring=ns::NodeSession::login(catalog,bootstrap.alias_a,bootstrap.username_a,bootstrap.password_a);
  const auto remaining=expiring.expires_at()-std::time(nullptr);need(remaining>0&&remaining<=bootstrap.expiry_budget_seconds,"expiry_within_budget");
  // Retain token in memory solely to force a real post-expiry /me via restore.
  auto envelope=expiring.credential_envelope();Wipe wipe_envelope{envelope};ns::detail::JsonGuard edoc(envelope);
  const auto& token=ns::detail::text(ns::detail::field(edoc.value,"access_token"));
  ns::CredentialStore::save(catalog,bootstrap.alias_a,expiring);
  send_frame(GetStdHandle(STD_OUTPUT_HANDLE),"{\"schema\":1,\"kind\":\"wait\",\"stage\":\"actual_api_expiry\",\"expires_at\":"+std::to_string(expiring.expires_at())+"}");
  const auto deadline=GetTickCount64()+(bootstrap.expiry_budget_seconds+3)*1000ull;
  while(std::time(nullptr)<=expiring.expires_at()){need(GetTickCount64()<deadline,"expiry_timeout");Sleep(250);}
  need(rejected([&]{(void)ns::NodeSession::restore(catalog,bootstrap.alias_a,token);}),"postexpiry_network_restore_rejected");
  need(rejected([&]{(void)ns::CredentialStore::load(catalog,bootstrap.alias_a);})&&absent(pa),"expired_store_purged");
  auto relogin=ns::NodeSession::login(catalog,bootstrap.alias_a,bootstrap.username_a,bootstrap.password_a);
  ns::CredentialStore::save(catalog,bootstrap.alias_a,relogin);auto reloaded=ns::CredentialStore::load(catalog,bootstrap.alias_a);
  need(reloaded.identity().user_id==relogin.identity().user_id,"postexpiry_reauth");relogin.logout();event("actual_expiry_purge_reauth");
  stage="store_cleanup";cleanup_ok=store.clear()&&absent(pa)&&absent(pb);need(cleanup_ok,"store_cleanup_verified");
  complete=true;
 }catch(NegativeProofGap){stage="negative_semantics_unproven";error=ERROR_NOT_SUPPORTED;}catch(Failure f){stage=f.stage;error=f.code;}catch(...){error=ERROR_INVALID_DATA;}
 const std::string result=std::string("{\"schema\":1,\"kind\":\"client_result\",\"ok\":")+(complete?"true":"false")+",\"stage\":\""+stage+"\",\"error\":"+std::to_string(error)+",\"store_cleanup_verified\":"+(cleanup_ok?"true":"false")+",\"os_b_covered\":false,\"http_401_independently_confirmed\":false,\"browser_allowed\":false}";
 try{send_frame(GetStdHandle(STD_OUTPUT_HANDLE),result);}catch(...){return 3;}return complete?0:1;
}
