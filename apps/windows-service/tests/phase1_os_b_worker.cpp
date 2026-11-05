// Opt-in TEST worker, run only by the approved highest session-2 controller.
// All API credentials, learned authorization and ciphertext enter via private pipe.
#include "phase1_os_b_win.hpp"
#include "orangespace/credential_store.hpp"
#include "orangespace/service_chain.hpp"
#include <algorithm>
namespace pb=phase1_os_b;
namespace ns=orangespace::node_session;
namespace ch=orangespace::service::chain;
using pb::need;using pb::Handle;
namespace {
std::uint64_t number(std::string_view s){std::uint64_t n=0;need(pb::decimal(s,n),"number");return n;}
std::wstring entry(const std::wstring& root,std::string_view node){return root+L"\\"+pb::wide(node)+L".dpapi";}
// Pin the same public catalog bytes while production's independent ACL-checking
// loader constructs the only network-capable catalog. Never build a fake catalog.
struct CatalogFile {
 Handle file;
 std::vector<ns::detail::NodeEntry> nodes;
 explicit CatalogFile(const std::wstring& path){
  file.reset(CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));need(file.h!=INVALID_HANDLE_VALUE,"catalog_pin");
  LARGE_INTEGER n{};need(GetFileSizeEx(file.h,&n)&&n.QuadPart>0&&n.QuadPart<=65536,"catalog_size");
  std::string raw(std::size_t(n.QuadPart),'\0');DWORD got=0;need(ReadFile(file.h,raw.data(),DWORD(raw.size()),&got,nullptr)&&got==raw.size(),"catalog_read");nodes=ns::detail::parse_catalog(raw);
 }
 const ns::detail::NodeEntry& node(std::string_view alias)const{auto i=std::find_if(nodes.begin(),nodes.end(),[&](const auto& n){return n.name==alias;});need(i!=nodes.end(),"catalog_alias");return *i;}
};
void install_copy(const std::wstring& target,std::string_view cipher,const std::wstring& sid){
 // Parent names are B's real production-created credential directory. No profile,
 // LocalAppData, store path or entropy is supplied by caller or environment.
 auto sd=pb::descriptor(L"O:"+sid+L"D:P(A;;FA;;;SY)(A;;FA;;;"+sid+L")");SECURITY_ATTRIBUTES sa{sizeof(sa),sd.get(),FALSE};
 Handle file(CreateFileW(target.c_str(),GENERIC_WRITE|READ_CONTROL,0,&sa,CREATE_NEW,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));need(file.h!=INVALID_HANDLE_VALUE,"copy_create_new");
 DWORD n=0;need(WriteFile(file.h,cipher.data(),DWORD(cipher.size()),&n,nullptr)&&n==cipher.size()&&FlushFileBuffers(file.h),"copy_cipher_only");
}
// OS AccessDenied at open is the only accepted negative. Closed/broken/busy,
// malformed replies, token errors and service absence NEVER become a pass.
bool raw_denial(const pb::Fields& f,pb::Observations& observations,const std::wstring& fixture_root){
 pb::Wiped payload("{\"auth_id\":"+ch::quote(f[pb::auth_a])+",\"sandbox_id\":"+ch::quote(f[pb::sandbox_a])+"}");
 auto frame=ch::request_frame(ch::Op::status,payload.value);
 struct Wipe{std::vector<std::uint8_t>& v;~Wipe(){SecureZeroMemory(v.data(),v.size());}}wipe{frame};
 // Actual production parser must accept the request; no NodeUserID surrogate.
 (void)ch::parse_request(frame);
 const std::wstring name=L"\\\\.\\pipe\\OrangeSpace.Foundation.v1.session.2";
 SC_HANDLE scm=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);if(!scm)return false;
 SC_HANDLE service=OpenServiceW(scm,L"OrangeSpaceFoundation",SERVICE_QUERY_STATUS|SERVICE_QUERY_CONFIG);CloseServiceHandle(scm);if(!service)return false;
 struct ServiceClose{SC_HANDLE h;~ServiceClose(){CloseServiceHandle(h);}} close{service};
 SERVICE_STATUS_PROCESS status{};DWORD needed=0;
 if(!QueryServiceStatusEx(service,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE*>(&status),sizeof(status),&needed)||status.dwCurrentState!=SERVICE_RUNNING||status.dwServiceType!=SERVICE_WIN32_OWN_PROCESS||status.dwProcessId!=number(f[pb::service_pid]))return false;
 QueryServiceConfigW(service,nullptr,0,&needed);if(GetLastError()!=ERROR_INSUFFICIENT_BUFFER||needed>65536||needed<sizeof(QUERY_SERVICE_CONFIGW))return false;
 std::vector<BYTE> config(needed);auto* cfg=reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config.data());
 if(!QueryServiceConfigW(service,cfg,needed,&needed)||!cfg->lpServiceStartName||std::wstring_view(cfg->lpServiceStartName)!=L"LocalSystem"||!cfg->lpBinaryPathName||std::wstring_view(cfg->lpBinaryPathName)!=L"\""+fixture_root+L"\\OrangeSpaceFoundation.exe\"")return false;
 const auto deadline=GetTickCount64()+3000;
 do{
  if(!WaitNamedPipeW(name.c_str(),500)){
   const auto e=GetLastError();if(e==ERROR_SEM_TIMEOUT||e==ERROR_PIPE_BUSY){Sleep(10);continue;}return false;
  }
  observations.flags[pb::listener_ready]=true;
  constexpr DWORD rights=0x12019b;static_assert(!(rights&FILE_CREATE_PIPE_INSTANCE));
  Handle pipe(CreateFileW(name.c_str(),rights,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IMPERSONATION,nullptr));
  const auto error=GetLastError();
  if(pipe.h==INVALID_HANDLE_VALUE){
   if(pb::pipe_denied(error,true)){SERVICE_STATUS_PROCESS final{};return QueryServiceStatusEx(service,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE*>(&final),sizeof(final),&needed)&&final.dwCurrentState==SERVICE_RUNNING&&final.dwProcessId==status.dwProcessId;}
   if(error==ERROR_PIPE_BUSY){Sleep(10);continue;}return false;
  }
  // Unexpected admission FAILS this strict pipe-DACL assertion. No learned
  // auth bytes are sent to an unpinned process; no service-policy reply is claimed.
  return false;
 }while(GetTickCount64()<deadline);
 return false;
}
void exercise(HANDLE channel,const std::wstring& catalog_path,const pb::Fields& f,pb::Observations& out){
 need(pb::valid_fields(f),"input_contract");const auto me=pb::current_identity();
 out.flags[pb::not_admin]=pb::ordinary();out.flags[pb::same_session]=me.session==2;
 out.flags[pb::different_sid]=me.sid!=pb::wide(f[pb::sid_a]);out.flags[pb::different_luid]=me.luid!=number(f[pb::luid_a]);
 need(out.flags[0]&&out.flags[1]&&out.flags[2]&&out.flags[3],"independent_ordinary_b");
 need(!pb::registry_absent(HKEY_USERS,me.sid),"profile_hive_loaded");out.flags[pb::profile_loaded]=true;
 CatalogFile pin(catalog_path);const auto catalog=ns::TrustedCatalog::load(catalog_path);
 const auto& na=pin.node(f[pb::alias_a]);const auto& nb=pin.node(f[pb::alias_b]);need(na.node_id==f[pb::node_a]&&na.node_id!=nb.node_id,"canonical_catalog_identity");
 const auto root=pb::store_root(),pa=entry(root,na.node_id),pbb=entry(root,nb.node_id);
 need(ns::detail::explicit_local_path(root)&&pb::path_absent(pa)&&pb::path_absent(pbb),"never_overwrite_store");
 const auto original=pb::wide(f[pb::original_a]);need(ns::detail::explicit_local_path(original)&&original.ends_with(L"\\OrangeSpace-Credentials-v1\\"+pb::wide(na.node_id)+L".dpapi"),"original_a_path");
 Handle a_file(CreateFileW(original.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));const auto ae=GetLastError();
 out.flags[pb::a_acl_denied]=a_file.h==INVALID_HANDLE_VALUE&&ae==ERROR_ACCESS_DENIED;need(out.flags[pb::a_acl_denied],"a_original_acl_denied5");
 // Fresh, real login uses production WinHTTP and its default TLS verification.
 auto own=ns::NodeSession::login(catalog,f[pb::alias_b],f[pb::username_b],f[pb::password_b]);out.flags[pb::real_login]=true;
 struct Cleanup {
  const ns::TrustedCatalog& catalog;const pb::Fields& f;const ns::NodeSession& session;bool a=false,b=false;
  bool clear()noexcept{bool ok=true;if(a)try{ns::CredentialStore::erase(catalog,f[pb::alias_a]);a=false;}catch(...){ok=false;}if(b)try{ns::CredentialStore::erase(catalog,f[pb::alias_b]);b=false;}catch(...){ok=false;}return ok;}
  ~Cleanup(){clear();try{session.logout();}catch(...){}}
 } cleanup{catalog,f,own};
 cleanup.b=true;ns::CredentialStore::save(catalog,f[pb::alias_b],own);
 auto loaded=ns::CredentialStore::load(catalog,f[pb::alias_b]);
 out.flags[pb::store_roundtrip]=loaded.identity().node_id==own.identity().node_id&&loaded.identity().user_id==own.identity().user_id&&own.identity().node_id==nb.node_id;
 need(out.flags[pb::store_roundtrip],"b_actual_store_roundtrip");
 pb::send_private(channel,"OSB_BEFORE_COPY1",3000);need(pb::read_private(channel,15000)=="OSB_ACK_COPY1","api_audit_begin_ack");
 cleanup.a=true;install_copy(pa,f[pb::cipher_a],me.sid);
 // Real production load selects current B SID + canonical A node UUID/origin.
 // There is intentionally NO A-SID/entropy/decrypt override/backdoor.
 try{auto unexpected=ns::CredentialStore::load(catalog,f[pb::alias_a]);(void)unexpected;}catch(...){out.flags[pb::a_load_rejected]=true;}
 out.flags[pb::a_copy_purged]=pb::path_absent(pa);need(out.flags[pb::a_load_rejected]&&out.flags[pb::a_copy_purged],"a_actual_cipher_rejected_purged");
 // A/control must remain live and keep the learned grant/binding valid here.
 pb::send_private(channel,"OSB_READY_RAW1",3000);need(pb::read_private(channel,15000)=="OSB_ACK_RAW1","live_a_ack");
 out.flags[pb::raw_osp2_denied]=raw_denial(f,out,catalog_path.substr(0,catalog_path.find_last_of(L'\\')));need(out.flags[pb::raw_osp2_denied],"raw_osp2_denied5");
 out.flags[pb::store_clean]=cleanup.clear()&&pb::path_absent(pa)&&pb::path_absent(pbb);need(out.flags[pb::store_clean],"b_store_cleanup");
}
}
int wmain(int argc,wchar_t** argv){
 // No stdin/env credentials, no files/log output. Public arguments only.
 if(argc!=4)return 2;
 pb::Observations out;Handle channel;
 try{
  const std::wstring catalog=argv[1],pipe=argv[2];const auto pid=number(pb::narrow(argv[3]));need(pid<=MAXDWORD,"controller_pid");
  need(ns::detail::explicit_local_path(catalog)&&pipe.starts_with(L"\\\\.\\pipe\\OrangeSpace.Phase1.OSB.")&&pipe.size()<180,"public_arguments");
  need(WaitNamedPipeW(pipe.c_str(),10000),"private_ready");
  channel.reset(CreateFileW(pipe.c_str(),0x12019b,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,nullptr));need(channel.h!=INVALID_HANDLE_VALUE,"private_connect");
  ULONG peer=0;need(GetNamedPipeServerProcessId(channel.h,&peer)&&peer==pid,"private_server_pid");
  // The protected creator supplies its PID in public argv. No PROCESS_QUERY
  // ACL widening on high-A is needed for B; the named-pipe server PID must match.
  pb::send_private(channel.h,"OSB_HELLO1",3000);
  pb::Wiped body(pb::read_private(channel.h,15000));auto fields=pb::decode(body.value);exercise(channel.h,catalog,fields,out);
 }catch(...){/* Never print exception text, bodies, auth IDs or usernames. */}
 if(channel.h&&channel.h!=INVALID_HANDLE_VALUE)try{pb::send_private(channel.h,out.encode(),3000);}catch(...){return 3;}
 return out.complete()?0:1;
}
