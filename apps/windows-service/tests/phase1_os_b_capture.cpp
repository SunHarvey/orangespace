#include "phase1_os_b_capture.hpp"
namespace phase1_os_b {
Wiped capture_input(const ns::TrustedCatalog& catalog,std::string_view aa,std::string_view ab,const ns::NodeSession& actual,
 const orangespace::service_client::Grant& grant,const orangespace::service::chain::Binding& binding,
 std::string_view username,std::string_view password,std::uint32_t service){
 namespace sc=orangespace::service_client;
 const auto id=current_identity();need(ordinary()&&id.session==2,"capture_limited_a");
 need(grant.user()==actual.identity().user_id&&grant.node()==actual.identity().node_id&&binding.user==grant.user()&&binding.node==grant.node(),"capture_real_identity");
 const auto active=sc::active_tunnels(grant);need(std::find(active.begin(),active.end(),binding)!=active.end(),"capture_live_actual_binding");
 const auto path=store_root()+L"\\"+wide(actual.identity().node_id)+L".dpapi";
 Handle file(CreateFileW(path.c_str(),GENERIC_READ|READ_CONTROL,FILE_SHARE_READ|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));need(file.h!=INVALID_HANDLE_VALUE,"capture_actual_cipher");
 BY_HANDLE_FILE_INFORMATION info{};need(GetFileInformationByHandle(file.h,&info)&&!(info.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY))&&info.nNumberOfLinks==1,"capture_cipher_object");
 // Read the held object once. Store.load below may resolve a replacement: it
 // remains mandatory, but is NOT authority for these particular captured bytes.
 LARGE_INTEGER size{};need(GetFileSizeEx(file.h,&size)&&size.QuadPart>0&&size.QuadPart<=65536,"capture_cipher_size");Wiped cipher(std::string(std::size_t(size.QuadPart),'\0'));DWORD n=0;
 need(ReadFile(file.h,cipher.value.data(),DWORD(cipher.value.size()),&n,nullptr)&&n==cipher.value.size(),"capture_cipher_bytes");
 capture_positive(cipher.value,[&]{
  auto loaded=ns::CredentialStore::load(catalog,aa);need(loaded.identity().node_id==actual.identity().node_id&&loaded.identity().user_id==actual.identity().user_id,"capture_actual_load");
 },[&](std::string_view bytes){
  // Origin comes from the actual authenticated NodeSession, NEVER the relay or
  // a caller-selected entropy/path. restore_envelope revalidates it against the
  // TrustedCatalog and real HTTPS /me + session. Same user alone is insufficient.
  Wiped current(actual.credential_envelope());ns::detail::JsonGuard metadata(current.value);
  const auto& origin=ns::detail::text(ns::detail::field(metadata.value,"api_origin"));
  auto entropy=capture_entropy(narrow(id.sid),actual.identity().node_id,origin);
  DATA_BLOB input{DWORD(bytes.size()),reinterpret_cast<BYTE*>(const_cast<char*>(bytes.data()))};
  DATA_BLOB extra{DWORD(entropy.size()),reinterpret_cast<BYTE*>(entropy.data())};
  struct Plain {DATA_BLOB data{};~Plain(){if(data.pbData){SecureZeroMemory(data.pbData,data.cbData);LocalFree(data.pbData);}}} plain;
  need(CryptUnprotectData(&input,nullptr,&extra,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&plain.data),"capture_exact_decrypt");
  need(plain.data.cbData>0&&plain.data.cbData<=16384,"capture_exact_envelope_size");
  auto exact=ns::NodeSession::restore_envelope(catalog,aa,std::string_view(reinterpret_cast<const char*>(plain.data.pbData),plain.data.cbData));
  need(exact.identity().node_id==actual.identity().node_id&&exact.identity().user_id==actual.identity().user_id,"capture_exact_restore");
 });
 const auto original=narrow(path),sid=narrow(id.sid),luid=std::to_string(id.luid),pid=std::to_string(service),generation=std::to_string(binding.generation);
 const Fields fields{aa,ab,actual.identity().node_id,original,cipher.value,grant.id(),binding.sandbox,generation,username,password,sid,luid,"2",pid};need(valid_fields(fields),"capture_fields");
 return Wiped(encode(fields));
}
}
