// Portable injection fixture for the *actual* production save/load/erase bodies.
// No filesystem or DPAPI is emulated as a security proof; all bytes stay in RAM.
#include "orangespace/platform_credential_store.hpp"
#include "orangespace/credential_store.hpp"
#include <cassert>
#include <cstring>
#include <map>
#include <iostream>
using DWORD = unsigned long;
constexpr int FALSE = 0;
struct LARGE_INTEGER { long long QuadPart{}; };
namespace orangespace::platform_session::detail {
struct TestAccess { static PlatformConfig config(std::string origin="https://control.example.test") {
  return PlatformConfig(credential_detail::validate_origin(origin));
} };
}
namespace orangespace::node_session {
struct Record { std::string encrypted; bool marker{}, fail_delete{}, fail_clear{}, locked{}; int opened{}; };
inline std::map<std::string,Record> records;
inline bool crypto_failure{};
inline int restores{};
inline void checked(bool ok) { if(!ok) throw std::runtime_error("policy I/O failure"); }
inline std::int64_t now() { return 1000; }
struct Secret { std::string bytes; ~Secret(){detail::wipe(bytes.data(),bytes.size());} };
struct Blob {
  std::string bytes;
  struct { unsigned char* pbData; std::size_t cbData; } value;
  explicit Blob(std::string b):bytes(std::move(b)),value{reinterpret_cast<unsigned char*>(bytes.data()),bytes.size()}{}
  ~Blob(){detail::wipe(bytes.data(),bytes.size());}
};
struct File { Record* r; ~File(){--r->opened;} };
using Handle=std::unique_ptr<File>;
enum class StoreKind {node,platform};
struct Directory {
  int user{};
  explicit Directory(StoreKind k) {assert(k==StoreKind::platform);}
  Handle open(const detail::NodeEntry& key) {auto& r=records[key.name];if(r.encrypted.empty())return {}; ++r.opened;return std::make_unique<File>(&r);}
  void verify() {}
  std::string scope(const detail::NodeEntry& key) {return platform_session::credential_detail::entropy("S-1-5-21-123",key.name);}
};
struct NodeLock {
  Record& r;
  NodeLock(Directory&,const detail::NodeEntry& key,bool=true):r(records[key.name]) {checked(!r.locked);r.locked=true;}
  ~NodeLock(){r.locked=false;}
};
inline void require_not_pending(Directory&,const detail::NodeEntry& key){credential_detail::require_no_pending(records[key.name].marker);}
inline void verify_object(File*,bool){}
inline void verify_acl(File*,int,bool){}
inline bool GetFileSizeEx(File* f,LARGE_INTEGER* n){n->QuadPart=static_cast<long long>(f->r->encrypted.size());return true;}
inline bool ReadFile(File* f,void* out,DWORD n,DWORD* count,void*){std::memcpy(out,f->r->encrypted.data(),n);*count=n;return true;}
inline Blob encrypt(std::string_view input,std::string_view scope){checked(!crypto_failure);return Blob(std::string(scope)+"|"+std::string(input));}
inline Blob decrypt(std::string& input,std::string_view scope){checked(!crypto_failure && input.starts_with(std::string(scope)+"|"));return Blob(input.substr(scope.size()+1));}
inline void atomic_write(Directory&,const detail::NodeEntry& key,const Blob& b){records[key.name].encrypted=b.bytes;}
inline void erase_pending(Directory&,const detail::NodeEntry& key) {
  auto& r=records[key.name];
  struct Tx {
    Record& r;
    void commit(){r.marker=true;}
    void remove_blob(){checked(r.opened==0 && !r.fail_delete);r.encrypted.clear();}
    void verify_absent(){checked(r.encrypted.empty());}
    void clear(){checked(!r.fail_clear);r.marker=false;}
  } tx{r};
  credential_detail::pending_erase(tx);
}
}
namespace orangespace::platform_session {
using namespace node_session;
inline node_session::detail::NodeEntry storage_key(const PlatformConfig& config){
  (void)credential_detail::validate_origin(config.api_origin());
  node_session::detail::NodeEntry k;k.name=config.api_origin();return k;
}
struct Central final:Transport {
  unsigned status=200;
  Response request(const Bootstrap&,std::string_view method,std::string_view path,std::string_view,std::string_view token) override {
    assert(method=="GET" && path=="/control/v1/session" && token==std::string(43,'A'));
    ++restores;
    return {status,SerializedSecret(R"({"schema":1,"central_session_id":"22222222-2222-4222-8222-222222222222","expires_at":2000,"user":{"central_user_id":"11111111-1111-4111-8111-111111111111","username":"alice","role":"user","enabled":true,"user_epoch":1,"created_at":1}})")};
  }
};
inline Central central;
Session Session::restore(const PlatformConfig& c,std::string_view s){return restore(c,s,central,node_session::now);}
inline std::string envelope(std::string origin="https://control.example.test") {
  return "{\"schema\":1,\"namespace\":\"orangespace.platform.session\",\"api_origin\":\""+origin+"\",\"central_user_id\":\"11111111-1111-4111-8111-111111111111\",\"central_session_id\":\"22222222-2222-4222-8222-222222222222\",\"user_epoch\":1,\"expires_at\":2000,\"access_token\":\""+std::string(43,'A')+"\"}";
}
}
template<class F> void denied(F f){bool bad=false;try{f();}catch(...){bad=true;}assert(bad);}
