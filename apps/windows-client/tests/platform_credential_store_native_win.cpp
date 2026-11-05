// Native current-user DPAPI/NTFS primitive fixture, NOT central HTTPS acceptance.
// Compile this TU + node_session_win.cpp + platform_session_win.cpp; do not also
// link credential_store_win.cpp (included for narrow private primitive access).
#include "../src/credential_store_win.cpp"
#include <iostream>
namespace ps=orangespace::platform_session;
namespace ns=orangespace::node_session;
namespace orangespace::platform_session::detail {
struct TestAccess { static PlatformConfig config(std::string origin) {
  return PlatformConfig(credential_detail::validate_origin(origin));
} };
}
int main() {
#ifdef _WIN32
  try {
    ns::Directory platform(ns::StoreKind::platform); // Naturally creates root.

    unsigned char random[16]{};
    ns::checked(BCryptGenRandom(nullptr,random,sizeof(random),BCRYPT_USE_SYSTEM_PREFERRED_RNG)==0);
    constexpr char hex[]="0123456789abcdef";std::string suffix;
    for(auto c:random){suffix+=hex[c>>4];suffix+=hex[c&15];}
    auto config=ps::detail::TestAccess::config("https://fixture-"+suffix+".invalid");
    auto key=ps::storage_key(config);
    ns::checked(ps::credential_detail::storage_id(key.node_id));
    ns::checked(platform.path.ends_with(L"\\OrangeSpace-Platform-Credentials-v1") && !platform.open(key) && !ns::open_pending(platform,key));
    const auto leaf=platform.filename(key);
    auto prior=ns::relative_file(platform.ancestors.back().get(),leaf+L".lock",READ_CONTROL,0,false);
    ns::checked(!prior);
    struct Cleanup {
      ns::Directory& d;const ns::detail::NodeEntry& key;
      void run(){auto f=d.open(key);if(f)ns::purge(f.get());f.reset();f=ns::open_pending(d,key);if(f)ns::purge(f.get());f.reset();
        const auto leaf=d.filename(key)+L".lock";
        f=ns::relative_file(d.ancestors.back().get(),leaf,DELETE|READ_CONTROL,0,false);if(f)ns::purge(f.get());f.reset();
        ns::checked(!d.open(key) && !ns::open_pending(d,key) && !ns::relative_file(d.ancestors.back().get(),leaf,READ_CONTROL,0,false));}
      ~Cleanup(){try{run();}catch(...){}}
    } cleanup{platform,key};
    {
      ns::NodeLock lock(platform,key,false);
      auto scope=platform.scope(key);
      auto blob=ns::encrypt("noncredential/central-DPAPI-fixture/v1",scope);
      std::string bytes(reinterpret_cast<char*>(blob.value.pbData),blob.value.cbData);
      const auto plain=ns::decrypt(bytes,scope);
      ns::checked(std::string_view(reinterpret_cast<char*>(plain.value.pbData),plain.value.cbData)=="noncredential/central-DPAPI-fixture/v1");
      bool rejected=false;try{(void)ns::decrypt(bytes,scope+"wrong");}catch(...){rejected=true;}ns::checked(rejected);
      ns::detail::NodeEntry old;old.name="fixture";old.node_id="11111111-1111-4111-8111-111111111111";old.host="fixture.invalid";
      auto legacy_scope=ns::credential_detail::entropy(std::string(platform.user.sid_text.begin(),platform.user.sid_text.end()),old);
      rejected=false;try{(void)ns::decrypt(bytes,legacy_scope);}catch(...){rejected=true;}ns::checked(rejected);
      ns::atomic_write(platform,key,blob);ns::atomic_write(platform,key,blob);
      ns::commit_pending(platform,key);
      rejected=false;try{ns::require_not_pending(platform,key);}catch(...){rejected=true;}ns::checked(rejected);
      ns::erase_pending(platform,key);ns::checked(!platform.open(key) && !ns::open_pending(platform,key));
    }
    cleanup.run();
    std::cout<<"platform DPAPI primitives native passed; central HTTPS not tested\n";
    return 0;
  } catch(...) {std::cerr<<"platform DPAPI primitive fixture failed\n";return 1;}
#else
  return 77;
#endif
}
