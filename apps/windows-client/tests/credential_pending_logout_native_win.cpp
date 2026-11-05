// Synthetic crypto/file unit fixture ONLY, never a real NodeSession/HTTPS login.
// Compile this TU plus node_session_win.cpp, not credential_store_win.cpp again.
// Default run creates random UUID fixtures and self-spawns bounded non-GUI child
// processes with nonsecret mode/UUID argv. Requires a limited interactive token.
#include "../src/credential_store_win.cpp"
#include <iostream>
#include <thread>
#include <atomic>
#ifdef _WIN32
namespace ns = orangespace::node_session;
namespace {
constexpr std::string_view synthetic="SYNTHETIC-NOT-CREDENTIAL/pending-logout";
ns::detail::NodeEntry node_for(const std::string& id) {
  ns::checked(ns::detail::uuid(id));
  return {"synthetic-pending",id,"pending-unit.invalid",443};
}
std::string random_id() {
  unsigned char bytes[16]{};
  ns::checked(BCryptGenRandom(nullptr,bytes,sizeof(bytes),BCRYPT_USE_SYSTEM_PREFERRED_RNG)==0);
  std::string id; constexpr char hex[]="0123456789abcdef";
  for(auto c:bytes) {id+=hex[c>>4];id+=hex[c&15];}
  for(auto pos:{8u,13u,18u,23u})id.insert(pos,"-");
  return id;
}
template<class F> void denied(F action) {
  bool failed=false;try {action();}catch(...) {failed=true;}
  ns::checked(failed);
}
std::string read(HANDLE file) {
  LARGE_INTEGER size{};
  ns::checked(GetFileSizeEx(file,&size) && size.QuadPart>0 && size.QuadPart<=65536);
  std::string bytes(static_cast<std::size_t>(size.QuadPart),'\0');DWORD count=0;
  ns::checked(ReadFile(file,bytes.data(),static_cast<DWORD>(bytes.size()),&count,nullptr) && count==bytes.size());
  return bytes;
}
void verify_blob(ns::Directory& directory,const ns::detail::NodeEntry& node) {
  auto file=directory.open(node);ns::checked(file!=nullptr);
  auto bytes=read(file.get());const auto clear=ns::decrypt(bytes,directory.scope(node));
  ns::checked(std::string_view(reinterpret_cast<char*>(clear.value.pbData),clear.value.cbData)==synthetic);
}
void put_blob(ns::Directory& directory,const ns::detail::NodeEntry& node) {
  const auto encrypted=ns::encrypt(synthetic,directory.scope(node));
  ns::atomic_write(directory,node,encrypted);
}
struct Fixture {
  ns::Directory& directory;ns::detail::NodeEntry node;
  ~Fixture() {
    // Only this generated synthetic fixture; this is NOT production recovery.
    for(const auto& leaf:{directory.filename(node),ns::pending_leaf(directory,node),directory.filename(node)+L".lock"}) {
      const auto path=directory.path+L"\\"+leaf;
      DeleteFileW(path.c_str());RemoveDirectoryW(path.c_str());
    }
  }
};
DWORD child(const wchar_t* mode,const std::string& id) {
  wchar_t self[32768]{};
  const auto length=GetModuleFileNameW(nullptr,self,32768);
  ns::checked(length>0 && length<32768);
  std::wstring command=L"\""+std::wstring(self)+L"\" "+mode+L" "+std::wstring(id.begin(),id.end());
  STARTUPINFOW startup{};startup.cb=sizeof(startup);PROCESS_INFORMATION process{};
  ns::checked(CreateProcessW(self,command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&startup,&process)!=FALSE);
  ns::Handle thread(process.hThread),handle(process.hProcess);
  if(WaitForSingleObject(handle.get(),15000)!=WAIT_OBJECT_0) {
    TerminateProcess(handle.get(),99);WaitForSingleObject(handle.get(),5000);ns::fail();
  }
  DWORD result=0;ns::checked(GetExitCodeProcess(handle.get(),&result)!=FALSE);return result;
}
int child_mode(std::string_view mode,const std::string& id) {
  ns::Directory directory;const auto node=node_for(id);
  if(mode=="--lock-denied") {denied([&]{ns::NodeLock lock(directory,node);});return 0;}
  if(mode=="--access-denied") {
    const auto start=GetTickCount64();
    denied([&]{ns::NodeLock lock(directory,node,false);});
    ns::checked(GetTickCount64()-start<1000);return 0;
  }
  ns::NodeLock lock(directory,node);
  if(mode=="--crash") {
    put_blob(directory,node);
    auto held=directory.open(node); // denies DELETE share on original blob
    denied([&]{ns::erase_pending(directory,node);});
    ns::checked(ns::pending(directory,node));held.reset();verify_blob(directory,node);
    // Abrupt OS process termination, no C++ destructors/fixture cleanup.
    ns::checked(TerminateProcess(GetCurrentProcess(),23)!=FALSE);
    return 98;
  }
  if(mode=="--check") {
    ns::checked(ns::pending(directory,node));
    denied([&]{ns::require_not_pending(directory,node);});
    verify_blob(directory,node);return 0;
  }
  return 97;
}
void set_acl(ns::Directory& directory,HANDLE file,bool insecure) {
  const auto sddl=L"D:P(A;;FA;;;SY)(A;;FA;;;"+directory.user.sid_text+L")"+(insecure?L"(A;;FR;;;WD)":L"");
  PSECURITY_DESCRIPTOR descriptor=nullptr;
  ns::checked(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&descriptor,nullptr)!=FALSE);
  ns::Local storage(descriptor);PACL acl=nullptr;BOOL present=FALSE,defaulted=FALSE;
  ns::checked(GetSecurityDescriptorDacl(descriptor,&present,&acl,&defaulted)!=FALSE && present);
  ns::checked(SetSecurityInfo(file,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,
      nullptr,nullptr,acl,nullptr)==ERROR_SUCCESS);
}
}
int main(int argc,char** argv) {
  try {
    if(argc==3)return child_mode(argv[1],argv[2]);
    ns::checked(argc==1);
    ns::Directory directory;
    Fixture a{directory,node_for(random_id())},b{directory,node_for(random_id())};
    const auto& node=a.node;
    ns::checked(child(L"--crash",node.node_id)==23);
    ns::checked(child(L"--check",node.node_id)==0); // separate restarted process
    {
      ns::NodeLock lock(directory,node);
      ns::checked(ns::pending(directory,node));
      denied([&]{ns::require_not_pending(directory,node);}); // load/save shared gate
      verify_blob(directory,node);
      ns::checked(child(L"--lock-denied",node.node_id)==0); // bounded cross-process ownership
      ns::checked(child(L"--access-denied",node.node_id)==0); // access never queues through logout
      ns::erase_pending(directory,node);
      ns::checked(!ns::pending(directory,node) && !directory.open(node));
      ns::erase_pending(directory,node); // idempotent absent-node cleanup
      ns::checked(!ns::pending(directory,node));
    }
    std::cout<<"native crash/reopen/right-entropy/recovery/held-lock: passed\n";
    {
      ns::NodeLock lock(directory,node);put_blob(directory,node);
      ns::commit_pending(directory,node);
      auto other=node;other.host="different-origin.invalid";
      denied([&]{ns::erase_pending(directory,other);});
      ns::checked(ns::pending(directory,node));verify_blob(directory,node);
      ns::Directory node_b;ns::NodeLock lock_b(node_b,b.node);
      ns::require_not_pending(node_b,b.node);put_blob(node_b,b.node);verify_blob(node_b,b.node);
      ns::checked(!ns::pending(node_b,b.node)); // A marker must not affect B
      auto held=directory.open(node);
      std::atomic<int> denied_count{};
      auto contender=[&]{
        try {
          ns::Directory fresh;ns::NodeLock queued(fresh,node,false);
          try {ns::require_not_pending(fresh,node);}catch(...) {++denied_count;}
        }catch(...) {++denied_count;}
      };
      std::thread save(contender),load(contender);
      // This lock remains held; access contenders fail fast, never queue past cleanup.
      save.join();load.join();ns::checked(denied_count==2);
      held.reset();ns::erase_pending(directory,node);
      ns::erase_pending(node_b,b.node);
    }
    std::cout<<"native origin/node isolation and concurrent gate: passed\n";
    {
      ns::NodeLock lock(directory,node);put_blob(directory,node);
      const auto marker=ns::pending_leaf(directory,node);
      // A directory/corrupt marker is unknown state: deny without reset.
      const auto path=directory.path+L"\\"+marker;
      ns::checked(CreateDirectoryW(path.c_str(),&directory.attributes)!=FALSE);
      denied([&]{ns::erase_pending(directory,node);});verify_blob(directory,node);
      denied([&]{ns::require_not_pending(directory,node);});
      ns::checked(RemoveDirectoryW(path.c_str())!=FALSE);
      const auto wrong=ns::encrypt("SYNTHETIC-MALFORMED-LOGOUT-MARKER",directory.scope(node));
      ns::atomic_write_leaf(directory,marker,wrong);
      denied([&]{ns::require_not_pending(directory,node);});
      denied([&]{ns::erase_pending(directory,node);});verify_blob(directory,node);
      // Deny actual atomic marker promotion while its target has no DELETE share.
      auto held=ns::open_pending(directory,node);
      denied([&]{const auto cipher=ns::encrypt(ns::logout_intent,ns::logout_scope(directory,node));
        ns::atomic_write_leaf(directory,marker,cipher);});
      held.reset();
      auto malformed=ns::open_pending(directory,node);ns::purge(malformed.get());malformed.reset();
      ns::commit_pending(directory,node);
      ns::Handle edit=ns::relative_file(directory.ancestors.back().get(),marker,
          READ_CONTROL|WRITE_DAC,FILE_SHARE_READ|FILE_SHARE_DELETE,false);
      ns::checked(edit!=nullptr);set_acl(directory,edit.get(),true);
      denied([&]{ns::require_not_pending(directory,node);});
      denied([&]{ns::erase_pending(directory,node);});verify_blob(directory,node);
      set_acl(directory,edit.get(),false);edit.reset();
      ns::erase_pending(directory,node);
      ns::checked(!ns::pending(directory,node) && !directory.open(node));
      // Reparse negative, if the ordinary user/OS enables unprivileged symlinks.
      const auto target=directory.path+L"\\"+directory.filename(b.node);
      if(CreateSymbolicLinkW(path.c_str(),target.c_str(),0x2)) {
        denied([&]{ns::require_not_pending(directory,node);});
        denied([&]{ns::erase_pending(directory,node);});
        ns::checked(DeleteFileW(path.c_str())!=FALSE);
        std::cout<<"native reparse marker denial: passed\n";
      } else {
        const auto error=GetLastError();
        ns::checked(error==ERROR_PRIVILEGE_NOT_HELD || error==ERROR_INVALID_PARAMETER);
        std::cout<<"SKIP native symlink marker: ordinary-user creation unavailable\n";
      }
    }
    std::cout<<"native failed commit/malformed/ACL marker deny and exact recovery: passed\n";
    // Verify all fixture data absent; persistent production lock leaves are empty
    // and private. These fixture-only lock leaves are removed after releasing.
    for(const auto* fixture:{&a,&b}) {
      ns::checked(!directory.open(fixture->node) && !ns::pending(directory,fixture->node));
      const auto path=directory.path+L"\\"+directory.filename(fixture->node)+L".lock";
      ns::checked(DeleteFileW(path.c_str())!=FALSE);
      ns::checked(GetFileAttributesW(path.c_str())==INVALID_FILE_ATTRIBUTES && GetLastError()==ERROR_FILE_NOT_FOUND);
    }
    directory.verify();std::cout<<"native synthetic fixture cleanup: passed\n";
    return 0;
  } catch(...) {std::cerr<<"native pending logout fixture failed (no credentials logged)\n";return 1;}
}
#endif
