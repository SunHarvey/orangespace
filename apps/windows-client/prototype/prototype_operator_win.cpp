#include "orangespace/platform_session.hpp"
#include "orangespace/platform_credential_store.hpp"
#include "orangespace/service_client.hpp"
#include <windows.h>
#include <wincred.h>
#include <bcrypt.h>
#include <cstdio>
#include <optional>
#ifndef ORANGESPACE_PROTOTYPE_NODE_UUID
#error Prototype requires the trusted build-selected SG node UUID
#endif
// OPERATOR_INPUT_BEGIN
namespace prototype_input {
namespace nd=orangespace::node_session::detail;
// Same bounded two-line guard as the existing SDK login diagnostic. Bytes are
// owned/wiped even when validation, allocation or the actual login throws.
struct Input {
  std::vector<char> bytes;
  Input()=default;Input(const Input&)=delete;
  Input(Input&& other) noexcept {bytes.swap(other.bytes);}
  ~Input(){nd::wipe(bytes.data(),bytes.size());}
  std::string_view view()const{return {bytes.data(),bytes.size()};}
};
template<class Read> Input line(Read read,std::size_t limit) {
  Input value;value.bytes.reserve(limit);
  struct Byte{char c{};~Byte(){nd::wipe(&c,1);}}byte;
  for(std::size_t n=0;n<=limit;++n) {
    nd::require(read(byte.c));
    if(byte.c=='\n') {nd::require(!value.bytes.empty()&&nd::safe_utf8(value.view(),true));return value;}
    nd::require(n<limit&&static_cast<unsigned char>(byte.c)>=32&&byte.c!=127);
    value.bytes.push_back(byte.c);
  }
  throw std::runtime_error("invalid bounded input");
}
}
// OPERATOR_INPUT_END
namespace {
namespace ps=orangespace::platform_session;
namespace sc=orangespace::service_client;
namespace nd=orangespace::node_session::detail;
void ordinary_user() {
  // SDK rejects thread impersonation and session 0, without process fallback.
  nd::require(sc::current_interactive_session().has_value());
  struct Token{HANDLE h{};~Token(){if(h)CloseHandle(h);}}token;
  nd::require(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token.h));
  TOKEN_ELEVATION elevation{};DWORD size{};
  nd::require(GetTokenInformation(token.h,TokenElevation,&elevation,sizeof(elevation),&size)&&!elevation.TokenIsElevated);
  BYTE sid[SECURITY_MAX_SID_SIZE]{};DWORD sid_size=sizeof(sid);BOOL interactive=FALSE;
  nd::require(CreateWellKnownSid(WinInteractiveSid,nullptr,sid,&sid_size)&&CheckTokenMembership(nullptr,sid,&interactive)&&interactive);
  sid_size=sizeof(sid);BOOL admin=TRUE;
  nd::require(CreateWellKnownSid(WinBuiltinAdministratorsSid,nullptr,sid,&sid_size)&&CheckTokenMembership(nullptr,sid,&admin)&&!admin);
}
std::wstring config_path() {
  wchar_t module[32768]{};const DWORD size=GetModuleFileNameW(nullptr,module,32768);
  nd::require(size&&size<32768);std::wstring path(module,size);auto end=path.rfind(L'\\');
  nd::require(end!=std::wstring::npos);path.resize(end+1);return path+L"platform.json";
}
ps::Session dialog_login(const ps::PlatformConfig& config) {
  // Ordinary-user native input only; no credential files, IPC or token launch.
  struct Fields {
    wchar_t user[257]{},password[1025]{};
    ~Fields(){SecureZeroMemory(user,sizeof(user));SecureZeroMemory(password,sizeof(password));}
  } fields;
  CREDUI_INFOW ui{};ui.cbSize=sizeof(ui);
  ui.pszCaptionText=L"OrangeSpace";
  ui.pszMessageText=L"登录中心并连接已授权的新加坡节点";
  BOOL save=FALSE;
  const DWORD result=CredUIPromptForCredentialsW(&ui,L"OrangeSpace",nullptr,0,
      fields.user,DWORD(std::size(fields.user)),fields.password,DWORD(std::size(fields.password)),
      &save,CREDUI_FLAGS_GENERIC_CREDENTIALS|CREDUI_FLAGS_DO_NOT_PERSIST|CREDUI_FLAGS_ALWAYS_SHOW_UI);
  nd::require(result==NO_ERROR&&!save);
  const auto convert=[](const wchar_t* text,std::size_t limit){
    prototype_input::Input value;const int length=int(wcslen(text));
    const int bytes=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,text,length,nullptr,0,nullptr,nullptr);
    nd::require(bytes>0&&std::size_t(bytes)<=limit);value.bytes.resize(std::size_t(bytes));
    nd::require(WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,text,length,value.bytes.data(),bytes,nullptr,nullptr)==bytes&&nd::safe_utf8(value.view(),true));
    return value;
  };
  auto username=convert(fields.user,256),password=convert(fields.password,1024);
  return ps::Session::login(config,username.view(),password.view());
}
std::string uuid() {
  std::array<unsigned char,16> bytes{};
  nd::require(BCryptGenRandom(nullptr,bytes.data(),static_cast<ULONG>(bytes.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG)==0);
  bytes[6]=(bytes[6]&0x0f)|0x40;bytes[8]=(bytes[8]&0x3f)|0x80;
  std::string out;out.reserve(36);
  for(std::size_t i=0;i<bytes.size();++i){if(i==4||i==6||i==8||i==10)out+='-';out+="0123456789abcdef"[bytes[i]>>4];out+="0123456789abcdef"[bytes[i]&15];}
  return out;
}
}
int wmain(int argc,wchar_t** argv) {
  std::optional<sc::Grant> grant;
  std::optional<orangespace::service::chain::Binding> binding;
  std::optional<ps::Session> session;
  bool own_login=false,cached_failure=false;
  try {
    ordinary_user();
    const bool login_stdin=argc==2&&std::wstring_view(argv[1])==L"--login-stdin";
    const bool login_dialog=argc==2&&std::wstring_view(argv[1])==L"--login-dialog";
    nd::require(argc==1||login_stdin||login_dialog);
    nd::require(nd::uuid(ORANGESPACE_PROTOTYPE_NODE_UUID));
    const auto config=ps::PlatformConfig::load(config_path());
    if(login_stdin) {
      const auto input=GetStdHandle(STD_INPUT_HANDLE);nd::require(GetFileType(input)==FILE_TYPE_PIPE);
      auto read=[&](char& c){DWORD n{};return ReadFile(input,&c,1,&n,nullptr)&&n==1;};
      auto username=prototype_input::line(read,256),password=prototype_input::line(read,1024);
      session.emplace(ps::Session::login(config,username.view(),password.view()));own_login=true;
    } else if(login_dialog) {
      session.emplace(dialog_login(config));own_login=true;
    } else {
      try{session.emplace(ps::CredentialStore::load(config));}catch(...){cached_failure=true;throw;}
    }
    const auto nodes=session->nodes();const ps::NodeRef* selected=nullptr;
    for(const auto& node:nodes)if(node.node_id==ORANGESPACE_PROTOTYPE_NODE_UUID){nd::require(!selected);selected=&node;}
    nd::require(selected);
    const auto local=uuid(); // all local identifier allocation before authorization
    grant.emplace(sc::authorize_platform(*session,*selected));
    const auto cursor=sc::register_sandbox(*grant,local);
    binding.emplace(sc::start_tunnel(*grant,cursor));
    // Typed SDK start already validated the full tuple/proof before ACK. The
    // Service independently owns adoption + fresh proof + private channel take.
    // Keep cache and central session alive: logout here would fence management.
    std::fputs("请求已接受\n",stdout);
    return 0;
  } catch(...) {
    if(grant) {
      if(binding)try{(void)sc::stop_tunnel(*grant,*binding);}catch(...){}
      try{sc::retire(*grant);}catch(...){}
    }
    // Only a fresh login created by this process may be remotely logged out.
    // Never erase/persist or logout the shared management program's cache.
    if(own_login&&session)try{session->logout();}catch(...){}
    std::fputs(cached_failure?"请先在管理程序正常登录\n":"请求失败\n",stderr);
    return 1;
  }
}
