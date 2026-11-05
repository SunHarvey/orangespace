#include "orangespace/broker_win.hpp"
#include "orangespace/model.hpp"
#include "orangespace/node_session.hpp"
#include "orangespace/platform_workspace.hpp"
#include "orangespace/platform_session.hpp"
#include "orangespace/service_client.hpp"
#include "orangespace/browser_session.hpp"
#include <sddl.h>
#include <userenv.h>
#include "../../windows-service/include/orangespace/install_identity.hpp"
#include "orangespace/platform_credential_store.hpp"
#include "orangespace/ui_lifecycle.hpp"
#include "orangespace/ui_v2.hpp"
#include "orangespace/file_transfer.hpp"
#include "orangespace/file_manager_win.hpp"
#include <objidl.h>
#include <gdiplus.h>
#include <filesystem>

#include <commctrl.h>
#include <windowsx.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <thread>

namespace {
namespace ns = orangespace::node_session;
namespace sc = orangespace::service_client;
namespace ps = orangespace::platform_session;
namespace bs = orangespace::browser_session;
// The only automatic USER-object exception: the Service's exact derived package
// SID on this process's current interactive station, WINSTA_CREATEDESKTOP=8.
// Original DACL retained, read back, and restored only without intervening drift.
class InstanceStationRight {
  std::vector<BYTE> before_,after_;
  static std::vector<BYTE> read() {
    SECURITY_INFORMATION info=DACL_SECURITY_INFORMATION;DWORD size{};
    GetUserObjectSecurity(GetProcessWindowStation(),&info,nullptr,0,&size);
    if(!size || size>65536)throw std::runtime_error("station-descriptor-size");
    std::vector<BYTE> value(size);
    if(!GetUserObjectSecurity(GetProcessWindowStation(),&info,value.data(),size,&size))throw std::runtime_error("station-read");
    return value;
  }
  static PACL acl(const std::vector<BYTE>& value) {
    BOOL present{},defaulted{};PACL result{};
    if(!GetSecurityDescriptorDacl(const_cast<BYTE*>(value.data()),&present,&result,&defaulted) || !present || !result || !IsValidAcl(result))
      throw std::runtime_error("station-dacl");
    return result;
  }
  static bool same(const std::vector<BYTE>& a,const std::vector<BYTE>& b) {
    const auto x=acl(a),y=acl(b);
    if(x->AclRevision!=y->AclRevision || x->AceCount!=y->AceCount)return false;
    for(DWORD i=0;i<x->AceCount;++i) {void* left{};void* right{};
      if(!GetAce(x,i,&left)||!GetAce(y,i,&right))return false;
      const auto n=static_cast<ACE_HEADER*>(left)->AceSize;
      if(n!=static_cast<ACE_HEADER*>(right)->AceSize || std::memcmp(left,right,n))return false;
    }
    return true;
  }
 public:
  bool active() const noexcept {return !before_.empty();}
  void grant(const bs::State& state) {
    if(active())throw std::runtime_error("station-already-owned");
    auto session=sc::current_interactive_session();if(!session)throw std::runtime_error("station-session");
    PSID derived{},claimed{};
    if(FAILED(DeriveAppContainerSidFromAppContainerName(orangespace::widen(state.profile_name).c_str(),&derived)))throw std::runtime_error("station-profile");
    struct SidOwner{PSID p;~SidOwner(){if(p)FreeSid(p);}} owner{derived};
    if(!ConvertStringSidToSidW(orangespace::widen(state.package_sid).c_str(),&claimed))throw std::runtime_error("station-sid");
    struct LocalOwner{PSID p;~LocalOwner(){if(p)LocalFree(p);}} claim{claimed};
    if(!EqualSid(derived,claimed))throw std::runtime_error("station-sid-mismatch");
    auto before=read();const auto old=acl(before);
    const DWORD length=old->AclSize+sizeof(ACCESS_ALLOWED_ACE)-sizeof(DWORD)+GetLengthSid(derived);
    if(length>65535)throw std::runtime_error("station-acl-size");
    std::vector<BYTE> next(length);auto target=reinterpret_cast<PACL>(next.data());
    if(!InitializeAcl(target,length,ACL_REVISION))throw std::runtime_error("station-acl-init");
    for(DWORD i=0;i<old->AceCount;++i) {void* ace{};if(!GetAce(old,i,&ace) || !AddAce(target,ACL_REVISION,MAXDWORD,ace,static_cast<ACE_HEADER*>(ace)->AceSize))throw std::runtime_error("station-ace-copy");}
    if(!AddAccessAllowedAceEx(target,ACL_REVISION,0,WINSTA_CREATEDESKTOP,derived))throw std::runtime_error("station-ace");
    SECURITY_DESCRIPTOR descriptor{};InitializeSecurityDescriptor(&descriptor,SECURITY_DESCRIPTOR_REVISION);
    if(!SetSecurityDescriptorDacl(&descriptor,TRUE,target,FALSE))throw std::runtime_error("station-descriptor");
    // Allocate original + expected descriptors before changing external state.
    std::vector<BYTE> after(65536);DWORD relative_size=static_cast<DWORD>(after.size());
    if(!MakeSelfRelativeSD(&descriptor,after.data(),&relative_size))throw std::runtime_error("station-relative");
    before_=std::move(before);after_=std::move(after);
    SECURITY_INFORMATION info=DACL_SECURITY_INFORMATION;
    if(!SetUserObjectSecurity(GetProcessWindowStation(),&info,&descriptor)){before_.clear();after_.clear();throw std::runtime_error("station-set");}
    const auto observed=read();
    const auto actual=acl(observed);
    if(actual->AceCount!=target->AceCount)throw std::runtime_error("station-readback-count");
    for(DWORD i=0;i<target->AceCount;++i){void* x{};void* y{};if(!GetAce(target,i,&x)||!GetAce(actual,i,&y)||static_cast<ACE_HEADER*>(x)->AceSize!=static_cast<ACE_HEADER*>(y)->AceSize||std::memcmp(x,y,static_cast<ACE_HEADER*>(x)->AceSize))throw std::runtime_error("station-readback-ace");}
  }
  bool restore() noexcept {
    if(!active())return true;
    try {
      if(!same(read(),after_))return false;
      SECURITY_INFORMATION info=DACL_SECURITY_INFORMATION;
      if(!SetUserObjectSecurity(GetProcessWindowStation(),&info,before_.data()) || !same(read(),before_))return false;
      before_.clear();after_.clear();return true;
    } catch (...) {return false;}
  }
};
using Auth = orangespace::PlatformWorkspace<ps::Session, ps::NodeRef>;
std::int64_t now() {
  return std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
}
enum Control : int { TrustPath = 100, LoadTrust, Alias, Username, Password, Login, Logout,
  Refresh, SandboxList, Name, Create, Bind, Open, Close, Delete, Connect, Stop, Remember, AddTab, Files, Menu, BackToBrowser, Navigate, BrowserBack, BrowserForward, BrowserReload };
enum class Job { catalog, login, broker, tunnel, open_node };
// Grant ownership begins at authorization completion, including stale results.
// No destructor starts detached work: the application drain awaits all owners.
struct TunnelLease {
  std::shared_ptr<sc::Grant> grant;
  orangespace::service::chain::Binding binding;
  std::string local;
  // Presentation only: timestamps never extend Service permit/lease authority.
  std::chrono::steady_clock::time_point status_at{},next_status{};
  bool status_known{},status_live{};
  std::optional<sc::TunnelDiagnosticDTO> diagnostic;
  std::optional<bs::State> browser;
  std::chrono::steady_clock::time_point browser_at{};
  bool browser_close_requested{}; // Queue acknowledgement is not process exit.
};
struct BrowserMailbox {
  std::mutex mutex;bool done{};
  std::shared_ptr<TunnelLease> lease;
  std::uint64_t generation{};
  std::chrono::steady_clock::time_point requested{};
  std::optional<bs::State> state;
};
struct StatusMailbox {
  std::mutex mutex;
  bool done{},known{},live{},had_diagnostic{};
  std::int64_t prior_deadline{},prior_expiry{},prior_observed{};
  orangespace::service::chain::Binding binding;
  std::optional<sc::TunnelDiagnosticDTO> diagnostic;
  std::shared_ptr<TunnelLease> lease;
  std::uint64_t generation{};
  std::chrono::steady_clock::time_point requested{};
};
struct Completion {
  Job job{};
  std::uint64_t generation{};
  Auth::LoginTicket login{};
  Auth::Operation operation{};
  std::unique_ptr<ps::PlatformConfig> catalog;
  std::unique_ptr<ps::Session> session;
  std::vector<ps::NodeRef> nodes;
  orangespace::PlatformRows::Ticket row_ticket;
  std::vector<orangespace::Sandbox> sandboxes;
  bool stopped{};
  std::shared_ptr<sc::Grant> grant;
  std::shared_ptr<TunnelLease> tunnel;
  std::string local_sandbox;
  std::optional<orangespace::service::chain::Cursor> cursor;
  orangespace::ProcessResult process;
  bool remember{}, automatic{}, close_tab{};
  bool refresh{};
  bool failed{};
};
// Workers never touch an HWND. The single worker is joined before consuming its
// result, draining owned grants, destroying the window or returning from main.
struct Mailbox {
  std::mutex mutex;
  std::unique_ptr<Completion> result;
  std::atomic<bool> cancelled{false};
};
struct PasswordBuffer {
  std::vector<wchar_t> wide;
  std::vector<char> utf8;
  ~PasswordBuffer() {
    ns::detail::wipe(wide.data(), wide.size() * sizeof(wchar_t));
    ns::detail::wipe(utf8.data(), utf8.size());
  }
  PasswordBuffer(const PasswordBuffer&) = delete;
  PasswordBuffer() = default;
  std::string_view view() const { return {utf8.data(), utf8.size()}; }
};

class Application {
 public:
  HWND window{};
  void finish_before_return() {
    begin_close();
    if(worker_.joinable())worker_.join();
    if(status_worker_.joinable())status_worker_.join();
    status_mailbox_.reset();
    if(browser_worker_.joinable())browser_worker_.join();
    browser_mailbox_.reset();
    // The final-return path can bypass timer adoption. A successful login that
    // finished after explicit logout still needs its own central revoke attempt.
    if(logout_requested_ && mailbox_ && mailbox_->result && mailbox_->result->session && !central_cleanup_) {
      central_cleanup_=std::shared_ptr<ps::Session>(std::move(mailbox_->result->session));
    }
    // Preserve the exact late/failed browser binding before discarding its result.
    if(mailbox_ && mailbox_->result && mailbox_->result->tunnel &&
       std::find(pending_stops_.begin(),pending_stops_.end(),mailbox_->result->tunnel)==pending_stops_.end())
      pending_stops_.push_back(mailbox_->result->tunnel);
    mailbox_.reset();busy_=false;
    // Every attempt is bounded by the typed pipe client. An unresolved service
    // or credential deletion keeps this process alive; it is not a success.
    while(!drain_->ready() || logout_state_.restore_blocked() || (file_panel_ && !file_panel_->can_close()) || browser_process_ || station_.active()) {
      browser_view();
      if(file_panel_)file_panel_->poll();
      cleanup_step();
      if(!drain_->ready() || logout_state_.restore_blocked() || (file_panel_ && !file_panel_->can_close()) || browser_process_ || station_.active())Sleep(1000);
    }
  }
  LRESULT message(UINT message, WPARAM wparam, LPARAM lparam) {
    switch (message) {
      case WM_CREATE: create_controls(); SetTimer(window, 1, 100, nullptr); load_automatic_config(); return 0;
      case WM_TIMER: poll(); return 0;
      case orangespace::files::ReturnToBrowserMessage: command(BackToBrowser); return 0;
      case WM_SIZE: layout(); return 0;
      case WM_GETMINMAXINFO: {
        auto* info = reinterpret_cast<MINMAXINFO*>(lparam);
        info->ptMinTrackSize = {px(720), px(580)}; return 0;
      }
      case WM_DRAWITEM: draw_button(*reinterpret_cast<DRAWITEMSTRUCT*>(lparam)); return TRUE;
      case WM_COMMAND:
        if (LOWORD(wparam) == Alias && HIWORD(wparam) == CBN_SELCHANGE && !draining_ && !closing_) {
          if(!busy_) { auth_.select(alias()); ++generation_; sync_identity(); }
        } else if (HIWORD(wparam) == BN_CLICKED) {
          try { command(LOWORD(wparam)); }
          catch (...) { notice(L"操作未完成；请检查输入和本机组件。", true); }
        }
        return 0;
      case WM_NOTIFY:
        if (reinterpret_cast<NMHDR*>(lparam)->idFrom == SandboxList) update_detail();
        return 0;
      case WM_CLOSE:
        begin_close(); return 0;
      case WM_QUERYENDSESSION:
        begin_close();
        // Veto a cooperative logoff until the bounded IPC attempts have actually
        // retired local grants. Windows forced termination cannot be prevented.
        return !busy_ && drain_->ready() && !logout_state_.restore_blocked() && (!file_panel_ || file_panel_->can_close());
      case WM_ENDSESSION:
        if (wparam) { begin_close(); finish_before_return(); }
        return 0;
      case WM_DESTROY:
        // Defensive path for a direct DestroyWindow, bypassing WM_CLOSE.
        begin_close(); finish_before_return();
        KillTimer(window, 1);
        if (font_) DeleteObject(font_);
        if (title_font_) DeleteObject(title_font_);
        if (background_) DeleteObject(background_);
        destroyed_=true;
        PostQuitMessage(0); return 0;
      case WM_CTLCOLORSTATIC: {
        auto dc = reinterpret_cast<HDC>(wparam); SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, RGB(66, 47, 36)); return reinterpret_cast<LRESULT>(background_);
      }
      case WM_ERASEBKGND: {
        RECT rect{}; GetClientRect(window, &rect);
        FillRect(reinterpret_cast<HDC>(wparam), &rect, background_); return 1;
      }
      case WM_PAINT: paint(); return 0;
      case WM_DPICHANGED: {
        const auto* rect = reinterpret_cast<RECT*>(lparam);
        SetWindowPos(window, nullptr, rect->left, rect->top, rect->right - rect->left,
                     rect->bottom - rect->top, SWP_NOZORDER);
        layout(); return 0;
      }
    }
    return DefWindowProcW(window, message, wparam, lparam);
  }
 private:
  int px(int value) const { return MulDiv(value, static_cast<int>(GetDpiForWindow(window)), 96); }
  HWND control(const wchar_t* kind, const wchar_t* title, DWORD style, int id = 0) {
    auto handle = CreateWindowExW(std::wstring_view(kind) == L"EDIT" ? WS_EX_CLIENTEDGE : 0,
        kind, title, WS_CHILD | WS_VISIBLE | style, 0, 0, 0, 0, window,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
    SendMessageW(handle, WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE); return handle;
  }
  HWND label(const wchar_t* title) { return control(L"STATIC", title, SS_LEFT); }
  HWND button(const wchar_t* title, int id) { return control(L"BUTTON", title, WS_TABSTOP | BS_PUSHBUTTON, id); }
  HWND edit(int id, int limit, DWORD extra = 0) {
    auto h = control(L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL | extra, id);
    SendMessageW(h, EM_SETLIMITTEXT, limit, 0); return h;
  }
  void create_controls() {
    background_ = CreateSolidBrush(RGB(247,248,250));
    font_ = CreateFontW(-px(14),0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,
      OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Microsoft YaHei UI");
    title_font_ = CreateFontW(-px(26),0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,
      OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Microsoft YaHei UI");
    // Legacy controller handles remain private implementation details, never an engineering table.
    trust_label_=label(L""); trust_=label(L""); load_=button(L"",LoadTrust);
    alias_label_=label(L""); alias_=control(WC_COMBOBOXW,L"",CBS_DROPDOWNLIST,Alias);
    username_label_=label(L"账号"); username_=edit(Username,64);
    password_label_=label(L"密码"); password_=edit(Password,1024,ES_PASSWORD);
    SendMessageW(username_,EM_SETCUEBANNER,TRUE,reinterpret_cast<LPARAM>(L"请输入账号"));
    remember_=control(L"BUTTON",L"记住登录",WS_TABSTOP|BS_AUTOCHECKBOX,Remember);
    login_=control(L"BUTTON",L"登录",WS_TABSTOP|BS_OWNERDRAW,Login);
    logout_=button(L"退出登录",Logout); identity_=label(L""); refresh_=button(L"刷新节点",Refresh);
    list_=control(WC_LISTVIEWW,L"",LVS_SINGLESEL,SandboxList);
    name_label_=label(L""); name_=edit(Name,80); create_=button(L"",Create);
    node_label_=label(L""); node_=label(L""); bind_=button(L"",Bind);
    open_=button(L"",Open); connect_=button(L"",Connect); stop_=button(L"",Stop);
    close_=button(L"关闭标签",Close); delete_=button(L"删除沙盒",Delete);
    detail_=label(L""); files_=label(L""); notice_=label(L"正在读取受保护配置…");
    add_=button(L"＋",AddTab); file_button_=button(L"文件",Files); menu_=button(L"···",Menu);
    address_=edit(Navigate,2048);
    SendMessageW(address_,EM_SETCUEBANNER,TRUE,reinterpret_cast<LPARAM>(L"输入 HTTPS 或 HTTP 网址"));
    SetWindowSubclass(address_,[](HWND h,UINT m,WPARAM w,LPARAM l,UINT_PTR,DWORD_PTR owner)->LRESULT {
      if(m==WM_GETDLGCODE)return DLGC_WANTALLKEYS;
      if(m==WM_KEYDOWN && w==VK_RETURN){SendMessageW(reinterpret_cast<HWND>(owner),WM_COMMAND,MAKEWPARAM(Navigate,BN_CLICKED),0);return 0;}
      return DefSubclassProc(h,m,w,l);
    },1,reinterpret_cast<DWORD_PTR>(window));
    back_=button(L"←",BrowserBack);forward_=button(L"→",BrowserForward);reload_=button(L"↻",BrowserReload);
    browser_host_=control(L"STATIC",L"",SS_BLACKRECT);ShowWindow(browser_host_,SW_HIDE);
    for(auto h:{address_,back_,forward_,reload_})EnableWindow(h,FALSE);
    return_=button(L"返回浏览器",BackToBrowser);
    sync_identity(); layout();
  }
  void load_automatic_config() {
    std::wstring executable(32768,L'\0');
    const auto count=GetModuleFileNameW(nullptr,executable.data(),static_cast<DWORD>(executable.size()));
    if(!count || count>=executable.size()) {notice(L"配置不可用，请联系管理员。");return;}
    executable.resize(count);
    auto path=(std::filesystem::path(executable).parent_path() / L"platform.json").wstring();
    start([path=std::move(path)](Completion& out,Mailbox&) {
      out.job=Job::catalog;out.catalog.reset(new ps::PlatformConfig(ps::PlatformConfig::load(path)));
    });
  }
  void place(HWND h,int x,int y,int width,int height) {MoveWindow(h,px(x),px(y),px(std::max(0,width)),px(std::max(0,height)),TRUE);}
  void layout() {
    if(!list_)return;
    RECT r{};GetClientRect(window,&r);
    const int w=MulDiv(r.right,96,static_cast<int>(GetDpiForWindow(window)));
    const int h=MulDiv(r.bottom,96,static_cast<int>(GetDpiForWindow(window)));
    for(auto control:{trust_label_,trust_,load_,alias_label_,alias_,username_label_,username_,password_label_,password_,
      remember_,login_,logout_,identity_,refresh_,list_,name_label_,name_,create_,node_label_,node_,bind_,open_,connect_,stop_,
      close_,delete_,detail_,files_,add_,file_button_,menu_,address_,back_,forward_,reload_,return_})ShowWindow(control,SW_HIDE);
    for(auto c:node_buttons_)ShowWindow(c,SW_HIDE);
    for(auto c:node_menus_)ShowWindow(c,SW_HIDE);
    for(auto c:tab_buttons_)ShowWindow(c,SW_HIDE);
    for(auto c:tab_closes_)ShowWindow(c,SW_HIDE);
    const bool logged=auth_.active(now())!=nullptr;
    auto show=[&](HWND c,int x,int y,int cw,int ch){place(c,x,y,cw,ch);ShowWindow(c,SW_SHOW);};
    if(!logged) {
      const int x=(w-400)/2,y=std::max(24,(h-470)/2);
      show(username_label_,x+32,y+180,336,22);show(username_,x+32,y+207,336,38);
      show(password_label_,x+32,y+260,336,22);show(password_,x+32,y+287,336,38);
      show(remember_,x+32,y+339,336,26);show(login_,x+32,y+381,336,42);
      show(notice_,x-20,y+480,440,46);
      if(file_panel_)file_panel_->hide();
    } else {
      show(identity_,std::max(20,w-330),16,190,28);show(logout_,w-125,12,105,30);
      if(choosing_node_ || tabs_.empty()) {
        show(refresh_,w-130,55,110,30);
        const int columns=std::max(1,(w-80)/280), cardw=250,cardh=230;
        const int count=static_cast<int>(node_buttons_.size());
        const int used=std::min(columns,std::max(1,count));
        const int left=(w-(used*cardw+(used-1)*20))/2;
        for(int i=0;i<count;++i) {
          show(node_buttons_[static_cast<std::size_t>(i)],left+(i%columns)*270,190+(i/columns)*250,cardw,cardh);
          show(node_menus_[static_cast<std::size_t>(i)],left+(i%columns)*270+cardw-40,198+(i/columns)*250,32,28);
        }
        show(notice_,40,h-54,w-80,44);
        if(file_panel_)file_panel_->hide();
      } else {
        int tx=12;const int tw=std::min(230,std::max(100,(w-100)/std::max(1,static_cast<int>(tabs_.size()))));
        for(std::size_t i=0;i<tab_buttons_.size();++i){show(tab_buttons_[i],tx,10,tw-28,38);show(tab_closes_[i],tx+tw-28,10,28,38);tx+=tw+4;}
        show(add_,std::min(tx,w-60),10,42,38);
        show(back_,12,64,32,32);show(forward_,48,64,32,32);show(reload_,84,64,32,32);
        show(address_,126,64,w-460,34);show(node_,w-324,68,170,32);
        show(file_button_,w-146,64,80,34);show(menu_,w-58,64,44,34);
        ShowWindow(identity_,SW_HIDE);ShowWindow(logout_,SW_HIDE);
        show(close_,12,h-48,110,30);show(notice_,138,h-48,w-155,42);
        show(detail_,std::max(30,(w-580)/2),std::max(170,h/2),580,100);
        if(file_view_ && file_panel_) {
          ShowWindow(detail_,SW_HIDE);show(return_,16,112,130,32);
          MoveWindow(file_panel_->window(),px(12),px(154),px(w-24),px(std::max(0,h-210)),TRUE);
        } else if(file_panel_)file_panel_->hide();
      }
    }
    browser_view();
    InvalidateRect(window,nullptr,TRUE);
  }
  void draw_button(const DRAWITEMSTRUCT& item) {
    RECT r=item.rcItem;const bool primary=item.CtlID==Login;
    auto brush=CreateSolidBrush(primary ? RGB(255,122,22) : RGB(255,255,255));
    FillRect(item.hDC,&r,brush);DeleteObject(brush);
    auto pen=CreatePen(PS_SOLID,1,RGB(226,229,234));auto oldpen=SelectObject(item.hDC,pen);
    auto oldbrush=SelectObject(item.hDC,GetStockObject(NULL_BRUSH));RoundRect(item.hDC,r.left,r.top,r.right,r.bottom,px(8),px(8));
    SelectObject(item.hDC,oldbrush);SelectObject(item.hDC,oldpen);DeleteObject(pen);
    SetBkMode(item.hDC,TRANSPARENT);SetTextColor(item.hDC,primary ? RGB(255,255,255) : RGB(35,42,52));
    SelectObject(item.hDC,font_);auto title=text(item.hwndItem);
    InflateRect(&r,-px(20),-px(16));
    DrawTextW(item.hDC,title.c_str(),-1,&r,DT_CENTER|DT_WORDBREAK|(primary ? DT_VCENTER|DT_SINGLELINE : 0));
    if(item.itemState&ODS_FOCUS)DrawFocusRect(item.hDC,&r);
  }
  void rebuild_tabs() {
    for(auto c:tab_buttons_)DestroyWindow(c);
    tab_buttons_.clear();
    for(auto c:tab_closes_)DestroyWindow(c);
    tab_closes_.clear();
    for(std::size_t i=0;i<tabs_.size();++i) {
      const auto row=std::find_if(sandboxes_.begin(),sandboxes_.end(),[&](const auto& v){return v.id==tabs_[i];});
      auto title=row==sandboxes_.end() ? L"沙盒" : orangespace::widen(row->name);
      if(tabs_[i]==active_sandbox_)title=L"● "+title;
      tab_buttons_.push_back(button(title.c_str(),2000+static_cast<int>(i)));
      tab_closes_.push_back(button(L"×",3000+static_cast<int>(i)));
    }
    layout();
  }
  void rebuild_nodes() {
    for(auto c:node_buttons_)DestroyWindow(c);
    node_buttons_.clear();
    for(auto c:node_menus_)DestroyWindow(c);
    node_menus_.clear();
    // Reserve both handle vectors before creating either member of a pair.
    node_buttons_.reserve(auth_.nodes().size());
    node_menus_.reserve(auth_.nodes().size());
    for(std::size_t i=0;i<auth_.nodes().size();++i) {
      const auto& n=auth_.nodes()[i];
      auto title=orangespace::widen(n.display_name.empty() ? n.alias : n.display_name)+(browser_enabled(n.node_id)?L"\r\n\r\n已获授权 · 可用性待连接验证\r\n\r\n打开沙盒 →":L"\r\n\r\n已获授权 · 浏览暂不可用");
      node_buttons_.push_back(control(L"BUTTON",title.c_str(),WS_TABSTOP|BS_OWNERDRAW,1000+static_cast<int>(i)));
      node_menus_.push_back(button(L"···",4000+static_cast<int>(i)));
    }
    layout();
  }
  std::wstring text(HWND handle) const {
    const int count = GetWindowTextLengthW(handle);
    std::wstring out(static_cast<std::size_t>(count) + 1, L'\0');
    GetWindowTextW(handle, out.data(), count + 1); out.resize(count); return out;
  }
  std::string alias() const { return orangespace::narrow(text(alias_)); }
  void notice(const std::wstring& value, bool error = false) {
    SetWindowTextW(notice_, value.c_str());
    if (error) MessageBoxW(window, value.c_str(), L"橙域 OrangeSpace", MB_OK | MB_ICONINFORMATION);
  }
  // Callback failure reports must contain both message construction and display
  // failures. A lost notice must never unwind past the retained cleanup owner.
  void notice(const wchar_t* value, bool error = false) noexcept {
    try {notice(std::wstring(value),error);} catch (...) {}
  }
  void clear_rows() {
    sandboxes_.clear(); ListView_DeleteAllItems(list_); SetWindowTextW(detail_, L"请选择工作区中的沙盒。");
  }
  std::optional<orangespace::Sandbox> selection() const {
    for(const auto& row:sandboxes_)if(row.id==active_sandbox_)return row;
    return {};
  }
  void update_detail() {
    auto row=selection();if(!row)return;
    auto value=orangespace::widen(row->name)+L"\r\n正在等待受保护服务的浏览会话。";
    SetWindowTextW(detail_,value.c_str());
  }
  void render_proofs() {
    auto row=selection();if(!row)return;
    const auto* n=auth_.node(row->node_id,now());
    std::wstring state=L" · 状态未知";
    if(rows_.state(row->id)==orangespace::PlatformRows::State::starting)state=L" · 连接中";
    else if(rows_.state(row->id)==orangespace::PlatformRows::State::failed)state=L" · 连接失败";
    else if(auto i=tunnels_.find(row->id);i!=tunnels_.end() && status_fresh(*i->second))
      state=i->second->status_live ? L" · 服务许可有效" : L" · 已停止";
    auto label=(n ? orangespace::widen(n->display_name.empty()?n->alias:n->display_name) : L"授权失效")+state;
    SetWindowTextW(node_,label.c_str());update_detail();
    auto detail=orangespace::widen(row->name)+L"\r\n浏览会话状态未知；不会直连回退。\r\n";
    if(auto i=tunnels_.find(row->id);i!=tunnels_.end() && i->second->browser) {
      const auto phase=i->second->browser->phase;
      detail=orangespace::widen(row->name)+(phase==bs::Phase::awaiting_desktop?L"\r\n正在设置当前桌面的实例访问权限。":phase==bs::Phase::starting?L"\r\n浏览器正在启动。":phase==bs::Phase::running?L"\r\n真实浏览器运行中。":phase==bs::Phase::failed?L"\r\n浏览会话失败；网络保持封锁。":L"\r\n浏览器已关闭。");
    }
    if(auto i=tunnels_.find(row->id);i!=tunnels_.end())detail+=diagnostic_text(*i->second);
    else detail+=L"本机许可：未知 · 近期转发：未知 · 租约剩余：未知";
    SetWindowTextW(detail_,detail.c_str());
    browser_view();
  }
  void sync_identity() {
    if(destroyed_)return;
    const auto* s=auth_.active(now());
    if(had_identity_ && !s) {
      // Expiry is the same identity/resource barrier as explicit logout.
      // Clear the transition before logout's sync_identity re-entry.
      had_identity_=false;logout();return;
    }
    const auto* n=auth_.selected_node(now());
    const bool authorized=s && n;
    if(!s) {
      SetWindowTextW(identity_,L"未登录");
      SetWindowTextW(node_,L"未登录");
      if(had_identity_)clear_rows();
    } else {
      auto value=orangespace::widen(s->identity().username);
      if(!n)value+=L"\r\n无获授权节点；请中心管理员配置节点授权及远端映射后退出重登。";
      SetWindowTextW(identity_,value.c_str());
      SetWindowTextW(node_,n ? orangespace::widen(n->node_id).c_str() : L"无授权节点");
    }
    had_identity_=s!=nullptr;
    const bool enabled=!busy_ && !draining_ && !closing_;
    for(auto h:{trust_,load_,alias_,username_,password_})EnableWindow(h,enabled);
    EnableWindow(login_,enabled && !s && !logout_state_.restore_blocked() && catalog_);
    for(auto h:{refresh_,name_,create_,bind_,close_,delete_,connect_})EnableWindow(h,enabled && authorized);
    EnableWindow(list_,!draining_ && !closing_ && authorized);
    auto selected=selection();
    EnableWindow(stop_,!draining_ && !closing_ && selected &&
      (tunnels_.contains(selected->id) || selected->id==starting_local_));
    EnableWindow(open_,enabled); // Always local denial, never a broker open.
    EnableWindow(logout_,!closing_);
    render_proofs();
    const bool login_page=!s;
    if(login_page!=login_page_){login_page_=login_page;layout();}
    for(auto c:node_buttons_)EnableWindow(c,enabled && s);
    for(auto c:node_menus_)EnableWindow(c,enabled && s);
    EnableWindow(add_,enabled && s);
    EnableWindow(file_button_,enabled && s);
  }
  template<class Work> void start(Work work) {
    if (worker_.joinable() || draining_) throw std::runtime_error("UI work already owned");
    auto box = std::make_shared<Mailbox>();
    auto result = std::make_unique<Completion>();
    result->generation=generation_;
    const auto ticket=drain_->begin();
    if(!ticket) throw std::runtime_error("UI is draining");
    auto drain=drain_;
    try {
      worker_=std::thread([box,drain,ticket=*ticket,result=std::move(result),work=std::move(work)]() mutable {
        try { work(*result,*box); } catch (...) {result->failed=true;}
        auto grant=result->grant;
        {std::lock_guard lock(box->mutex);box->result=std::move(result);}
        // Publish all late authorization owners before resolving startup.
        drain->finish(ticket,grant ? std::optional{grant} : std::nullopt);
      });
    } catch (...) {drain->finish(*ticket);throw;}
    mailbox_=std::move(box);busy_=true;sync_identity();
  }
  void invalidate_ui() {
    ++generation_;
    if(!central_cleanup_)central_cleanup_=auth_.retain(now());
    auth_.logout();
    if(mailbox_)mailbox_->cancelled=true;
    SetWindowTextW(password_,L"");SendMessageW(password_,EM_EMPTYUNDOBUFFER,0,0);
    SetWindowTextW(username_,L"");clear_rows();
    tabs_.clear();active_sandbox_.clear();choosing_node_=true;file_view_=false;open_pending_=false;
    if(file_panel_)file_panel_->request_logout();
    rebuild_nodes();rebuild_tabs();
  }
  void begin_close() {
    if(file_panel_)file_panel_->request_logout();
    if(!closing_) {
      closing_=true;invalidate_ui();auth_.close();drain_->close();draining_=true;
      notice(logout_requested_
        ? L"正在等待凭据删除与本机服务停止确认；清理未完成前不会退出。"
        : L"正在等待本机服务确认停止；已存 DPAPI 登录保留。清理失败时窗口不会退出。");
    }
    sync_identity();
  }
  void logout() {
    if(closing_)return;
    if(file_panel_)file_panel_->request_logout();
    if(!logout_requested_) {
      logout_state_.request();
      draining_=true;logout_requested_=true;invalidate_ui();drain_->close();
      retirement_=orangespace::ui_lifecycle::Retirement{};central_logout_failed_=false;
      // CredentialStore::erase commits a protected per-node logout intent before
      // attempting deletion. Exceptions still mean NOT COMPLETE: disk failure
      // may prevent even that commit, so keep the in-process gate and retry.
    }
    next_cleanup_={};
    notice(L"登录界面已失效；正在逐项删除已存凭据并停止本机授权。结果尚未确认。");
    sync_identity();
  }
  void cleanup_step() {
    if(!draining_)return;
    if(browser_mailbox_)return; // Join/discard every old command before retirement.
    const auto stamp=std::chrono::steady_clock::now();
    if(stamp<next_cleanup_)return;
    next_cleanup_=stamp+std::chrono::seconds(1);
    // Failed enumeration is still an admitted logout, not an empty erase list.
    // Retry it independently of service cleanup, including after window close.
    if(logout_requested_ && !logout_state_.initialized()) {
      try {logout_state_.begin(catalog_ ? std::vector<std::string>{"platform"} : std::vector<std::string>{});}
      catch (...) {}
    }
    // Always attempt every remaining erase, independently of service reachability.
    if(logout_requested_ && !busy_ && logout_state_.restore_blocked()) {
      logout_state_.retry_erasure([&](const std::string& name) {
        if(!catalog_)return false;
        (void)name; ps::CredentialStore::erase(*catalog_);return true;
      });
    }
    drain_->retry([&](const std::shared_ptr<sc::Grant>& grant) {
      bool closed=true;
      for(const auto& [local,lease]:tunnels_)
        if(lease->grant==grant && !close_browser_step(*lease))closed=false;
      for(const auto& lease:pending_stops_)
        if(lease->grant==grant && !close_browser_step(*lease))closed=false;
      // Service phase 0 alone can precede the final kernel process observation.
      // Keep the retained exact handle authoritative, including WAIT_FAILED.
      if(!closed || (browser_process_ && WaitForSingleObject(browser_process_,0)!=WAIT_OBJECT_0))return false;
      return retirement_.run(grant->id(),logout_requested_,
        [&]{sc::logout(*grant);},[&]{sc::retire(*grant);});
    });
    browser_view();
    const bool local=drain_->ready() && (!file_panel_ || file_panel_->can_close()) && !busy_ && !browser_process_ && !station_.active();
    if(!local || (logout_requested_ && logout_state_.restore_blocked())) {
      notice(!local ? L"本机停止尚未确认；保留清理所有权并重试，不会退出或允许新登录。凭据删除结果独立记录。"
        : L"本机服务授权已停止；凭据删除未完成，恢复登录与正常退出仍被阻止，将重试。仅已落盘的退出标记可跨重启阻断；存储失败时不保证。");
      return;
    }
    if(file_panel_)file_panel_->logout(); // Tasks finished: join/scrub cannot wait on I/O.
    if(!busy_ && central_cleanup_) {
      if(logout_requested_) {
        try {central_cleanup_->logout();} catch (...) {central_logout_failed_=true;}
      }
      central_cleanup_.reset();
    }

    rows_.retired_all();starting_local_.clear();
    grants_.clear();tunnels_.clear();pending_stops_.clear();
    if(closing_)return;
    draining_=false;drain_=std::make_shared<GrantDrain>();
    if(logout_requested_)notice(retirement_.remote_failed() || central_logout_failed_
      ? L"本机凭据删除与服务授权停止已确认；服务器退出未确认，不宣称远端已撤销。"
      : L"中心退出请求、中心凭据删除与本机服务停止已确认；不等同于 Linux 全部历史连接已撤销。");
    logout_requested_=false;
    if(pending_catalog_) {
      auto path=std::move(*pending_catalog_);pending_catalog_.reset();catalog_.reset();
      SendMessageW(alias_,CB_RESETCONTENT,0,0);
      start([path=std::move(path)](Completion& out,Mailbox&) {
        out.job=Job::catalog;out.catalog.reset(new ps::PlatformConfig(ps::PlatformConfig::load(path)));
      });
    }
  }
  void command(int id) {
    if(id==Navigate){queue_browser(bs::Command::navigate,orangespace::narrow(text(address_)));return;}
    if(id==BrowserBack){queue_browser(bs::Command::back);return;}
    if(id==BrowserForward){queue_browser(bs::Command::forward);return;}
    if(id==BrowserReload){queue_browser(bs::Command::reload);return;}
    if(id>=3000 && id<4000) {
      const auto i=static_cast<std::size_t>(id-3000);if(!busy_ && i<tabs_.size()) {active_sandbox_=tabs_[i];command(Close);}return;
    }
    if(id>=4000 && id<5000) {node_menu(static_cast<std::size_t>(id-4000));return;}
    if(id>=1000 && id<2000) {open_node(static_cast<std::size_t>(id-1000),false);return;}
    if(id>=2000 && id<3000) {
      const auto i=static_cast<std::size_t>(id-2000);if(i<tabs_.size()) {
        active_sandbox_=tabs_[i];file_view_=false;if(file_panel_)file_panel_->hide();rebuild_tabs();render_proofs();
      } return;
    }
    if(id==AddTab) {if(!busy_){choosing_node_=true;additional_=false;file_view_=false;layout();}return;}
    if(id==BackToBrowser) {file_view_=false;layout();return;}
    if(id==Files) {show_files();return;}
    if(id==Menu) {
      auto menu=CreatePopupMenu();AppendMenuW(menu,MF_STRING,Stop,L"停止连接");
      AppendMenuW(menu,MF_STRING,Delete,L"删除此沙盒（仅本机）");AppendMenuW(menu,MF_STRING,Logout,L"退出登录");
      POINT p{};GetCursorPos(&p);const auto picked=TrackPopupMenu(menu,TPM_RETURNCMD|TPM_RIGHTBUTTON,p.x,p.y,0,window,nullptr);
      DestroyMenu(menu);if(picked)command(static_cast<int>(picked));return;
    }
    if (id == Logout) { logout(); return; }
    if (id == Open) { notice(orangespace::widen(orangespace::browser_launch_decision().reason), true); return; }
    if(id==Stop && !draining_ && !closing_) {
      auto selected=selection();if(!selected)return;
      if(selected->id==starting_local_) {
        rows_.stop(selected->id);if(mailbox_)mailbox_->cancelled=true;
        notice(L"已拒绝采用该沙盒的迟到启动结果；精确停止处理中，其他沙盒保持不变。");return;
      }
      if(auto i=tunnels_.find(selected->id);i!=tunnels_.end()) {
        pending_stops_.push_back(i->second); // Allocate before map ownership loss.
        rows_.stop(selected->id);tunnels_.erase(i);next_stop_={};
      }
      sync_identity();return;
    }
    if (busy_ || draining_ || closing_ || logout_state_.restore_blocked()) return;
    if (id == LoadTrust) {
      pending_catalog_=text(trust_);draining_=true;invalidate_ui();drain_->close();
      return;
    }
    if (id == Login) {
      auto secret = std::make_shared<PasswordBuffer>();
      const int length = GetWindowTextLengthW(password_);
      secret->wide.resize(static_cast<std::size_t>(length) + 1);
      GetWindowTextW(password_, secret->wide.data(), length + 1);
      SetWindowTextW(password_, L""); // Clear immediately, before validation/network dispatch.
      SendMessageW(password_, EM_EMPTYUNDOBUFFER, 0, 0);
      if (logout_state_.restore_blocked()) {notice(L"凭据删除尚未完成；恢复登录已阻止。",true);return;}
      if (!catalog_) { notice(L"请先验证管理员保护的 platform.json；不使用旧节点清单。", true); return; }
      const int bytes = length ? WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, secret->wide.data(), length, nullptr, 0, nullptr, nullptr) : 0;
      if (length && !bytes) throw std::runtime_error("invalid password encoding");
      secret->utf8.resize(static_cast<std::size_t>(bytes));
      if (length && !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, secret->wide.data(), length, secret->utf8.data(), bytes, nullptr, nullptr))
        throw std::runtime_error("invalid password encoding");
      ns::detail::wipe(secret->wide.data(), secret->wide.size() * sizeof(wchar_t));
      auto username = orangespace::narrow(text(username_));
      const bool automatic=restore_requested_;restore_requested_=false;
      if(!automatic && secret->view().empty()){notice(L"请输入账号和密码。");return;}
      const bool remember=automatic || SendMessageW(remember_,BM_GETCHECK,0,0)==BST_CHECKED;
      auto ticket=auth_.begin_login();auto catalog=catalog_;
      start([catalog,ticket,username=std::move(username),secret,remember,automatic](Completion& out,Mailbox& box) {
        out.job=Job::login;out.login=ticket;out.remember=remember;out.automatic=automatic;
        if(box.cancelled){out.failed=true;return;}
        if(automatic)out.session.reset(new ps::Session(ps::CredentialStore::load(*catalog)));
        else out.session.reset(new ps::Session(ps::Session::login(*catalog,username,secret->view())));
        try {
          if(!box.cancelled) {out.nodes=out.session->nodes();
            persist_login(*catalog,*out.session,remember);
          }
        } catch (...) {
          // Login already created/restored a central session. A failed node
          // enumeration cannot abandon it merely because UI adoption failed.
          // Preserve the original failure; remote revoke remains best effort.
          try {out.session->logout();} catch (...) {}
          throw;
        }
        if(box.cancelled)out.failed=true;
      });notice(L"正在中心 HTTPS 登录/恢复并读取完整授权节点清单；不回退旧节点登录。");return;
    }
    const auto* s=auth_.active(now());
    const auto* destination=auth_.selected_node(now());
    if(!s || !destination) {
      notice(L"请先中心登录并选择获授权节点；无授权时请中心管理员配置节点授权和远端账号映射。",true);return;
    }
    const auto user = auth_.workspace_user(); const auto user_wide = orangespace::widen(user);
    auto selected = selection();
    if(id==Connect) {
      if(!selected || !auth_.manage(selected->user_id,selected->node_id,now()) || selected->node_id.empty()) {
        notice(L"请选择中心用户拥有且已绑定获授权节点的沙盒。",true);return;
      }
      if(std::any_of(pending_stops_.begin(),pending_stops_.end(),[&](const auto& lease){return lease->local==selected->id;})) {
        notice(L"该沙盒的精确停止尚未确认；请等待清理重试，其他沙盒不受影响。",true);return;
      }
      // OSP3 Prototype deliberately rejects OSP1 foundation probes. The real
      // worker's SCM/retained-process/pipe authentication is the admission path.
      if(!browser_enabled(selected->node_id)){notice(L"此节点已获授权，浏览暂不可用。");return;}
      const auto admitted_at=now();
      auto session=auth_.retain(admitted_at);
      const auto* destination=auth_.node(selected->node_id,admitted_at);
      auto op=auth_.operation(admitted_at,selected->node_id);
      if(!session || !destination ||
         !auth_.manage(selected->user_id,selected->node_id,admitted_at) ||
         !auth_.current(op,admitted_at)) {
        notice(L"中心会话或节点授权已失效；请重新登录后再连接沙盒。",true);return;
      }
      auto node=*destination;auto local=selected->id;
      std::shared_ptr<sc::Grant> grant;
      if(auto i=grants_.find(node.node_id);i!=grants_.end())grant=i->second;
      std::shared_ptr<TunnelLease> old;
      if(auto i=tunnels_.find(local);i!=tunnels_.end())old=i->second;
      auto row_ticket=rows_.begin(local,node.node_id);
      start([grant,local,op,node=std::move(node),session,row_ticket,old=std::move(old)](Completion& out,Mailbox& box) mutable {
        out.tunnel=old;out.job=Job::tunnel;out.operation=op;out.local_sandbox=local;out.row_ticket=row_ticket;
        if(box.cancelled || now()>=op.expiry){out.failed=true;return;}
        auto lease=std::make_shared<TunnelLease>();lease->local=local;
        if(!grant) {
          orangespace::ui_lifecycle::SharedReturnSlot<sc::Grant> owner;
          out.grant=std::move(owner).adopt(sc::authorize_platform(*session,node));
          grant=out.grant;
        }
        lease->grant=grant;
        if(box.cancelled || now()>=op.expiry){out.failed=true;return;}
        // Service ledger, not SQLite/UI generations, owns the durable cursor.
        out.cursor=sc::register_sandbox(*grant,local);
        static_assert(std::is_nothrow_move_assignable_v<decltype(lease->binding)>);
        lease->binding=sc::start_registered_tunnel(*grant,local);
        // Typed return validates all three proofs. Publish exact cleanup owner
        // before any fallible Cursor/string construction or cancellation check.
        out.tunnel=std::move(lease);old.reset();
        out.cursor=orangespace::service::chain::Cursor{out.tunnel->binding.sandbox,out.tunnel->binding.generation};
        if(box.cancelled)out.failed=true;
      });
      starting_local_=local;tunnels_.erase(local);render_proofs();return;
    }
    if(selected && (id==Bind || id==Close || id==Delete) &&
       (!rows_.may_mutate(selected->id) || std::any_of(pending_stops_.begin(),pending_stops_.end(),
         [&](const auto& lease){return lease->local==selected->id;}))) {
      notice(L"该沙盒启动/精确停止仍未确认；请先独立停止并等待确认，再关闭、换绑或删除。其他沙盒可继续管理。",true);return;
    }
    std::vector<std::wstring> args;
    if (id == Refresh) args = {L"list", L"--user", user_wide};
    else if (id == Create) {
      auto name = text(name_); if (name.empty()) { notice(L"请输入沙盒名称。", true); return; }
      args = {L"create", L"--user", user_wide, L"--name", name};
    } else {
      if (!selected || !auth_.authorize(selected->user_id, selected->node_id, destination->node_id, now()) ||
          (id != Bind && !auth_.manage(selected->user_id, selected->node_id, now()))) {
        notice(L"操作被拒绝：沙盒必须归属当前中心用户，绑定节点必须仍在中心授权清单；旧资料须显式迁入。", true); return;
      }
      if (id == Delete && MessageBoxW(window, L"删除此沙盒的本机数据和任务？Linux 个人文件保留。", L"删除沙盒",
          MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) != IDYES) return;
      if (id != Bind && id != Delete && id != Close) return;
      args = {id == Bind ? L"bind" : id == Delete ? L"delete" : L"close", L"--user", user_wide,
          L"--sandbox", orangespace::widen(selected->id)};
      if (id == Bind) { args.push_back(L"--node"); args.push_back(orangespace::widen(destination->node_id)); }
    }
    // Recheck after any confirmation dialog (expiry can occur in its message loop).
    auto op = auth_.operation(now(), (id == Refresh || id == Create || !selected) ? "" : selected->node_id);
    if (!auth_.current(op, now())) { sync_identity(); return; }
    const bool refresh = id != Refresh;
    std::shared_ptr<TunnelLease> closing;
    if(selected && (id==Bind || id==Close || id==Delete)) {
      if(auto it=tunnels_.find(selected->id);it!=tunnels_.end()) closing=it->second;
    }
    start([args = std::move(args), op, refresh, local=selected ? selected->id : std::string{}, stopping=(id==Bind || id==Close || id==Delete), close_tab=(id==Close || id==Delete), closing=std::move(closing)](Completion& out, Mailbox& box) {
      out.tunnel=closing;
      out.job = Job::broker; out.operation = op; out.refresh = refresh;out.close_tab=close_tab;
      if (box.cancelled || now() >= op.expiry) { out.failed = true; return; }
      out.local_sandbox=local;
      if(closing) {wait_browser_closed(*closing);out.cursor=sc::stop_tunnel(*closing->grant,closing->binding);out.tunnel.reset();}
      out.stopped=stopping;
      if(box.cancelled || now()>=op.expiry) {out.failed=true;return;}
      out.process = orangespace::run_broker(args); // UUIDs only; no password/token IPC.
    });
    if(selected && (id==Bind || id==Close || id==Delete)) {tunnels_.erase(selected->id);rows_.stop(selected->id);}
    notice(L"正在处理已认证工作区的本机元数据……");
  }
  void retry_stops() {
    const auto stamp=std::chrono::steady_clock::now();
    if(stamp<next_stop_)return;
    next_stop_=stamp+std::chrono::seconds(1);
    for(auto it=pending_stops_.begin();it!=pending_stops_.end();) {
      try {
        auto& lease=**it;
        if(!close_browser_step(lease)){++it;continue;}
        cursors_[lease.local]=sc::stop_tunnel(*lease.grant,lease.binding);
        rows_.stopped(lease.local);
        it=pending_stops_.erase(it);
      } catch (...) {
        ++it;notice(L"迟到或失败操作的隧道停止尚未确认；保留清理所有权并重试。");
      }
    }
  }
  static bool close_browser_step(TunnelLease& lease) {
    if(!browser_enabled(lease.binding.node))return true;
    try {
      // Observe first: after finish_run only status is valid on the last binding.
      const auto state=bs::exchange(*lease.grant,lease.binding,bs::Command::status);
      if(state.phase==bs::Phase::closed && state.process_id==0)return true;
      if(!lease.browser_close_requested) {
        (void)bs::exchange(*lease.grant,lease.binding,bs::Command::close);
        lease.browser_close_requested=true;
      }
    } catch (...) { /* Unknown service/identity is not a closed browser. */ }
    return false;
  }
  static void wait_browser_closed(TunnelLease& lease) {
    // Worker only. Reuse the Service's existing five-second graceful-close
    // boundary; expiry is failure, not permission to stop an unconfirmed root.
    const auto until=std::chrono::steady_clock::now()+std::chrono::seconds(5);
    do {
      if(close_browser_step(lease))return;
      if(std::chrono::steady_clock::now()>=until)break;
      Sleep(50);
    } while(std::chrono::steady_clock::now()<until);
    throw std::runtime_error("browser close not confirmed");
  }
  static void persist_login(ps::PlatformConfig& catalog,ps::Session& session,bool remember) {
    if(remember)ps::CredentialStore::save(catalog,session);
    else ps::CredentialStore::erase(catalog);
  }
  void adopt_login(Completion& out) {
    if(!out.session)throw std::runtime_error("central session missing");
    if(!auth_.finish_login(out.login,std::move(out.session),std::move(out.nodes),now()))
      throw std::runtime_error("central adoption rejected");
  }
  void reject_login(std::unique_ptr<Completion>& out) {
    // Reuse the existing retained mailbox + logout drain. This also erases a
    // partially/successfully saved credential and gates restore until confirmed.
    // No central HTTP request is made in this adoption callback.
    {std::lock_guard lock(mailbox_->mutex);mailbox_->result=std::move(out);}
    busy_=true;
    logout();
  }
  bool status_fresh(const TunnelLease& lease) const {
    return lease.status_known && std::chrono::steady_clock::now()-lease.status_at<std::chrono::seconds(5);
  }
  static bool same_binding(const orangespace::service::chain::Binding& a,
                           const orangespace::service::chain::Binding& b) {
    return a.user==b.user && a.sandbox==b.sandbox && a.node==b.node &&
      a.tunnel==b.tunnel && a.generation==b.generation;
  }
  std::wstring diagnostic_text(const TunnelLease& lease) const {
    std::wstring value=L"本机许可：";
    value+=status_fresh(lease) ? (lease.status_live ? L"有效" : L"已停止") : L"未知";
    const auto tick=GetTickCount64();
    const auto* d=lease.diagnostic ? &*lease.diagnostic : nullptr;
    const bool recent=status_fresh(lease) && lease.status_live && d &&
      same_binding(d->binding,lease.binding) && d->clock==ns::detail::lease_clock &&
      d->observed_at_ms>=0 && tick>=static_cast<std::uint64_t>(d->observed_at_ms) &&
      tick-static_cast<std::uint64_t>(d->observed_at_ms)<5000 &&
      d->deadline_ms>0 && tick<static_cast<std::uint64_t>(d->deadline_ms);
    value+=recent ? (d->fresh_proof ? L" · 近期转发：已验证" : L" · 近期转发：未验证") : L" · 近期转发：未知";
    value+=L"\r\n租约剩余：";
    if(d && d->clock==ns::detail::lease_clock && d->deadline_ms>0) {
      const auto deadline=static_cast<std::uint64_t>(d->deadline_ms);
      value+=std::to_wstring(tick<deadline ? (deadline-tick)/1000 : 0)+L" 秒";
      value+=L" · 最近观测：";
      if(d->observed_at_ms>=0 && tick>=static_cast<std::uint64_t>(d->observed_at_ms)) {
        const auto age=tick-static_cast<std::uint64_t>(d->observed_at_ms);
        if(age<1000)value+=L"刚刚";
        else if(age<60000)value+=std::to_wstring(age/1000)+L" 秒前";
        else value+=L"超过一分钟";
      } else value+=L"未知";
    } else value+=L"未知";
    return value;
  }
  static bool browser_enabled(std::string_view node) {
#ifdef ORANGESPACE_PROTOTYPE_NODE_UUID
    return node==ORANGESPACE_PROTOTYPE_NODE_UUID;
#else
    (void)node;return false;
#endif
  }
  bool retain_browser_process(const bs::State& state) {
    if(browser_process_)return browser_pid_==state.process_id && browser_birth_==state.process_birth && WaitForSingleObject(browser_process_,0)==WAIT_TIMEOUT;
    HANDLE process=OpenProcess(SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,state.process_id);
    if(!process)return false;
    struct Guard{HANDLE p;~Guard(){if(p)CloseHandle(p);}} guard{process};
    FILETIME creation{},exit{},kernel{},user{};DWORD session{};
    const auto own=sc::current_interactive_session();
    wchar_t image[32768]{},module[32768]{};DWORD count=32768;
    const auto n=GetModuleFileNameW(nullptr,module,32768);
    if(!own || !n || n>=32768 || !GetProcessTimes(process,&creation,&exit,&kernel,&user) ||
       ((std::uint64_t(creation.dwHighDateTime)<<32)|creation.dwLowDateTime)!=state.process_birth ||
       !ProcessIdToSessionId(state.process_id,&session) || session!=*own ||
       !QueryFullProcessImageNameW(process,0,image,&count) ||
       _wcsicmp(image,(std::filesystem::path(module).parent_path()/L"client.exe").c_str()) ||
       WaitForSingleObject(process,0)!=WAIT_TIMEOUT)return false;
    HANDLE token{};if(!OpenProcessToken(process,TOKEN_QUERY,&token))return false;
    Guard token_guard{token};DWORD needed{};
    GetTokenInformation(token,TokenAppContainerSid,nullptr,0,&needed);
    if(!needed || needed>65536)return false;
    std::vector<BYTE> data(needed);
    if(!GetTokenInformation(token,TokenAppContainerSid,data.data(),needed,&needed))return false;
    auto sid=reinterpret_cast<TOKEN_APPCONTAINER_INFORMATION*>(data.data())->TokenAppContainer;
    PSID claimed{};if(!ConvertStringSidToSidW(orangespace::widen(state.package_sid).c_str(),&claimed))return false;
    const bool match=sid && EqualSid(sid,claimed);LocalFree(claimed);if(!match)return false;
    browser_process_=process;guard.p=nullptr;browser_pid_=state.process_id;browser_birth_=state.process_birth;
    embed_until_=std::chrono::steady_clock::now()+std::chrono::seconds(15);return true;
  }
  void browser_view() {
    if(browser_process_ && WaitForSingleObject(browser_process_,0)==WAIT_OBJECT_0) {
      if(!station_.restore()){notice(L"浏览器已退出；桌面权限恢复未确认，停止重新打开。");return;}
      CloseHandle(browser_process_);browser_process_=nullptr;browser_hwnd_=nullptr;browser_pid_=0;browser_birth_=0;station_ready_=false;embed_failed_=false;
    }
    auto i=tunnels_.find(active_sandbox_);
    const auto* state=i!=tunnels_.end() && i->second->browser ? &*i->second->browser : nullptr;
    const bool fresh=state && std::chrono::steady_clock::now()-i->second->browser_at<std::chrono::seconds(5);
    const bool running=fresh && state->phase==bs::Phase::running && !draining_ && !closing_;
    if(running && !browser_hwnd_ && !embed_failed_) {
      if(!retain_browser_process(*state)) {embed_failed_=true;notice(L"浏览器进程身份核验失败；未嵌入窗口。");}
      else {
        struct Search{DWORD pid;HWND found;};Search search{browser_pid_,nullptr};
        EnumWindows([](HWND h,LPARAM p)->BOOL {
          auto& value=*reinterpret_cast<Search*>(p);DWORD pid{};GetWindowThreadProcessId(h,&pid);
          if(pid==value.pid && IsWindowVisible(h) && !GetWindow(h,GW_OWNER) && GetAncestor(h,GA_ROOT)==h){value.found=h;return FALSE;}return TRUE;
        },reinterpret_cast<LPARAM>(&search));
        if(search.found) {
          SetLastError(ERROR_SUCCESS);const auto previous=SetParent(search.found,browser_host_);const auto error=GetLastError();
          if(!previous && error!=ERROR_SUCCESS){embed_failed_=true;notice(L"SetParent 失败；无法内嵌真实浏览器。");}
          else {
            const auto style=GetWindowLongPtrW(search.found,GWL_STYLE);
            SetLastError(ERROR_SUCCESS);SetWindowLongPtrW(search.found,GWL_STYLE,(style&~(WS_POPUP|WS_CAPTION|WS_THICKFRAME))|WS_CHILD);
            if(GetLastError()!=ERROR_SUCCESS){embed_failed_=true;ShowWindow(search.found,SW_HIDE);notice(L"浏览器子窗口样式设置失败。");}
            else {browser_hwnd_=search.found;SetWindowPos(browser_hwnd_,nullptr,0,0,0,0,SWP_NOMOVE|SWP_NOSIZE|SWP_NOZORDER|SWP_FRAMECHANGED);}
          }
        } else if(std::chrono::steady_clock::now()>=embed_until_){embed_failed_=true;notice(L"浏览器窗口创建超时；未显示替代网页。");}
      }
    }
    const bool visible=running && browser_hwnd_ && !embed_failed_ && !file_view_ && !choosing_node_ && !tabs_.empty();
    RECT area{};GetClientRect(window,&area);
    MoveWindow(browser_host_,px(12),px(110),std::max<LONG>(0,area.right-px(24)),std::max<LONG>(0,area.bottom-px(170)),TRUE);
    ShowWindow(browser_host_,visible?SW_SHOW:SW_HIDE);
    if(browser_hwnd_) {
      DWORD owner{};GetWindowThreadProcessId(browser_hwnd_,&owner);
      if(owner==browser_pid_ && browser_process_ && WaitForSingleObject(browser_process_,0)==WAIT_TIMEOUT) {
        RECT box{};GetClientRect(browser_host_,&box);MoveWindow(browser_hwnd_,0,0,box.right,box.bottom,TRUE);
        ShowWindow(browser_hwnd_,visible?SW_SHOW:SW_HIDE);
      }
    }
    EnableWindow(address_,running && !file_view_);EnableWindow(reload_,running && !file_view_);
    EnableWindow(back_,running && !file_view_ && state->can_go_back);EnableWindow(forward_,running && !file_view_ && state->can_go_forward);
    if(visible)ShowWindow(detail_,SW_HIDE);
  }
  void queue_browser(bs::Command command,std::string url={}) {
    if(draining_ || closing_ || busy_)return;
    const auto i=tunnels_.find(active_sandbox_);if(i==tunnels_.end() || !browser_enabled(i->second->binding.node))return;
    if(command==bs::Command::navigate && !sc::valid_browser_url(url)){notice(L"请输入有效的 HTTP 或 HTTPS 网址。");return;}
    if(browser_command_){notice(L"上一条浏览操作仍在处理中。");return;}
    browser_command_=command;browser_url_=std::move(url);browser_command_owner_=i->second;
  }
  void poll_browser() {
    browser_view();
    if(browser_mailbox_) {
      auto box=browser_mailbox_;bool done{};{std::lock_guard lock(box->mutex);done=box->done;}if(!done)return;
      if(browser_worker_.joinable())browser_worker_.join();
      const auto i=tunnels_.find(box->lease->local);
      if(!draining_ && !closing_ && generation_==box->generation && i!=tunnels_.end() && i->second==box->lease) {
        i->second->browser=std::move(box->state);i->second->browser_at=box->requested;
        if(i->second->browser) {
          const auto& state=*i->second->browser;
          if(GetFocus()!=address_)SetWindowTextW(address_,orangespace::widen(state.url).c_str());
          if(state.phase==bs::Phase::awaiting_desktop && !station_ready_) {
            try {
              if(!retain_browser_process(state))throw std::runtime_error("browser-identity");
              station_.grant(state);station_ready_=true;
              browser_command_=bs::Command::station_configured;browser_command_owner_=i->second;
            } catch (...) {
              browser_command_=bs::Command::close;browser_command_owner_=i->second;
              notice(L"当前桌面的实例权限设置失败；关闭该实例，不扩大权限。");
            }
          }
          if(state.phase==bs::Phase::failed)notice(L"浏览会话失败；不会切换到直连网络。");
        } else notice(L"浏览状态未知；服务通信或授权未确认。");
      }
      browser_mailbox_.reset();browser_view();return;
    }
    if(draining_ || closing_ || busy_)return;
    const auto stamp=std::chrono::steady_clock::now();if(!browser_command_ && stamp<next_browser_)return;
    auto i=tunnels_.find(active_sandbox_);if(i==tunnels_.end() || !browser_enabled(i->second->binding.node))return;
    auto box=std::make_shared<BrowserMailbox>();box->lease=i->second;box->generation=generation_;box->requested=stamp;
    const auto command=browser_command_ && browser_command_owner_==box->lease ? *browser_command_ : bs::Command::status;
    auto url=command==bs::Command::navigate?browser_url_:std::string{};
    browser_worker_=std::thread([box,command,url=std::move(url)] {
      try {box->state=bs::exchange(*box->lease->grant,box->lease->binding,command,url);}catch (...) {}
      std::lock_guard lock(box->mutex);box->done=true;
    });
    browser_command_.reset();browser_command_owner_.reset();browser_url_.clear();
    browser_mailbox_=std::move(box);next_browser_=stamp+std::chrono::milliseconds(500);
  }
  void poll_status() {
    if(status_mailbox_) {
      auto box=status_mailbox_;
      bool done=false;{std::lock_guard lock(box->mutex);done=box->done;}
      if(!done)return;
      if(status_worker_.joinable())status_worker_.join();
      const auto i=tunnels_.find(box->lease->local);
      // The immutable owner carries local + complete Service binding, including
      // node, tunnel and durable generation. Never publish to a replacement.
      if(!draining_ && !closing_ && generation_==box->generation &&
         i!=tunnels_.end() && i->second==box->lease && same_binding(i->second->binding,box->binding) &&
         bool(i->second->diagnostic)==box->had_diagnostic &&
         (!box->had_diagnostic || (i->second->diagnostic->deadline_ms==box->prior_deadline &&
           i->second->diagnostic->server_expiry==box->prior_expiry &&
           i->second->diagnostic->observed_at_ms==box->prior_observed))) {
        i->second->status_at=box->requested;
        i->second->status_known=box->known;
        i->second->status_live=box->live;
        // Queue age is part of the original observation budget, never receipt time.
        i->second->diagnostic.reset();
        if(status_fresh(*i->second) && box->known && box->live && box->diagnostic &&
           same_binding(box->diagnostic->binding,box->binding))
          i->second->diagnostic=std::move(box->diagnostic);
      }
      status_mailbox_.reset();
      return;
    }
    if(draining_ || closing_)return;
    const auto stamp=std::chrono::steady_clock::now();
    auto chosen=tunnels_.end();
    for(auto i=tunnels_.begin();i!=tunnels_.end();++i)
      if(stamp>=i->second->next_status &&
         (chosen==tunnels_.end() || i->second->next_status<chosen->second->next_status))chosen=i;
    if(chosen==tunnels_.end())return;
    auto box=std::make_shared<StatusMailbox>();
    box->lease=chosen->second;box->generation=generation_;box->requested=stamp;
    box->binding=box->lease->binding;
    box->had_diagnostic=bool(box->lease->diagnostic);
    if(box->had_diagnostic) {
      box->prior_deadline=box->lease->diagnostic->deadline_ms;
      box->prior_expiry=box->lease->diagnostic->server_expiry;
      box->prior_observed=box->lease->diagnostic->observed_at_ms;
    }
    status_worker_=std::thread([box] {
      bool known=false,live=false;
      try {
        const auto active=sc::active_tunnels(*box->lease->grant);
        const auto& expected=box->binding;
        live=std::any_of(active.begin(),active.end(),[&](const auto& b) {
          return b.user==expected.user && b.sandbox==expected.sandbox &&
            b.node==expected.node && b.tunnel==expected.tunnel && b.generation==expected.generation;
        });
        known=true;
      } catch (...) {} // Unreachable/invalid/expired authority is unknown, not cached success.
      // Diagnostic failure is independent from the local permit observation.
      if(known && live)try {
        auto diagnostic=sc::diagnose_tunnel(*box->lease->grant,box->binding);
        if(same_binding(diagnostic.binding,box->binding))box->diagnostic=std::move(diagnostic);
      } catch (...) {}
      std::lock_guard lock(box->mutex);box->known=known;box->live=live;box->done=true;
    });
    chosen->second->next_status=stamp+std::chrono::seconds(2);
    status_mailbox_=std::move(box);
  }
  void poll() {
    if(file_panel_)file_panel_->poll();
    poll_browser();
    poll_status();
    if (draining_) {
      if(mailbox_) {
        bool done=false;{std::lock_guard lock(mailbox_->mutex);done=bool(mailbox_->result);}
        if(done) {
          if(worker_.joinable())worker_.join();
          // A login that completed after logout still owns a central session.
          if(mailbox_->result->session && !central_cleanup_)
            central_cleanup_=std::shared_ptr<ps::Session>(std::move(mailbox_->result->session));
          // Startup/close can finish after drain began; keep its browser owner.
          if(mailbox_->result->tunnel &&
             std::find(pending_stops_.begin(),pending_stops_.end(),mailbox_->result->tunnel)==pending_stops_.end())
            pending_stops_.push_back(mailbox_->result->tunnel);
          mailbox_.reset();busy_=false;
        }
      }
      cleanup_step();
      if(closing_ && !busy_ && drain_->ready() && !logout_state_.restore_blocked() && (!file_panel_ || file_panel_->can_close()) && !browser_process_ && !station_.active()) {DestroyWindow(window);return;}
      sync_identity();return;
    }
    retry_stops();
    if (!busy_) { sync_identity(); return; }
    std::unique_ptr<Completion> out;
    { std::lock_guard<std::mutex> lock(mailbox_->mutex); out = std::move(mailbox_->result); }
    if (!out) { sync_identity(); return; }
    if(worker_.joinable())worker_.join();
    // Until pending-stop adoption succeeds the mailbox remains the retry owner.
    // A receiver allocation failure must not destroy the sole exact lease.
    try {
      if(out->tunnel && std::find(pending_stops_.begin(),pending_stops_.end(),out->tunnel)==pending_stops_.end())
        pending_stops_.push_back(out->tunnel);
    } catch (...) {
      std::lock_guard lock(mailbox_->mutex);mailbox_->result=std::move(out);return;
    }
    busy_ = false; starting_local_.clear();
    if(out->session && (out->failed || out->generation!=generation_)) {
      reject_login(out);sync_identity();return;
    }
    if (out->generation != generation_) {mailbox_.reset();sync_identity();return;}
    try {
      if(out->cursor && !out->local_sandbox.empty()) cursors_[out->local_sandbox]=*out->cursor;
      if(out->grant)grants_[out->grant->node()]=out->grant;
      if(out->stopped && !out->local_sandbox.empty())rows_.stopped(out->local_sandbox);
      if(out->failed) {
        if(out->job==Job::open_node)open_pending_=false;
        if(out->job==Job::login && out->automatic && !out->session) {notice(L"请输入账号和密码登录。");sync_identity();return;}
        if(out->job==Job::tunnel) {
          rows_.complete(out->row_ticket,false,false,false);
          if(!out->tunnel && rows_.state(out->local_sandbox)==orangespace::PlatformRows::State::stopping)rows_.stopped(out->local_sandbox);
        }
        notice(out->job==Job::catalog
          ? L"platform.json 载入失败：请检查绝对路径、管理员保护 ACL 和中心 HTTPS 配置。不会使用旧 Node 登录。"
          : out->job==Job::login
          ? L"中心登录/恢复失败：请检查中心账号、HTTPS 证书与网络；恢复失败可输入密码重新登录。"
          : L"操作未完成：请检查获授权节点在线、受保护服务已安装运行，以及节点授权/远端映射；未知状态不代表启动成功。",true);
        sync_identity();return;
      }
      if(out->job==Job::catalog) {
        catalog_=std::shared_ptr<ps::PlatformConfig>(std::move(out->catalog));
        notice(L"请输入账号和密码登录。");
        restore_requested_=true;command(Login);return;
      } else if(out->job==Job::login) {
        adopt_login(*out);
        {
          SendMessageW(alias_,CB_RESETCONTENT,0,0);
          for(const auto& node:auth_.nodes()) {
            const auto label=orangespace::widen(node.alias);
            SendMessageW(alias_,CB_ADDSTRING,0,reinterpret_cast<LPARAM>(label.c_str()));
          }
          SendMessageW(alias_,CB_SETCURSEL,0,0);
          SendMessageW(remember_,BM_SETCHECK,out->remember?BST_CHECKED:BST_UNCHECKED,0);
          choosing_node_=true;additional_=false;rebuild_nodes();
          clear_rows();notice(auth_.nodes().empty()
            ? L"中心身份已验证但无授权节点；请中心管理员配置节点授权与远端映射后重新登录。"
            : L"中心身份与授权节点已验证；本机旧资料不改归属。浏览会话由受保护服务独立授权。");
          if(!auth_.nodes().empty()){command(Refresh);return;}
        }
      } else if(out->job==Job::tunnel && auth_.current(out->operation,now()) && rows_.current(out->row_ticket)) {
        if(!out->tunnel) throw std::runtime_error("tunnel proof absent");
        // Keep pending ownership until the fallible map slot exists. Shared
        // pointer copy assignment and reset are allocation-free on both STLs.
        tunnels_[out->local_sandbox]=out->tunnel;
        std::erase(pending_stops_,out->tunnel);
        out->tunnel.reset();
        rows_.complete(out->row_ticket,true,true,true); // Only after validated typed Service return.
        next_browser_={};notice(L"节点隧道已验证；正在等待 Service 完成浏览器防护与启动。");
      } else if(out->job==Job::open_node && auth_.current(out->operation,now())) {
        open_pending_=false;sandboxes_=std::move(out->sandboxes);active_sandbox_=out->local_sandbox;
        const bool already_open=std::find(tabs_.begin(),tabs_.end(),active_sandbox_)!=tabs_.end();
        if(!already_open)tabs_.push_back(active_sandbox_);
        choosing_node_=false;additional_=false;rebuild_tabs();
        if(!already_open && !tunnels_.contains(active_sandbox_) && active_sandbox_!=starting_local_)command(Connect);
        return;
      } else if (out->job==Job::broker && auth_.current(out->operation, now())) {
        if (!out->process.failure.empty()) throw std::runtime_error("local process failed");
        const auto response = orangespace::parse_response(out->process.output, out->operation.user);
        if (!response.ok || out->process.exit_code != 0) throw std::runtime_error("local operation failed");
        if(out->close_tab) {
          std::erase(tabs_,out->local_sandbox);
          if(active_sandbox_==out->local_sandbox)active_sandbox_=tabs_.empty()?std::string{}:tabs_.back();
          file_view_=false;if(file_panel_)file_panel_->hide();
          if(tabs_.empty())choosing_node_=true;
          rebuild_tabs();
        }
        if (out->refresh) { command(Refresh); return; }
        sandboxes_ = response.sandboxes;rebuild_tabs();
        notice(L"工作区已读取。原有沙盒数据保持不变；浏览状态由受保护服务核验。");
      } else notice(L"登录已失效；已忽略迟到结果，请重新登录并读取工作区。");
    } catch (...) {
      if(out && out->session) {reject_login(out);sync_identity();return;}
      if(out && out->job==Job::open_node)open_pending_=false;
      notice(L"响应无效或本机操作失败；未采用此结果。", true);
    }
    mailbox_.reset();
    sync_identity();
  }
  // Non-secret local preference only. Every read is revalidated against broker
  // ownership and current central node grants; this registry value is no authority.
  static std::string default_preference(const std::string& user,const std::string& node,const std::string& save={}) {
    std::wstring product=L"Software\\OrangeSpace";
    if(!orangespace::install_identity::suffix.empty()) {
      product+=L".Dev.";
      product.append(orangespace::install_identity::suffix.begin(),orangespace::install_identity::suffix.end());
    }
    const auto key=product+L"\\DefaultSandboxes\\"+orangespace::widen(user);
    const auto name=orangespace::widen(node);
    if(!save.empty()) {
      HKEY handle{};if(RegCreateKeyExW(HKEY_CURRENT_USER,key.c_str(),0,nullptr,0,KEY_SET_VALUE,nullptr,&handle,nullptr)!=ERROR_SUCCESS)
        throw std::runtime_error("cannot persist default sandbox");
      const auto value=orangespace::widen(save);
      const auto result=RegSetValueExW(handle,name.c_str(),0,REG_SZ,reinterpret_cast<const BYTE*>(value.c_str()),static_cast<DWORD>((value.size()+1)*sizeof(wchar_t)));
      RegCloseKey(handle);if(result!=ERROR_SUCCESS)throw std::runtime_error("cannot persist default sandbox");
      return save;
    }
    wchar_t value[37]{};DWORD size=sizeof(value);
    if(RegGetValueW(HKEY_CURRENT_USER,key.c_str(),name.c_str(),RRF_RT_REG_SZ,nullptr,value,&size)!=ERROR_SUCCESS)return {};
    const auto id=orangespace::narrow(value);return orangespace::valid_uuid(id)?id:std::string{};
  }
  void node_menu(std::size_t index) {
    if(busy_ || draining_ || closing_ || index>=auth_.nodes().size() || index>=node_menus_.size() || !node_menus_[index])return;
    const auto session=auth_.retain(now());if(!session)return;
    const auto& node=auth_.nodes()[index];
    const auto node_id=node.node_id;
    std::vector<std::string> choices;
    auto menu=CreatePopupMenu();if(!menu)return;
    struct MenuOwner {HMENU handle;~MenuOwner(){if(handle)DestroyMenu(handle);}} menu_owner{menu};
    for(const auto& row:sandboxes_) {
      if(row.user_id!=session->identity().central_user_id || row.node_id!=node.node_id || row.state=="deleting")continue;
      choices.push_back(row.id);
      auto title=orangespace::widen(row.name);
      AppendMenuW(menu,MF_STRING,static_cast<UINT_PTR>(choices.size()),title.c_str());
    }
    constexpr UINT NewIndependent=60000;
    AppendMenuW(menu,MF_SEPARATOR,0,nullptr);
    AppendMenuW(menu,MF_STRING,NewIndependent,L"新建独立沙盒");
    RECT r{};GetWindowRect(node_menus_[index],&r);
    const auto picked=TrackPopupMenu(menu,TPM_RETURNCMD|TPM_NONOTIFY,r.left,r.bottom,0,window,nullptr);
    // A native popup pumps messages: logout, expiry or a new login may have
    // replaced the account/node list while the old menu was still visible.
    if(auth_.retain(now())!=session || index>=auth_.nodes().size() || auth_.nodes()[index].node_id!=node_id)return;
    if(picked==NewIndependent)open_node(index,true);
    else if(picked>0 && static_cast<std::size_t>(picked)<=choices.size())open_node(index,false,choices[static_cast<std::size_t>(picked)-1]);
  }
  void open_node(std::size_t index,bool additional,std::string requested={}) {
    if(busy_ || open_pending_ || draining_ || closing_ || index>=auth_.nodes().size())return;
    if(!browser_enabled(auth_.nodes()[index].node_id)){notice(L"此节点已获授权，浏览暂不可用。");return;}
    if(additional){notice(L"当前开发包仅支持一个新加坡浏览沙盒。");return;}
    if(browser_process_ && tunnels_.empty()){notice(L"上次浏览关闭及桌面权限恢复仍在确认，请稍候。");return;}
    if(!tunnels_.empty()) {
      const auto& live=tunnels_.begin()->second;
      if(!requested.empty() && requested!=live->local){notice(L"请先关闭当前新加坡沙盒；本包不并发启动第二个浏览器。");return;}
      active_sandbox_=live->local;choosing_node_=false;file_view_=false;rebuild_tabs();return;
    }
    auto node=auth_.nodes()[index];auth_.select(node.alias);
    const auto op=auth_.operation(now(),node.node_id);if(!auth_.current(op,now()))return;
    auto& slot=default_candidates_[{op.user,node.node_id}];
    if(!slot)slot=std::make_shared<std::string>();
    auto candidate=slot;
    open_pending_=true;
    try {
      start([op,node,additional,candidate,requested](Completion& out,Mailbox& box) {
        out.job=Job::open_node;out.operation=op;
        auto call=[&](std::vector<std::wstring> args) {
          if(box.cancelled || now()>=op.expiry)throw std::runtime_error("stale workspace open");
          const auto process=orangespace::run_broker(args);
          if(!process.failure.empty() || process.exit_code!=0)throw std::runtime_error("broker failed");
          auto response=orangespace::parse_response(process.output,op.user);
          if(!response.ok)throw std::runtime_error("broker rejected");
          if(!args.empty() && args.front()==L"create")response.sandboxes.push_back(orangespace::ui_v2::created_sandbox(process.output,op.user));
          return response;
        };
        const auto user=orangespace::widen(op.user);
        auto listed=call({L"list",L"--user",user});
        std::optional<orangespace::Sandbox> chosen;
        if(!requested.empty()) {
          for(const auto& row:listed.sandboxes)
            if(row.id==requested && row.user_id==op.user && row.node_id==node.node_id && row.state!="deleting")chosen=row;
          if(!chosen)throw std::runtime_error("requested sandbox no longer owned");
        } else if(!additional)chosen=orangespace::ui_v2::default_sandbox(listed.sandboxes,op.user,node.node_id,(candidate->empty()?default_preference(op.user,node.node_id):*candidate));
        if(!additional && requested.empty() && !candidate->empty() && (!orangespace::valid_uuid(*candidate) || !chosen || chosen->id!=*candidate))
          throw std::runtime_error("unresolved default creation");
        if(!chosen) {
          const auto name=orangespace::widen(node.display_name.empty()?node.alias:node.display_name)+L" · 沙盒";
          if(!additional)*candidate="uncertain"; // Lost create reply must not cause another create.
          auto created=call({L"create",L"--user",user,L"--name",name});
          if(created.sandboxes.size()!=1)throw std::runtime_error("create identity missing");
          chosen=created.sandboxes.front();
          if(!additional)*candidate=chosen->id;
        }
        // Persist exact ownership before bind/list can fail. Retry selects only
        // this broker-owned unbound row, never another row sharing its name.
        if(!additional && requested.empty())default_preference(op.user,node.node_id,chosen->id);
        if(chosen->node_id.empty()) {
          listed=call({L"list",L"--user",user});
          const auto owned=orangespace::ui_v2::default_sandbox(listed.sandboxes,op.user,node.node_id,chosen->id);
          if(!owned || owned->id!=chosen->id)throw std::runtime_error("default ownership changed");
          call({L"bind",L"--user",user,L"--sandbox",orangespace::widen(chosen->id),L"--node",orangespace::widen(node.node_id)});
          listed=call({L"list",L"--user",user});
        }
        out.local_sandbox=chosen->id;out.sandboxes=std::move(listed.sandboxes);
        // Only unresolved work retains the latch. A completed default may be
        // explicitly deleted; its absence on a later trusted list is not an
        // uncertain create outcome and must permit a new default.
        if(!additional && requested.empty())candidate->clear();
      });
    } catch (...) {open_pending_=false;throw;}
    notice(L"正在打开工作区…");
  }
  void show_files() {
    if(busy_ || draining_ || closing_)return;
    auto row=selection();auto session=auth_.retain(now());
    if(!row || !session || !catalog_)return;
    const auto* node=auth_.node(row->node_id,now());if(!node)return;
    orangespace::files::FileContext context;
    context.central_user_id=session->identity().central_user_id;context.sandbox_id=row->id;
    context.node_id=row->node_id;context.username=session->identity().username;
    context.node_name=node->display_name.empty()?node->alias:node->display_name;
    context.platform=catalog_;context.session=session;
    context.central_envelope=std::make_shared<ps::SerializedSecret>(session->export_envelope());
    if(!file_panel_)file_panel_=std::make_unique<orangespace::files::FilePanel>(window,GetModuleHandleW(nullptr));
    file_panel_->show(context);file_view_=true;layout();
  }
  void paint_logo(HDC dc,int x,int y,int size) {
    auto resource=FindResourceW(GetModuleHandleW(nullptr),MAKEINTRESOURCEW(201),RT_RCDATA);
    if(!resource)return;
    const auto bytes=SizeofResource(GetModuleHandleW(nullptr),resource);
    const auto data=LockResource(LoadResource(GetModuleHandleW(nullptr),resource));
    if(!bytes || !data)return;
    auto memory=GlobalAlloc(GMEM_MOVEABLE,bytes);if(!memory)return;
    auto target=GlobalLock(memory);if(!target){GlobalFree(memory);return;}
    CopyMemory(target,data,bytes);GlobalUnlock(memory);
    IStream* stream=nullptr;
    if(FAILED(CreateStreamOnHGlobal(memory,TRUE,&stream))){GlobalFree(memory);return;}
    {
      Gdiplus::Bitmap image(stream);Gdiplus::Graphics graphics(dc);
      graphics.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
      graphics.DrawImage(&image,px(x),px(y),px(size),px(size));
    }
    stream->Release();
  }
  void paint() {
    PAINTSTRUCT ps{};auto dc=BeginPaint(window,&ps);RECT client{};GetClientRect(window,&client);
    const int w=MulDiv(client.right,96,static_cast<int>(GetDpiForWindow(window)));
    const int h=MulDiv(client.bottom,96,static_cast<int>(GetDpiForWindow(window)));
    SetBkMode(dc,TRANSPARENT);SetTextColor(dc,RGB(34,41,52));SelectObject(dc,title_font_);
    if(!auth_.active(now())) {
      const int x=(w-400)/2,y=std::max(24,(h-470)/2);
      RECT card{px(x),px(y),px(x+400),px(y+455)};
      auto white=CreateSolidBrush(RGB(255,255,255));FillRect(dc,&card,white);DeleteObject(white);
      auto border=CreatePen(PS_SOLID,1,RGB(225,229,234));auto old=SelectObject(dc,border);
      auto brush=SelectObject(dc,GetStockObject(NULL_BRUSH));RoundRect(dc,card.left,card.top,card.right,card.bottom,px(8),px(8));
      SelectObject(dc,brush);SelectObject(dc,old);DeleteObject(border);
      paint_logo(dc,x+168,y+30,64);
      RECT title{px(x),px(y+110),px(x+400),px(y+148)};
      DrawTextW(dc,L"登录橙域",-1,&title,DT_CENTER|DT_SINGLELINE);
      SelectObject(dc,font_);SetTextColor(dc,RGB(120,125,133));title.top=px(y+150);title.bottom=px(y+175);
      DrawTextW(dc,L"远方的网络，眼前的工作空间。",-1,&title,DT_CENTER|DT_SINGLELINE);
    } else if(choosing_node_ || tabs_.empty()) {
      RECT title{0,px(90),client.right,px(130)};DrawTextW(dc,L"我的节点",-1,&title,DT_CENTER|DT_SINGLELINE);
      SelectObject(dc,font_);SetTextColor(dc,RGB(120,125,133));title.top=px(140);title.bottom=px(170);
      DrawTextW(dc,additional_ ? L"选择节点，再开一个独立沙盒" : L"选择一个节点，打开你的独立工作空间",-1,&title,DT_CENTER|DT_SINGLELINE);
    } else if(!file_view_)paint_logo(dc,(w-64)/2,std::max(130,h/2-110),64);
    EndPaint(window,&ps);
  }
  HWND trust_label_{}, trust_{}, load_{}, alias_label_{}, alias_{}, username_label_{}, username_{}, password_label_{}, password_{},
      login_{}, logout_{}, identity_{}, refresh_{}, list_{}, name_label_{}, name_{}, create_{}, node_label_{}, node_{},
      bind_{}, open_{}, connect_{}, stop_{}, close_{}, delete_{}, detail_{}, files_{}, notice_{};
  HWND remember_{},add_{},file_button_{},menu_{},address_{},back_{},forward_{},reload_{},return_{},browser_host_{},browser_hwnd_{};
  HANDLE browser_process_{};DWORD browser_pid_{};std::uint64_t browser_birth_{};
  InstanceStationRight station_;bool station_ready_{},embed_failed_{};
  std::thread browser_worker_;std::shared_ptr<BrowserMailbox> browser_mailbox_;
  std::optional<bs::Command> browser_command_;std::string browser_url_;
  std::shared_ptr<TunnelLease> browser_command_owner_;
  std::chrono::steady_clock::time_point next_browser_{},embed_until_{};
  std::vector<HWND> node_buttons_,node_menus_,tab_buttons_,tab_closes_;
  std::map<std::pair<std::string,std::string>,std::shared_ptr<std::string>> default_candidates_;
  std::vector<std::string> tabs_;
  std::string active_sandbox_;
  bool choosing_node_=true,additional_{},open_pending_{},file_view_{},restore_requested_{},login_page_=true;
  std::unique_ptr<orangespace::files::FilePanel> file_panel_;
  HFONT font_{}, title_font_{}; HBRUSH background_{};
  std::vector<orangespace::Sandbox> sandboxes_;
  std::shared_ptr<ps::PlatformConfig> catalog_;
  std::shared_ptr<ps::Session> central_cleanup_;
  bool central_logout_failed_{};
  orangespace::PlatformRows rows_;
  std::string starting_local_;
  std::shared_ptr<Mailbox> mailbox_;
  using GrantDrain=orangespace::ui_lifecycle::Drain<std::shared_ptr<sc::Grant>>;
  std::shared_ptr<GrantDrain> drain_=std::make_shared<GrantDrain>();
  std::thread worker_;
  std::thread status_worker_;
  std::shared_ptr<StatusMailbox> status_mailbox_;
  orangespace::ui_lifecycle::LogoutState logout_state_;
  orangespace::ui_lifecycle::Retirement retirement_;
  std::optional<std::wstring> pending_catalog_;
  std::chrono::steady_clock::time_point next_cleanup_{},next_stop_{};
  std::vector<std::shared_ptr<TunnelLease>> pending_stops_;
  bool draining_{},closing_{},destroyed_{},logout_requested_{};
  Auth auth_;
  std::map<std::string,std::shared_ptr<sc::Grant>> grants_;
  std::map<std::string,std::shared_ptr<TunnelLease>> tunnels_;
  std::map<std::string,orangespace::service::chain::Cursor> cursors_;
  std::uint64_t generation_{};
  bool busy_{}, had_identity_{};
};
LRESULT CALLBACK window_procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam) noexcept {
  auto* app = reinterpret_cast<Application*>(GetWindowLongPtrW(window, GWLP_USERDATA));
  if (message == WM_NCCREATE) {
    app = static_cast<Application*>(reinterpret_cast<CREATESTRUCTW*>(lparam)->lpCreateParams);
    app->window = window; SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(app));
  }
  try {
    return app ? app->message(message, wparam, lparam) : DefWindowProcW(window, message, wparam, lparam);
  } catch (...) {
    // Never unwind into Windows or allocate another error report here. Existing
    // exact cleanup owners remain for the next event; zero also vetoes logoff.
    return 0;
  }
}
} // namespace
int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
  Gdiplus::GdiplusStartupInput gdiplus_input; ULONG_PTR gdiplus_token{};
  if(Gdiplus::GdiplusStartup(&gdiplus_token,&gdiplus_input,nullptr)!=Gdiplus::Ok)return 1;
  SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
  INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES}; InitCommonControlsEx(&controls);
  Application app;
  WNDCLASSEXW type{}; type.cbSize = sizeof(type); type.hInstance = instance; type.lpfnWndProc = window_procedure;
  type.lpszClassName = L"OrangeSpaceManager"; type.hCursor = LoadCursorW(nullptr, IDC_ARROW); type.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(101));
  if (!RegisterClassExW(&type)) return 1;
  auto window = CreateWindowExW(0, type.lpszClassName, L"橙域 OrangeSpace", WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, CW_USEDEFAULT, 1120, 760, nullptr, nullptr, instance, &app);
  if (!window) return 1;
  ShowWindow(window, show); UpdateWindow(window); MSG message{};
  while (GetMessageW(&message, nullptr, 0, 0) > 0) {
    if (!IsDialogMessageW(window, &message)) { TranslateMessage(&message); DispatchMessageW(&message); }
  }
  app.finish_before_return();
  Gdiplus::GdiplusShutdown(gdiplus_token);
  return static_cast<int>(message.wParam);
}
