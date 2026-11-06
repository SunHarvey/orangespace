#pragma once
#include "private_channel.hpp"
#include "include/cef_app.h"
#include "include/cef_client.h"
#include "include/cef_request_handler.h"
#include "include/cef_resource_request_handler.h"
#include "include/cef_download_handler.h"
#include "include/cef_life_span_handler.h"
#include "include/cef_dialog_handler.h"
#include "include/cef_display_handler.h"
#include "include/cef_load_handler.h"
#include "include/cef_task.h"
#include <commctrl.h>
namespace orangespace::prototype {
class BrowserCommandTask final : public CefTask {
 CefRefPtr<CefBrowser> browser_;BrowserFrame frame_;
 public: BrowserCommandTask(CefRefPtr<CefBrowser> b,BrowserFrame f):browser_(b),frame_(f){}
 void Execute() override {if(!browser_->IsValid())return;switch(frame_.command){
 case 1:browser_->GetMainFrame()->LoadURL(std::string(frame_.url.data(),frame_.url_size));break;
 case 2:browser_->GoBack();break;case 3:browser_->GoForward();break;
 case 4:browser_->Reload();break;case 5:browser_->GetHost()->CloseBrowser(false);break;
 default:break;}}
 IMPLEMENT_REFCOUNTING(BrowserCommandTask);
};
class OnlineClient final : public CefClient, public CefLifeSpanHandler,
 public CefRequestHandler, public CefResourceRequestHandler, public CefDownloadHandler, public CefDialogHandler,
 public CefDisplayHandler, public CefLoadHandler {
 public:
 explicit OnlineClient(const PrivateOwner* owner):owner_(owner){}
 bool OpenWindow() {
  const auto instance=GetModuleHandleW(nullptr);
  WNDCLASSW wc{};
  wc.lpfnWndProc=WindowProc;wc.hInstance=instance;wc.lpszClassName=L"OrangeSpace.SandboxBrowser";
  wc.hCursor=LoadCursorW(nullptr,IDC_ARROW);
  wc.hbrBackground=GetSysColorBrush(COLOR_BTNFACE);
  if(!RegisterClassW(&wc))return false;
  window_=CreateWindowExW(0,wc.lpszClassName,L"橙域 · 新加坡",WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,
                          CW_USEDEFAULT,CW_USEDEFAULT,1000,720,nullptr,nullptr,instance,this);
  if(!window_)return false;
  back_=AddControl(L"BUTTON",L"←",WS_TABSTOP,Back);
  forward_=AddControl(L"BUTTON",L"→",WS_TABSTOP,Forward);
  reload_=AddControl(L"BUTTON",L"刷新",WS_TABSTOP,Reload);
  address_=AddControl(L"EDIT",L"",WS_TABSTOP|WS_BORDER|ES_AUTOHSCROLL,0);
  go_=AddControl(L"BUTTON",L"前往",WS_TABSTOP,Go);
  if(!back_||!forward_||!reload_||!address_||!go_||
     !SetWindowSubclass(address_,AddressProc,1,reinterpret_cast<DWORD_PTR>(window_))){
   DestroyWindow(window_);return false;
  }
  SendMessageW(address_,EM_SETLIMITTEXT,2048,0);
  SendMessageW(address_,EM_SETCUEBANNER,FALSE,reinterpret_cast<LPARAM>(L"输入 HTTP 或 HTTPS 网址"));
  EnableWindow(back_,FALSE);EnableWindow(forward_,FALSE);
  Layout();
  CefWindowInfo info;info.SetAsChild(window_,PageBounds());
  info.runtime_style=CEF_RUNTIME_STYLE_ALLOY;
  CefBrowserSettings settings;settings.javascript=STATE_ENABLED;
  if(CefBrowserHost::CreateBrowserSync(info,this,"https://example.com/",settings,nullptr,nullptr))return true;
  DestroyWindow(window_);return false;
 }
 CefRefPtr<CefDialogHandler> GetDialogHandler() override {return this;}
 bool OnFileDialog(CefRefPtr<CefBrowser>,FileDialogMode,const CefString&,const CefString&,const std::vector<CefString>&,const std::vector<CefString>&,const std::vector<CefString>&,CefRefPtr<CefFileDialogCallback> callback) override {callback->Cancel();return true;}
 bool GetAuthCredentials(CefRefPtr<CefBrowser>,const CefString&,bool isProxy,const CefString& host,int port,const CefString&,const CefString& scheme,CefRefPtr<CefAuthCallback> callback) override {
  if(!owner_||!ProxyChallenge(isProxy,host.ToString(),port,scheme.ToString(),owner_->offer.port))return false;
  const auto&o=owner_->offer;CefString user(o.username.data(),o.username_size),password(o.password.data(),o.password_size);
  callback->Continue(user,password);PrivateWipe(const_cast<char16_t*>(user.c_str()),user.length()*sizeof(char16_t));PrivateWipe(const_cast<char16_t*>(password.c_str()),password.length()*sizeof(char16_t));return true;
 }
 CefRefPtr<CefLifeSpanHandler> GetLifeSpanHandler() override {return this;}
 CefRefPtr<CefRequestHandler> GetRequestHandler() override {return this;}
 CefRefPtr<CefDownloadHandler> GetDownloadHandler() override {return this;}
 CefRefPtr<CefDisplayHandler> GetDisplayHandler() override {return this;}
 CefRefPtr<CefLoadHandler> GetLoadHandler() override {return this;}
 void OnAfterCreated(CefRefPtr<CefBrowser> browser) override {
  browser_=browser;
  {
   std::lock_guard lock(owner_->browser_mutex);owner_->browser_state.phase=3;
   owner_->browser_command=[browser](BrowserFrame f){if(!CefPostTask(TID_UI,new BrowserCommandTask(browser,f)))TerminateProcess(GetCurrentProcess(),71);};
  }
  Layout();ShowWindow(window_,SW_SHOW);
 }
 template<std::size_t N> static void text(std::array<char,N>& out,std::uint32_t& length,std::string value){
  auto n=std::min(value.size(),N);while(n<value.size()&&n&&(static_cast<unsigned char>(value[n])&0xc0)==0x80)--n;
  out.fill(0);std::memcpy(out.data(),value.data(),n);length=static_cast<std::uint32_t>(n);
 }
 void OnAddressChange(CefRefPtr<CefBrowser>,CefRefPtr<CefFrame> frame,const CefString& url) override {
  if(!frame->IsMain())return;auto value=url.ToString();if(!OnlineNavigation(value))return;
  if(GetFocus()!=address_)SetWindowTextW(address_,url.ToWString().c_str());
  std::lock_guard lock(owner_->browser_mutex);text(owner_->browser_state.url,owner_->browser_state.url_size,std::move(value));
 }
 void OnTitleChange(CefRefPtr<CefBrowser>,const CefString& title) override {
  std::lock_guard lock(owner_->browser_mutex);text(owner_->browser_state.title,owner_->browser_state.title_size,title.ToString());
 }
 void OnLoadingStateChange(CefRefPtr<CefBrowser>,bool loading,bool back,bool forward) override {
  EnableWindow(back_,back);EnableWindow(forward_,forward);
  std::lock_guard lock(owner_->browser_mutex);auto&s=owner_->browser_state;s.loading=loading;s.back=back;s.forward=forward;
 }
 void OnBeforeClose(CefRefPtr<CefBrowser>) override {
  {std::lock_guard lock(owner_->browser_mutex);owner_->browser_state.phase=0;owner_->browser_command={};}
  browser_=nullptr;
  CefQuitMessageLoop();
 }
 bool OnBeforePopup(CefRefPtr<CefBrowser>,CefRefPtr<CefFrame>,int,const CefString&,
   const CefString&,cef_window_open_disposition_t,bool,const CefPopupFeatures&,CefWindowInfo&,
   CefRefPtr<CefClient>&,CefBrowserSettings&,CefRefPtr<CefDictionaryValue>&,bool*) override {return true;}
 bool CanDownload(CefRefPtr<CefBrowser>,const CefString&,const CefString&) override {return false;}
 void OnDownloadUpdated(CefRefPtr<CefBrowser>,CefRefPtr<CefDownloadItem>,
   CefRefPtr<CefDownloadItemCallback> callback) override {callback->Cancel();}
 bool OnBeforeBrowse(CefRefPtr<CefBrowser>,CefRefPtr<CefFrame>,CefRefPtr<CefRequest> request,bool,bool) override {
   return !OnlineNavigation(request->GetURL().ToString());
 }
 CefRefPtr<CefResourceRequestHandler> GetResourceRequestHandler(CefRefPtr<CefBrowser>,
   CefRefPtr<CefFrame>,CefRefPtr<CefRequest>,bool,bool,const CefString&,bool& disable) override {
   disable=false; return this;
 }
 ReturnValue OnBeforeResourceLoad(CefRefPtr<CefBrowser>,CefRefPtr<CefFrame>,
   CefRefPtr<CefRequest> request,CefRefPtr<CefCallback>) override {
   return OnlineNavigation(request->GetURL().ToString())?RV_CONTINUE:RV_CANCEL;
 }
 void OnProtocolExecution(CefRefPtr<CefBrowser>,CefRefPtr<CefFrame>,CefRefPtr<CefRequest>,bool& allow) override {allow=false;}
 private:
 enum : WORD { Back=1, Forward, Reload, Go };
 const PrivateOwner* owner_;
 CefRefPtr<CefBrowser> browser_;
 HWND window_{},back_{},forward_{},reload_{},address_{},go_{};
 HWND AddControl(const wchar_t* kind,const wchar_t* label,DWORD style,WORD id) {
  auto control=CreateWindowExW(0,kind,label,WS_CHILD|WS_VISIBLE|style,0,0,0,0,window_,
                              reinterpret_cast<HMENU>(static_cast<UINT_PTR>(id)),GetModuleHandleW(nullptr),nullptr);
  if(control)SendMessageW(control,WM_SETFONT,reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)),FALSE);
  return control;
 }
 int Scale(int value) const {return MulDiv(value,static_cast<int>(GetDpiForWindow(window_)),96);}
 CefRect PageBounds() const {
  RECT client{};GetClientRect(window_,&client);
  const int y=Scale(48);
  return {0,y,static_cast<int>(client.right),std::max(0,static_cast<int>(client.bottom)-y)};
 }
 void Layout() {
  if(!go_)return;
  const auto page=PageBounds();
  const auto move=[&](HWND h,int x,int width){MoveWindow(h,x,Scale(8),width,Scale(30),TRUE);};
  move(back_,Scale(8),Scale(34));move(forward_,Scale(46),Scale(34));move(reload_,Scale(84),Scale(54));
  move(address_,Scale(144),std::max(0,page.width-Scale(212)));
  move(go_,std::max(0,page.width-Scale(62)),Scale(54));
  if(browser_)MoveWindow(browser_->GetHost()->GetWindowHandle(),page.x,page.y,page.width,page.height,TRUE);
 }
 void Navigate() {
  wchar_t input[2049]{};
  const int size=GetWindowTextW(address_,input,static_cast<int>(std::size(input)));
  if(size<=0)return;
  CefString url(input,static_cast<std::size_t>(size));
  if(!OnlineNavigation(url.ToString())) {
   MessageBoxW(window_,L"请输入完整的 HTTP 或 HTTPS 网址。",L"橙域",MB_OK|MB_ICONINFORMATION);
   return;
  }
  SetFocus(browser_->GetHost()->GetWindowHandle());
  browser_->GetMainFrame()->LoadURL(url);
 }
 static LRESULT CALLBACK AddressProc(HWND h,UINT message,WPARAM w,LPARAM l,UINT_PTR,DWORD_PTR owner) {
  if(message==WM_KEYDOWN&&w==VK_RETURN) {
   SendMessageW(reinterpret_cast<HWND>(owner),WM_COMMAND,MAKEWPARAM(Go,BN_CLICKED),0);return 0;
  }
  if(message==WM_CHAR&&w==VK_RETURN)return 0;
  return DefSubclassProc(h,message,w,l);
 }
 static LRESULT CALLBACK WindowProc(HWND window,UINT message,WPARAM w,LPARAM l) {
  if(message==WM_NCCREATE) {
   auto* creation=reinterpret_cast<const CREATESTRUCTW*>(l);
   SetWindowLongPtrW(window,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(creation->lpCreateParams));
  }
  auto* self=reinterpret_cast<OnlineClient*>(GetWindowLongPtrW(window,GWLP_USERDATA));
  if(!self)return DefWindowProcW(window,message,w,l);
  switch(message) {
   case WM_SIZE:self->Layout();break;
   case WM_CLOSE:
    if(self->browser_&&!self->browser_->GetHost()->TryCloseBrowser())return 0;
    break;
   case WM_NCDESTROY:
    SetWindowLongPtrW(window,GWLP_USERDATA,0);self->window_=nullptr;break;
   case WM_COMMAND:
    if(self->browser_&&HIWORD(w)==BN_CLICKED) {
     switch(LOWORD(w)) {
      case Back:self->browser_->GoBack();return 0;
      case Forward:self->browser_->GoForward();return 0;
      case Reload:self->browser_->Reload();return 0;
      case Go:self->Navigate();return 0;
     }
    }
    break;
  }
  return DefWindowProcW(window,message,w,l);
 }
 IMPLEMENT_REFCOUNTING(OnlineClient);
};
class OnlineApp final : public CefApp, public CefBrowserProcessHandler {
 public:
 explicit OnlineApp(const PrivateOwner* owner):owner_(owner){}
 void OnBeforeCommandLineProcessing(const CefString& type,CefRefPtr<CefCommandLine> command) override {
  if(type.empty()&&owner_){command->AppendSwitch("disable-chrome-login-prompt");command->AppendSwitchWithValue("proxy-server","http://127.0.0.1:"+std::to_string(owner_->offer.port));command->AppendSwitchWithValue("proxy-bypass-list","<-loopback>");}
  command->AppendSwitch("disable-quic");command->AppendSwitch("disable-dns-prefetch");
  command->AppendSwitchWithValue("force-webrtc-ip-handling-policy","disable_non_proxied_udp");
 }

 CefRefPtr<CefBrowserProcessHandler> GetBrowserProcessHandler() override {return this;}
 void OnContextInitialized() override {
   if(!owner_){CefQuitMessageLoop();return;}
   client_=new OnlineClient(owner_);
   if(!client_->OpenWindow())CefQuitMessageLoop();
 }
 private:
 const PrivateOwner* owner_;
 // Retain the native window's callback target until the CEF message loop exits.
 CefRefPtr<OnlineClient> client_;
 IMPLEMENT_REFCOUNTING(OnlineApp);
};
}
