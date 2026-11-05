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
namespace orangespace::prototype {
class BrowserCommandTask final : public CefTask {
 CefRefPtr<CefBrowser> browser_;BrowserFrame frame_;
 public: BrowserCommandTask(CefRefPtr<CefBrowser> b,BrowserFrame f):browser_(b),frame_(f){}
 void Execute() override {switch(frame_.command){
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
  std::lock_guard lock(owner_->browser_mutex);owner_->browser_state.phase=3;
  owner_->browser_command=[browser](BrowserFrame f){if(!CefPostTask(TID_UI,new BrowserCommandTask(browser,f)))TerminateProcess(GetCurrentProcess(),71);};
 }
 template<std::size_t N> static void text(std::array<char,N>& out,std::uint32_t& length,std::string value){
  auto n=std::min(value.size(),N);while(n<value.size()&&n&&(static_cast<unsigned char>(value[n])&0xc0)==0x80)--n;
  out.fill(0);std::memcpy(out.data(),value.data(),n);length=static_cast<std::uint32_t>(n);
 }
 void OnAddressChange(CefRefPtr<CefBrowser>,CefRefPtr<CefFrame> frame,const CefString& url) override {
  if(!frame->IsMain())return;auto value=url.ToString();if(!OnlineNavigation(value))return;
  std::lock_guard lock(owner_->browser_mutex);text(owner_->browser_state.url,owner_->browser_state.url_size,std::move(value));
 }
 void OnTitleChange(CefRefPtr<CefBrowser>,const CefString& title) override {
  std::lock_guard lock(owner_->browser_mutex);text(owner_->browser_state.title,owner_->browser_state.title_size,title.ToString());
 }
 void OnLoadingStateChange(CefRefPtr<CefBrowser>,bool loading,bool back,bool forward) override {
  std::lock_guard lock(owner_->browser_mutex);auto&s=owner_->browser_state;s.loading=loading;s.back=back;s.forward=forward;
 }
 void OnBeforeClose(CefRefPtr<CefBrowser>) override {
  {std::lock_guard lock(owner_->browser_mutex);owner_->browser_state.phase=0;owner_->browser_command={};}
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
 private: const PrivateOwner* owner_; IMPLEMENT_REFCOUNTING(OnlineClient);
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
   CefWindowInfo window; window.SetAsPopup(nullptr,L"OrangeSpace - Singapore prototype");
   window.runtime_style=CEF_RUNTIME_STYLE_ALLOY;
   window.bounds={0,0,1000,720};
   CefBrowserSettings settings; settings.javascript=STATE_ENABLED;
   if(!CefBrowserHost::CreateBrowser(window,new OnlineClient(owner_),"https://example.com/",settings,nullptr,nullptr)) CefQuitMessageLoop();
 }
 private: const PrivateOwner* owner_; IMPLEMENT_REFCOUNTING(OnlineApp);
};
}
