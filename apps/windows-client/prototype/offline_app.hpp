#pragma once
#include "admission_protocol.hpp"
#include "include/cef_app.h"
#include "include/cef_client.h"
#include "include/cef_request_handler.h"
#include "include/cef_resource_request_handler.h"
#include "include/cef_download_handler.h"
#include "include/cef_life_span_handler.h"
namespace orangespace::prototype {
class OfflineClient final : public CefClient, public CefLifeSpanHandler,
 public CefRequestHandler, public CefResourceRequestHandler, public CefDownloadHandler {
 public:
 CefRefPtr<CefLifeSpanHandler> GetLifeSpanHandler() override {return this;}
 CefRefPtr<CefRequestHandler> GetRequestHandler() override {return this;}
 CefRefPtr<CefDownloadHandler> GetDownloadHandler() override {return this;}
 void OnBeforeClose(CefRefPtr<CefBrowser>) override {CefQuitMessageLoop();}
 bool OnBeforePopup(CefRefPtr<CefBrowser>,CefRefPtr<CefFrame>,int,const CefString&,
   const CefString&,cef_window_open_disposition_t,bool,const CefPopupFeatures&,CefWindowInfo&,
   CefRefPtr<CefClient>&,CefBrowserSettings&,CefRefPtr<CefDictionaryValue>&,bool*) override {return true;}
 bool CanDownload(CefRefPtr<CefBrowser>,const CefString&,const CefString&) override {return false;}
 void OnDownloadUpdated(CefRefPtr<CefBrowser>,CefRefPtr<CefDownloadItem>,
   CefRefPtr<CefDownloadItemCallback> callback) override {callback->Cancel();}
 bool OnBeforeBrowse(CefRefPtr<CefBrowser>,CefRefPtr<CefFrame>,CefRefPtr<CefRequest> request,bool,bool) override {
   return !AllowedNavigation(request->GetURL().ToString());
 }
 CefRefPtr<CefResourceRequestHandler> GetResourceRequestHandler(CefRefPtr<CefBrowser>,
   CefRefPtr<CefFrame>,CefRefPtr<CefRequest>,bool,bool,const CefString&,bool& disable) override {
   disable=false; return this;
 }
 ReturnValue OnBeforeResourceLoad(CefRefPtr<CefBrowser>,CefRefPtr<CefFrame>,
   CefRefPtr<CefRequest> request,CefRefPtr<CefCallback>) override {
   return AllowedNavigation(request->GetURL().ToString())?RV_CONTINUE:RV_CANCEL;
 }
 void OnProtocolExecution(CefRefPtr<CefBrowser>,CefRefPtr<CefFrame>,CefRefPtr<CefRequest>,bool& allow) override {allow=false;}
 private: IMPLEMENT_REFCOUNTING(OfflineClient);
};
class OfflineApp final : public CefApp, public CefBrowserProcessHandler {
 public:
 CefRefPtr<CefBrowserProcessHandler> GetBrowserProcessHandler() override {return this;}
 void OnContextInitialized() override {
   CefWindowInfo window; window.SetAsPopup(nullptr,L"OrangeSpace - offline prototype");
   window.bounds={0,0,1000,720};
   CefBrowserSettings settings; settings.javascript=STATE_DISABLED;
   if(!CefBrowserHost::CreateBrowser(window,new OfflineClient,kOfflineUrl,settings,nullptr,nullptr)) CefQuitMessageLoop();
 }
 private: IMPLEMENT_REFCOUNTING(OfflineApp);
};
}
