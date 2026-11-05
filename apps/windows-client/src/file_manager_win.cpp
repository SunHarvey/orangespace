#ifndef UNICODE
#define UNICODE
#define _UNICODE
#endif
#include "orangespace/file_manager_win.hpp"
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <algorithm>
#include <condition_variable>
#include <deque>
#include <filesystem>
#include <mutex>
#include <thread>
#include <vector>

namespace orangespace::files {
namespace {
constexpr COLORREF orange = RGB(255,122,22), background = RGB(247,248,250);
std::wstring wide(const std::string& s) {
  if (s.empty()) return {};
  const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0);
  if (!n) return L"—";
  std::wstring r(static_cast<std::size_t>(n), L' ');
  MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),r.data(),n); return r;
}
std::string utf8(const std::wstring& s) {
  if (s.empty()) return {};
  const int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0,nullptr,nullptr);
  if (!n) throw std::runtime_error("invalid name");
  std::string r(static_cast<std::size_t>(n),' ');
  WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),r.data(),n,nullptr,nullptr); return r;
}
std::wstring text(HWND w) { const int n=GetWindowTextLengthW(w); std::wstring s(static_cast<std::size_t>(n)+1,L'\0'); GetWindowTextW(w,s.data(),n+1); s.resize(static_cast<std::size_t>(n)); return s; }
std::string joined(const std::string& dir,const std::string& leaf) { return dir.empty()?leaf:dir+"/"+leaf; }
void cell(HWND list,int row,int col,const std::wstring& value) {
  LVITEMW v{}; v.iItem=row; v.iSubItem=col; v.mask=LVIF_TEXT; v.pszText=const_cast<wchar_t*>(value.c_str());
  if(col==0) ListView_InsertItem(list,&v); else ListView_SetItem(list,&v);
}
std::wstring modified(const Entry& e) {
  if(!e.modified_at_ns || *e.modified_at_ns<0) return L"—";
  const auto ticks=static_cast<ULONGLONG>(*e.modified_at_ns/100)+116444736000000000ULL;
  FILETIME ft{static_cast<DWORD>(ticks),static_cast<DWORD>(ticks>>32)}, local{}; SYSTEMTIME st{};
  if(!FileTimeToLocalFileTime(&ft,&local)||!FileTimeToSystemTime(&local,&st)) return L"—";
  wchar_t b[40]{}; swprintf(b,40,L"%04u-%02u-%02u %02u:%02u",st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute); return b;
}
enum : int { Upload=301,Download,MakeDir,Filter,Up,Crumb,Tasks,Cancel,Retry,Back,RemoteTree,RemoteList,TaskList };
enum class Kind { List, Mkdir, Upload, Download };
enum class State { Queued, Running, Complete, Failed, Cancelled };
const wchar_t* label(State s) {
  switch(s) {case State::Queued:return L"等待中";case State::Running:return L"传输中";case State::Complete:return L"已完成";case State::Failed:return L"失败，可重试";case State::Cancelled:return L"已取消";} return L"—";
}
struct Job {
  panel_detail::TaskPin pin;
  const panel_detail::Scope& scope;
  const Kind kind;
  FileContext context;
  std::shared_ptr<FileClient> client;
  std::string remote;
  std::wstring local, name;
  std::atomic<bool>& cancel;
  std::atomic<bool> done{false};
  bool observed{false};
  std::atomic<bool> destination_exists{false};
  std::atomic<std::uint64_t> bytes{0},total{0};
  std::atomic<State> state{State::Queued};
  std::vector<Entry> entries;
  Job(panel_detail::Scope s, Kind k, FileContext c):pin(std::move(s)),scope(pin.scope()),kind(k),context(std::move(c)),cancel(pin.cancellation()) {}
};
}
struct FilePanel::Impl {
  HWND hwnd{},parent{},title{},subtitle{},upload{},download{},mkdir{},filter{},up{},crumb{},tree{},list{},tasks{},tasklist{},cancel{},retry{},note{},back{};
  HINSTANCE instance{}; HFONT font{},heading{}; HBRUSH brush{};
  FileContext current; std::string directory; std::uint64_t epoch{1}, view{0};
  std::vector<Entry> entries; std::vector<std::size_t> visible;
  std::vector<std::shared_ptr<Job>> jobs, taskrows;
  std::shared_ptr<Job> listing;
  std::mutex mutex; std::condition_variable wake; std::deque<std::shared_ptr<Job>> queue;
  std::thread worker; bool stopping{false},expanded{true},rendering{false};
  int dpi{96};
  explicit Impl(HWND p,HINSTANCE i):parent(p),instance(i) {
    INITCOMMONCONTROLSEX cc{sizeof(cc),ICC_LISTVIEW_CLASSES|ICC_TREEVIEW_CLASSES}; InitCommonControlsEx(&cc);
    WNDCLASSW wc{}; wc.lpfnWndProc=proc; wc.hInstance=i; wc.lpszClassName=L"OrangeSpaceFilePanelV2"; wc.hCursor=LoadCursor(nullptr,IDC_ARROW); RegisterClassW(&wc);
    brush=CreateSolidBrush(background);
    hwnd=CreateWindowExW(0,wc.lpszClassName,L"",WS_CHILD|WS_CLIPCHILDREN,0,0,100,100,p,nullptr,i,this);
    if(!hwnd) throw std::runtime_error("file panel unavailable");
    dpi=static_cast<int>(GetDpiForWindow(hwnd)); if(!dpi)dpi=96;
    font=CreateFontW(-MulDiv(13,dpi,96),0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Microsoft YaHei UI");
    heading=CreateFontW(-MulDiv(18,dpi,96),0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Microsoft YaHei UI");
    title=control(L"STATIC",L"个人文件",0,0); subtitle=control(L"STATIC",L"",0,0);
    SendMessageW(title,WM_SETFONT,reinterpret_cast<WPARAM>(heading),TRUE);
    upload=control(L"BUTTON",L"↑  上传文件",BS_OWNERDRAW,Upload); download=control(L"BUTTON",L"↓  下载到本机",BS_PUSHBUTTON,Download);
    mkdir=control(L"BUTTON",L"新建文件夹",BS_PUSHBUTTON,MakeDir); up=control(L"BUTTON",L"↑",BS_PUSHBUTTON,Up);
    crumb=control(L"EDIT",L"个人文件",ES_READONLY|ES_AUTOHSCROLL,Crumb);
    filter=control(L"EDIT",L"",ES_AUTOHSCROLL|WS_BORDER,Filter); SendMessageW(filter,EM_SETCUEBANNER,TRUE,reinterpret_cast<LPARAM>(L"搜索当前目录"));
    back=control(L"BUTTON",L"← 返回浏览器",BS_PUSHBUTTON,Back);
    tree=control(WC_TREEVIEWW,L"",TVS_HASBUTTONS|TVS_HASLINES|TVS_LINESATROOT|TVS_SHOWSELALWAYS,RemoteTree);
    list=control(WC_LISTVIEWW,L"",LVS_REPORT|LVS_SHOWSELALWAYS,RemoteList);
    ListView_SetExtendedListViewStyle(list,LVS_EX_CHECKBOXES|LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER);
    columns(list,{L"名称",L"大小",L"修改时间"});
    tasks=control(L"BUTTON",L"传输任务  ▾",BS_PUSHBUTTON,Tasks);
    tasklist=control(WC_LISTVIEWW,L"",LVS_REPORT|LVS_SINGLESEL|LVS_SHOWSELALWAYS,TaskList);
    ListView_SetExtendedListViewStyle(tasklist,LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER);
    columns(tasklist,{L"文件名",L"方向 / 节点",L"字节 / 进度",L"状态"});
    cancel=control(L"BUTTON",L"取消任务",BS_PUSHBUTTON,Cancel); retry=control(L"BUTTON",L"重试",BS_PUSHBUTTON,Retry);
    note=control(L"STATIC",L"当前账号在该节点的个人目录 · 拖入本机文件上传到当前目录",0,0);
    DragAcceptFiles(hwnd,TRUE); layout();
  }
  ~Impl() { stop(); if(hwnd)DestroyWindow(hwnd); DeleteObject(font);DeleteObject(heading);DeleteObject(brush); }
  HWND control(const wchar_t* cls,const wchar_t* value,DWORD style,int id) {
    HWND w=CreateWindowExW(0,cls,value,WS_CHILD|WS_VISIBLE|WS_TABSTOP|style,0,0,1,1,hwnd,reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),instance,nullptr);
    SendMessageW(w,WM_SETFONT,reinterpret_cast<WPARAM>(font),TRUE); return w;
  }
  static void columns(HWND w,std::initializer_list<const wchar_t*> names) {
    int n=0;for(auto name:names){LVCOLUMNW c{};c.mask=LVCF_TEXT|LVCF_WIDTH;c.pszText=const_cast<wchar_t*>(name);c.cx=180;ListView_InsertColumn(w,n++,&c);}
  }
  void layout() {
    if(!title)return;
    RECT r{};GetClientRect(hwnd,&r);const int w=MulDiv(r.right,96,dpi),h=MulDiv(r.bottom,96,dpi);
    auto move=[&](HWND c,int x,int y,int cw,int ch){MoveWindow(c,MulDiv(x,dpi,96),MulDiv(y,dpi,96),MulDiv(std::max(1,cw),dpi,96),MulDiv(std::max(1,ch),dpi,96),TRUE);};
    move(title,20,12,180,28);move(subtitle,20,43,w-220,22);move(back,w-155,16,140,30);
    move(upload,16,78,115,34);move(download,140,78,130,34);move(mkdir,280,78,120,34);move(filter,std::max(420,w-260),78,244,34);
    move(up,16,121,36,28);move(crumb,62,121,w-78,28);
    const int bottom=expanded?174:64, content=std::max(40,h-155-bottom);
    move(tree,12,155,175,content);move(list,195,155,w-207,content);
    move(tasks,12,h-bottom,190,29);move(cancel,w-200,h-bottom,100,29);move(retry,w-94,h-bottom,80,29);
    move(tasklist,12,h-bottom+33,w-24,110);move(note,16,h-25,w-32,22);
    ShowWindow(tasklist,expanded?SW_SHOW:SW_HIDE);ShowWindow(cancel,expanded?SW_SHOW:SW_HIDE);ShowWindow(retry,expanded?SW_SHOW:SW_HIDE);
    ListView_SetColumnWidth(list,0,MulDiv(std::max(100,w-485),dpi,96));ListView_SetColumnWidth(list,1,MulDiv(100,dpi,96));ListView_SetColumnWidth(list,2,MulDiv(170,dpi,96));
    for(int c=0;c<4;++c)ListView_SetColumnWidth(tasklist,c,MulDiv(c==0?std::max(110,w-590):185,dpi,96));
  }
  void start() {
    if(worker.joinable())return;
    stopping=false;
    worker=std::thread([this]{
      for(;;){std::shared_ptr<Job> job;{std::unique_lock lock(mutex);wake.wait(lock,[this]{return stopping||!queue.empty();});if(stopping&&queue.empty())return;job=queue.front();queue.pop_front();}
        if(job->cancel.load()){job->state=State::Cancelled;job->done=true;continue;}
        job->state=State::Running;
        try {
          job->client=std::make_shared<FileClient>(job->context);
          auto progress=[job](std::uint64_t b,std::uint64_t t){job->bytes=b;job->total=t;};
          switch(job->kind){case Kind::List:job->entries=job->client->list(job->remote,job->cancel);break;
            case Kind::Mkdir:job->client->mkdir(job->remote,job->cancel);break;
            case Kind::Upload:job->client->upload(std::filesystem::path(job->local),job->remote,job->cancel,progress);break;
            case Kind::Download:
              if(GetFileAttributesW(job->local.c_str())!=INVALID_FILE_ATTRIBUTES){job->destination_exists=true;throw std::system_error(ERROR_FILE_EXISTS,std::system_category());}
              job->client->download(job->remote,std::filesystem::path(job->local),job->cancel,progress);break;}
          job->state=job->cancel.load()?State::Cancelled:State::Complete;
        }catch(const Cancelled&){job->state=State::Cancelled;}catch(const std::system_error& e){job->destination_exists=e.code().value()==ERROR_FILE_EXISTS||e.code().value()==ERROR_ALREADY_EXISTS;job->state=job->cancel.load()?State::Cancelled:State::Failed;}catch(...){job->state=job->cancel.load()?State::Cancelled:State::Failed;}
        job->done.store(true);
      }
    });
  }
  void stop() {
    for(auto& j:jobs)j->cancel=true;
    {std::lock_guard lock(mutex);stopping=true;for(auto& j:queue){j->cancel=true;j->state=State::Cancelled;j->done=true;}queue.clear();}
    wake.notify_all();if(worker.joinable())worker.join();
  }
  void error(const wchar_t* s=L"操作失败，请重试。") { MessageBoxW(hwnd,s,L"个人文件",MB_OK|MB_ICONWARNING); }
  void admit(const std::shared_ptr<Job>& j) {
    jobs.push_back(j);
    try {
      start();
      std::lock_guard lock(mutex);
      queue.push_back(j);
    } catch(...) {
      // No queue owner was published: vector/deque insertion has strong rollback.
      j->state=State::Failed;j->done=true;
      throw;
    }
    wake.notify_one();
  }
  std::shared_ptr<Job> enqueue(Kind kind,const std::string& remote,const std::wstring& local={},const std::wstring& name={}) {
    if(!current.central_envelope||!current.platform)return {};
    // Main provided the immutable envelope while its Session was idle.
    // Worker restores its own Session; never retain the mutable UI Session.
    auto j=std::make_shared<Job>(panel_detail::Scope{current.central_user_id,current.sandbox_id,current.node_id,directory,epoch},kind,current);
    j->context.session.reset();j->remote=remote;j->local=local;j->name=name;
    admit(j);return j;
  }
  void refresh() {
    if(listing)listing->cancel=true;
    ++view;entries.clear();render_list();rendering=true;TreeView_DeleteAllItems(tree);rendering=false;
    SetWindowTextW(crumb,wide(directory.empty()?"个人文件":"个人文件 / "+directory).c_str());
    listing=enqueue(Kind::List,directory);
  }
  void render_list() {
    ListView_DeleteAllItems(list);visible.clear();std::wstring query=text(filter);
    std::transform(query.begin(),query.end(),query.begin(),towlower);
    for(std::size_t i=0;i<entries.size();++i){auto name=wide(entries[i].name),fold=name;std::transform(fold.begin(),fold.end(),fold.begin(),towlower);if(fold.find(query)==std::wstring::npos)continue;
      const int row=static_cast<int>(visible.size());visible.push_back(i);cell(list,row,0,(entries[i].is_directory?L"▸  ":L"    ")+name);cell(list,row,1,entries[i].is_directory?L"—":std::to_wstring(entries[i].size)+L" B");cell(list,row,2,modified(entries[i]));}
  }
  void render_tree() {
    rendering=true;TreeView_DeleteAllItems(tree);TVINSERTSTRUCTW t{};t.hParent=TVI_ROOT;t.hInsertAfter=TVI_LAST;t.item.mask=TVIF_TEXT|TVIF_PARAM;t.item.pszText=const_cast<wchar_t*>(L"个人文件");t.item.lParam=-1;auto root=TreeView_InsertItem(tree,&t);
    if(!directory.empty()){t.hParent=root;
      auto path=wide(directory);t.item.pszText=path.data();t.item.lParam=-2;auto node=TreeView_InsertItem(tree,&t);t.hParent=node;}
    else t.hParent=root;
    for(std::size_t i=0;i<entries.size();++i)if(entries[i].is_directory){auto name=wide(entries[i].name);t.item.pszText=name.data();t.item.lParam=static_cast<LPARAM>(i);TreeView_InsertItem(tree,&t);}
    TreeView_Expand(tree,root,TVE_EXPAND);if(t.hParent!=root)TreeView_Expand(tree,t.hParent,TVE_EXPAND);rendering=false;
  }
  void render_tasks() {
    int selected=ListView_GetNextItem(tasklist,-1,LVNI_SELECTED);ListView_DeleteAllItems(tasklist);taskrows.clear();
    for(auto& j:jobs){if(j->kind==Kind::List||j->kind==Kind::Mkdir||j->scope.user_id!=current.central_user_id)continue;
      int row=static_cast<int>(taskrows.size());taskrows.push_back(j);cell(tasklist,row,0,j->name.empty()?L"已保留的任务":j->name);
      cell(tasklist,row,1,(j->kind==Kind::Upload?L"↑ 上传到 ":L"↓ 下载自 ")+wide(j->context.node_name));
      auto b=j->bytes.load(),t=j->total.load();std::wstring bytes=std::to_wstring(b)+L" B / "+(t?std::to_wstring(t)+L" B":L"总量未知");
      if(t)bytes+=L" · "+std::to_wstring(static_cast<unsigned>(std::min<long double>(100,static_cast<long double>(b)*100/t)))+L"%";
      cell(tasklist,row,2,bytes);cell(tasklist,row,3,j->destination_exists.load()?L"本机文件已存在，请选择其他保存位置":label(j->state.load()));}
    if(selected>=0&&selected<static_cast<int>(taskrows.size()))ListView_SetItemState(tasklist,selected,LVIS_SELECTED,LVIS_SELECTED);
    SetWindowTextW(tasks,(L"传输任务 ("+std::to_wstring(taskrows.size())+L")  "+(expanded?L"▾":L"▴")).c_str());
  }
  void poll() {
    if(listing&&listing->done.load()){
      auto j=listing;listing.reset();if(j->pin.publishable(current.central_user_id,epoch)&&j->scope.sandbox_id==current.sandbox_id&&j->scope.node_id==current.node_id){
        if(j->state==State::Complete){entries=std::move(j->entries);render_list();render_tree();SetWindowTextW(note,L"当前账号在该节点的个人目录 · 拖入本机文件上传到当前目录");}
        else SetWindowTextW(note,L"目录读取失败 · 点击上级目录可重试");}
    }
    bool refresh_needed=false;
    for(auto& j:jobs)if(j->done.load()&&!j->observed){j->observed=true;j->client.reset();if(j->kind==Kind::Mkdir&&j->state==State::Failed&&j->pin.publishable(current.central_user_id,epoch))SetWindowTextW(note,L"新建文件夹失败，请重试。");if((j->kind==Kind::Upload||j->kind==Kind::Mkdir)&&j->state==State::Complete&&j->scope.epoch==epoch&&j->scope.user_id==current.central_user_id&&j->scope.node_id==current.node_id&&j->scope.directory==directory)refresh_needed=true;}
    if(refresh_needed&&!listing)refresh();
    render_tasks();
  }
  void upload_file(const std::wstring& path) {
    // File validation and IO happen in FileClient's worker, not on UI thread.
    auto name=std::filesystem::path(path).filename().wstring();enqueue(Kind::Upload,joined(directory,utf8(name)),path,name);
  }
  void pick_upload() {
    const auto owner=current;const auto original_dir=directory;const auto original_epoch=epoch;
    std::vector<wchar_t> paths(65536,L'\0');OPENFILENAMEW of{};of.lStructSize=sizeof(of);of.hwndOwner=hwnd;of.lpstrFile=paths.data();of.nMaxFile=static_cast<DWORD>(paths.size());of.lpstrTitle=L"选择上传文件";of.Flags=OFN_EXPLORER|OFN_ALLOWMULTISELECT|OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST|OFN_NOCHANGEDIR;
    if(!GetOpenFileNameW(&of))return;
    if(original_epoch!=epoch||owner.central_user_id!=current.central_user_id||owner.node_id!=current.node_id||owner.sandbox_id!=current.sandbox_id||original_dir!=directory)return;
    std::wstring first=paths.data();const wchar_t* next=paths.data()+first.size()+1;
    if(!*next)upload_file(first);else for(;*next;next+=wcslen(next)+1)upload_file((std::filesystem::path(first)/next).wstring());
  }
  void pick_download() {
    std::vector<std::size_t> checked;for(std::size_t row=0;row<visible.size();++row)if(ListView_GetCheckState(list,static_cast<int>(row)))checked.push_back(visible[row]);
    if(checked.empty()){int row=ListView_GetNextItem(list,-1,LVNI_SELECTED);if(row>=0)checked.push_back(visible[static_cast<std::size_t>(row)]);}
    if(checked.empty()){error(L"请先选择文件。");return;}
    std::vector<Entry> selected;for(auto index:checked)selected.push_back(entries[index]);
    const auto owner=current;const auto original_dir=directory;const auto original_epoch=epoch;
    for(const auto& e:selected){if(e.is_directory){error(L"暂不支持整个文件夹下载，请进入文件夹选择文件。");continue;}
      std::vector<wchar_t> path(32768,L'\0');auto name=wide(e.name);std::copy_n(name.data(),std::min(name.size(),path.size()-1),path.data());
      OPENFILENAMEW of{};of.lStructSize=sizeof(of);of.hwndOwner=hwnd;of.lpstrFile=path.data();of.nMaxFile=static_cast<DWORD>(path.size());of.lpstrTitle=L"保存到本机（不覆盖已有文件）";of.Flags=OFN_EXPLORER|OFN_PATHMUSTEXIST|OFN_NOCHANGEDIR;
      if(GetSaveFileNameW(&of)){
        if(original_epoch!=epoch||owner.central_user_id!=current.central_user_id||owner.node_id!=current.node_id||owner.sandbox_id!=current.sandbox_id||original_dir!=directory)return;
        enqueue(Kind::Download,e.path,path.data(),name);
      }
    }
  }
  struct NameDialog { HWND window{},edit{}; bool done{},accepted{}; std::wstring value; };
  static LRESULT CALLBACK name_proc(HWND w,UINT m,WPARAM a,LPARAM b) {
    auto* d=reinterpret_cast<NameDialog*>(GetWindowLongPtrW(w,GWLP_USERDATA));
    if(m==WM_NCCREATE){d=static_cast<NameDialog*>(reinterpret_cast<CREATESTRUCTW*>(b)->lpCreateParams);SetWindowLongPtrW(w,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(d));}
    try {
      if(d&&m==WM_COMMAND){if(LOWORD(a)==IDOK){d->value=text(d->edit);d->accepted=true;d->done=true;}if(LOWORD(a)==IDCANCEL)d->done=true;return 0;}
    } catch(...) {if(d){d->accepted=false;d->done=true;}return 0;}
    if(d&&m==WM_CLOSE){d->done=true;return 0;}return DefWindowProcW(w,m,a,b);
  }
  struct ModalOwner {
    HWND parent,window;BOOL enabled;
    ModalOwner(HWND p,HWND w):parent(p),window(w),enabled(IsWindowEnabled(p)){EnableWindow(parent,FALSE);}
    ~ModalOwner(){DestroyWindow(window);EnableWindow(parent,enabled);}
  };
  void make_dir() {
    const auto owner=current;const auto original_dir=directory;const auto original_epoch=epoch;
    WNDCLASSW wc{};wc.lpfnWndProc=name_proc;wc.hInstance=instance;wc.lpszClassName=L"OrangeSpaceFolderNameV2";wc.hbrBackground=reinterpret_cast<HBRUSH>(COLOR_WINDOW+1);wc.hCursor=LoadCursor(nullptr,IDC_ARROW);RegisterClassW(&wc);
    NameDialog d;d.window=CreateWindowExW(WS_EX_DLGMODALFRAME,wc.lpszClassName,L"新建文件夹",WS_POPUP|WS_CAPTION|WS_SYSMENU,0,0,370,145,hwnd,nullptr,instance,&d);
    if(!d.window)return;
    RECT r{};GetWindowRect(hwnd,&r);SetWindowPos(d.window,HWND_TOP,r.left+60,r.top+100,0,0,SWP_NOSIZE);
    d.edit=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL,16,15,320,27,d.window,nullptr,instance,nullptr);
    CreateWindowW(L"BUTTON",L"创建",WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_DEFPUSHBUTTON,165,58,80,28,d.window,reinterpret_cast<HMENU>(IDOK),instance,nullptr);
    CreateWindowW(L"BUTTON",L"取消",WS_CHILD|WS_VISIBLE|WS_TABSTOP,255,58,80,28,d.window,reinterpret_cast<HMENU>(IDCANCEL),instance,nullptr);
    {
      ModalOwner modal(parent,d.window);
      SendMessageW(d.edit,EM_SETLIMITTEXT,240,0);ShowWindow(d.window,SW_SHOW);SetFocus(d.edit);
      MSG msg{};while(!d.done){const BOOL got=GetMessageW(&msg,nullptr,0,0);if(got<=0){if(!got)PostQuitMessage(static_cast<int>(msg.wParam));break;}if(msg.message==WM_KEYDOWN&&msg.wParam==VK_RETURN){name_proc(d.window,WM_COMMAND,IDOK,0);continue;}if(msg.message==WM_KEYDOWN&&msg.wParam==VK_ESCAPE)break;if(!IsDialogMessageW(d.window,&msg)){TranslateMessage(&msg);DispatchMessageW(&msg);}}
    }
    SetFocus(hwnd);
    if(d.accepted){
      if(original_epoch!=epoch||owner.central_user_id!=current.central_user_id||owner.node_id!=current.node_id||owner.sandbox_id!=current.sandbox_id||original_dir!=directory)return;
      auto name=utf8(d.value);if(name.empty()||name=="."||name==".."||name.find_first_of("/\\")!=std::string::npos){error(L"请输入有效文件夹名称。");return;}enqueue(Kind::Mkdir,joined(directory,name));}
  }
  void navigate(std::string path) {directory=std::move(path);refresh();}
  void command(int id) {
    switch(id){case Upload:pick_upload();break;case Download:pick_download();break;case MakeDir:make_dir();break;
      case Up:{auto slash=directory.rfind('/');navigate(slash==std::string::npos?"":directory.substr(0,slash));break;}
      case Tasks:expanded=!expanded;layout();break;case Back:PostMessageW(parent, ReturnToBrowserMessage, 0, 0);break;
      case Cancel:case Retry:{int row=ListView_GetNextItem(tasklist,-1,LVNI_SELECTED);if(row<0||row>=static_cast<int>(taskrows.size()))return;auto j=taskrows[static_cast<std::size_t>(row)];
        if(id==Cancel)j->cancel=true;
        else if(j->done.load()&&(j->state==State::Failed||j->state==State::Cancelled)&&j->scope.epoch==epoch&&j->scope.user_id==current.central_user_id){
          // Retry uses the original context and directory, not current tab.
          auto next=std::make_shared<Job>(j->scope,j->kind,j->context);next->remote=j->remote;next->local=j->local;next->name=j->name;admit(next);}
        break;}default:break;}
  }
  static LRESULT CALLBACK proc(HWND w,UINT m,WPARAM a,LPARAM b) {
    auto* self=reinterpret_cast<Impl*>(GetWindowLongPtrW(w,GWLP_USERDATA));
    if(m==WM_NCCREATE){self=static_cast<Impl*>(reinterpret_cast<CREATESTRUCTW*>(b)->lpCreateParams);self->hwnd=w;SetWindowLongPtrW(w,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(self));}
    if(!self)return DefWindowProcW(w,m,a,b);
    try {switch(m){case WM_SIZE:self->layout();return 0;
      case WM_ERASEBKGND:{RECT r{};GetClientRect(w,&r);FillRect(reinterpret_cast<HDC>(a),&r,self->brush);return 1;}
      case WM_CTLCOLORSTATIC:case WM_CTLCOLOREDIT:SetBkColor(reinterpret_cast<HDC>(a),RGB(255,255,255));SetTextColor(reinterpret_cast<HDC>(a),RGB(40,44,51));return reinterpret_cast<LRESULT>(GetStockObject(WHITE_BRUSH));
      case WM_DRAWITEM:{auto* d=reinterpret_cast<DRAWITEMSTRUCT*>(b);if(d->CtlID==Upload){HBRUSH fill=CreateSolidBrush((d->itemState&ODS_SELECTED)?RGB(226,101,13):orange);FillRect(d->hDC,&d->rcItem,fill);DeleteObject(fill);SetBkMode(d->hDC,TRANSPARENT);SetTextColor(d->hDC,RGB(255,255,255));auto s=text(d->hwndItem);DrawTextW(d->hDC,s.c_str(),-1,&d->rcItem,DT_CENTER|DT_VCENTER|DT_SINGLELINE);if(d->itemState&ODS_FOCUS)DrawFocusRect(d->hDC,&d->rcItem);return TRUE;}break;}
      case WM_COMMAND:if(LOWORD(a)==Filter&&HIWORD(a)==EN_CHANGE)self->render_list();else self->command(LOWORD(a));return 0;
      case WM_NOTIFY:{auto* n=reinterpret_cast<NMHDR*>(b);if(n->idFrom==RemoteList&&n->code==NM_DBLCLK){int row=ListView_GetNextItem(self->list,-1,LVNI_SELECTED);if(row>=0&&row<static_cast<int>(self->visible.size())){auto e=self->entries[self->visible[static_cast<std::size_t>(row)]];if(e.is_directory)self->navigate(e.path);}}
        if(n->idFrom==RemoteTree&&n->code==TVN_SELCHANGEDW&&!self->rendering){auto* t=reinterpret_cast<NMTREEVIEWW*>(b);auto index=t->itemNew.lParam;if(index==-1)self->navigate("");else if(index>=0&&static_cast<std::size_t>(index)<self->entries.size())self->navigate(self->entries[static_cast<std::size_t>(index)].path);}return 0;}
      case WM_DROPFILES:{HDROP drop=reinterpret_cast<HDROP>(a);const UINT count=DragQueryFileW(drop,0xFFFFFFFF,nullptr,0);try{for(UINT i=0;i<count;++i){const UINT size=DragQueryFileW(drop,i,nullptr,0);std::wstring path(size+1,L'\0');DragQueryFileW(drop,i,path.data(),size+1);path.resize(size);self->upload_file(path);}}catch(...){DragFinish(drop);throw;}DragFinish(drop);return 0;}
      default:break;}}
    catch(...){self->error();}return DefWindowProcW(w,m,a,b);
  }
};
FilePanel::FilePanel(HWND p,HINSTANCE i):impl_(std::make_unique<Impl>(p,i)) {}
FilePanel::~FilePanel()=default;
HWND FilePanel::window() const noexcept{return impl_->hwnd;}
void FilePanel::show(const FileContext& context){
  auto& p=*impl_;if(!p.current.central_user_id.empty()&&p.current.central_user_id!=context.central_user_id)logout();
  const bool changed=p.current.central_user_id!=context.central_user_id||p.current.sandbox_id!=context.sandbox_id||p.current.node_id!=context.node_id;
  p.current=context;p.current.session.reset();SetWindowTextW(p.subtitle,(wide(context.node_name)+L" · "+wide(context.username)+L" 的 Linux 个人目录").c_str());
  ShowWindow(p.hwnd,SW_SHOW);if(changed){p.directory.clear();SetWindowTextW(p.filter,L"");try{p.refresh();}catch(...){p.error();}}p.render_tasks();
}
void FilePanel::hide(){ShowWindow(impl_->hwnd,SW_HIDE);}
void FilePanel::request_logout(){auto& p=*impl_;++p.epoch;
  for(auto& j:p.jobs)j->cancel=true;
  p.listing.reset();p.current={};p.directory.clear();p.entries.clear();p.visible.clear();
  ListView_DeleteAllItems(p.list);ListView_DeleteAllItems(p.tasklist);TreeView_DeleteAllItems(p.tree);p.taskrows.clear();SetWindowTextW(p.subtitle,L"");SetWindowTextW(p.crumb,L"个人文件");SetWindowTextW(p.filter,L"");SetWindowTextW(p.note,L"");hide();}
void FilePanel::logout(){request_logout();if(!can_close())return;auto& p=*impl_;p.stop();
  for(auto& j:p.jobs){j->client.reset();j->context={};j->entries.clear();j->remote.clear();j->local.clear();j->name.clear();}}
bool FilePanel::can_close() const {return std::all_of(impl_->jobs.begin(),impl_->jobs.end(),[](const auto& j){return j->done.load();});}
void FilePanel::poll(){try{impl_->poll();}catch(...){SetWindowTextW(impl_->note,L"操作失败，请重试。");}}
} // namespace orangespace::files
