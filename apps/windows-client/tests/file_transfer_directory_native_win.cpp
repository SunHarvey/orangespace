#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#include <shlobj.h>
#include <sddl.h>
#include <winioctl.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <filesystem>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>
#include "../src/file_transfer_local_io_win.hpp"
using namespace orangespace::files;
using namespace orangespace::files::local_io;
namespace nd=orangespace::node_session::detail;
static const wchar_t leaf[]=L"OrangeSpace-native-file-relative-7b2e8c4819d0-r2";
void write_bytes(HANDLE h,const std::string& b){DWORD done=0;check(WriteFile(h,b.data(),static_cast<DWORD>(b.size()),&done,nullptr));nd::require(done==b.size());}
void fresh(const std::wstring& p,const std::string& b){File h(CreateFileW(p.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr));nd::require(h.get()!=INVALID_HANDLE_VALUE);write_bytes(h.get(),b);check(FlushFileBuffers(h.get()));}
std::string read_bytes(const std::wstring& p){File h(CreateFileW(p.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));nd::require(h.get()!=INVALID_HANDLE_VALUE);std::array<char,64>b{};DWORD done{};check(ReadFile(h.get(),b.data(),b.size(),&done,nullptr));return {b.data(),done};}
bool absent(const std::wstring& p){auto a=GetFileAttributesW(p.c_str());return a==INVALID_FILE_ATTRIBUTES&&GetLastError()==ERROR_FILE_NOT_FOUND;}

struct MountBuffer { DWORD tag; WORD length,reserved; WORD suboff,sublen,printoff,printlen; wchar_t paths[1024]; };
bool junction(HANDLE h,const std::wstring& target,DWORD& error){
 MountBuffer b{};b.tag=IO_REPARSE_TAG_MOUNT_POINT;std::wstring nt=L"\\??\\"+target;
 nd::require(nt.size()+target.size()+2<1024);b.sublen=WORD(nt.size()*2);b.printoff=WORD((nt.size()+1)*2);b.printlen=WORD(target.size()*2);
 std::copy(nt.begin(),nt.end(),b.paths);std::copy(target.begin(),target.end(),b.paths+nt.size()+1);
 b.length=WORD(8+(nt.size()+target.size()+2)*2);DWORD n=0;BOOL r=DeviceIoControl(h,FSCTL_SET_REPARSE_POINT,&b,DWORD(8+b.length),nullptr,0,&n,nullptr);error=r?0:GetLastError();return r;
}
bool unjunction(HANDLE h,DWORD& error){struct {DWORD tag;WORD length,reserved;} b{IO_REPARSE_TAG_MOUNT_POINT,0,0};DWORD n=0;BOOL r=DeviceIoControl(h,FSCTL_DELETE_REPARSE_POINT,&b,sizeof(b),nullptr,0,&n,nullptr);error=r?0:GetLastError();return r;}
File open_dir(const std::wstring& p,DWORD access,DWORD& error){HANDLE h=CreateFileW(p.c_str(),access,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS,nullptr);error=h==INVALID_HANDLE_VALUE?GetLastError():0;return File(h);}
int wmain(){int rc=90;bool owned_root=false;std::wstring base;std::string receipt="native-file-relative-v1\n";bool unsafe=false,failed=false;const char* stage="setup";
 auto record=[&](const char* k,DWORD v){receipt+=k;receipt+='=';receipt+=std::to_string(v);receipt+='\n';};
 auto run=[&](const char* name,auto fn){stage=name;try{fn();receipt+=name;receipt+="=pass\n";}catch(...){failed=true;receipt+=name;receipt+="=fail\n";}};
 try{
 PWSTR local=nullptr;nd::require(SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData,0,nullptr,&local)));base=local;CoTaskMemFree(local);base+=L"\\";base+=leaf;
 HANDLE token=nullptr;check(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token));File th(token);DWORD size=0;GetTokenInformation(token,TokenUser,nullptr,0,&size);std::vector<unsigned char> tb(size);check(GetTokenInformation(token,TokenUser,tb.data(),size,&size));LPWSTR sid=nullptr;check(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(tb.data())->User.Sid,&sid));std::wstring sddl=L"D:P(A;;FA;;;SY)(A;;FA;;;";sddl+=sid;LocalFree(sid);sddl+=L")";PSECURITY_DESCRIPTOR sd=nullptr;check(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&sd,nullptr));SECURITY_ATTRIBUTES sa{sizeof(sa),sd,FALSE};BOOL made=CreateDirectoryW(base.c_str(),&sa);LocalFree(sd);if(!made)return 91; // preserve any preexisting path; never inspect or clean it

 owned_root=true;
 // Every case directory has an explicit protected current-user + SYSTEM DACL.
 HANDLE tok=nullptr;check(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&tok));File token2(tok);DWORD sz=0;GetTokenInformation(tok,TokenUser,nullptr,0,&sz);std::vector<unsigned char> t(sz);check(GetTokenInformation(tok,TokenUser,t.data(),sz,&sz));LPWSTR sid2=nullptr;check(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(t.data())->User.Sid,&sid2));std::wstring acl=L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;";acl+=sid2;LocalFree(sid2);acl+=L")";
 auto mkdir=[&](const std::wstring& p){PSECURITY_DESCRIPTOR d=nullptr;check(ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(),SDDL_REVISION_1,&d,nullptr));SECURITY_ATTRIBUTES a{sizeof(a),d,FALSE};BOOL r=CreateDirectoryW(p.c_str(),&a);DWORD e=r?0:GetLastError();LocalFree(d);SetLastError(e);check(r);};
 std::wstring ancestor=base+L"\\empty-ancestor",dest=base+L"\\junction-target";mkdir(ancestor);mkdir(dest);
 // A real positive control is mandatory, not a skipped attack.
 bool clean=true;
 run("junction-positive-control",[&]{DWORD e=0;auto h=open_dir(ancestor,FILE_WRITE_ATTRIBUTES,e);nd::require(h.get()!=INVALID_HANDLE_VALUE);nd::require(junction(h.get(),dest,e));clean=false;nd::require(unjunction(h.get(),e));clean=true;});
 run("preexisting-reparse-rejected",[&]{DWORD e=0;auto h=open_dir(ancestor,FILE_WRITE_ATTRIBUTES,e);nd::require(h.get()!=INVALID_HANDLE_VALUE);nd::require(junction(h.get(),dest,e));bool rejected=false;try{LocalPath p(ancestor+L"\\never.bin");}catch(...){rejected=true;}nd::require(unjunction(h.get(),e));nd::require(rejected);});
 run("mutation-before-upload-open",[&]{
 // Keep the real ancestor empty: a missing original source must never be
 // satisfied by the outside junction target's same-named file.
 fresh(dest+L"\\source.bin","outside");
 LocalPath pin(ancestor+L"\\source.bin");DWORD e=0;auto h=open_dir(ancestor,FILE_WRITE_ATTRIBUTES,e);nd::require(h.get()!=INVALID_HANDLE_VALUE);
 bool changed=junction(h.get(),dest,e);record("uploadJunctionError",e);nd::require(changed);clean=false;
 bool rejected=false;try{auto f=pin.open_upload();unsafe=true;}catch(...){rejected=true;}
 nd::require(unjunction(h.get(),e));clean=true;nd::require(rejected);
 });
 run("mutation-before-part-create",[&]{
 // Holding the parent then mutating it tests the same production relative
 // creation primitive used by Part, without an alternate pathname reopen.
 LocalPath pin(ancestor+L"\\created.bin");DWORD e=0;auto h=open_dir(ancestor,FILE_WRITE_ATTRIBUTES,e);nd::require(h.get()!=INVALID_HANDLE_VALUE);bool changed=junction(h.get(),dest,e);record("createJunctionError",e);nd::require(changed);clean=false;
 bool created=false;try{auto f=relative(pin.parent(),L"created.bin",FILE_GENERIC_WRITE|DELETE,FILE_CREATE,FILE_NON_DIRECTORY_FILE,0);write_bytes(f.get(),"inside");created=true;}catch(...){}
 nd::require(unjunction(h.get(),e));clean=true;
 if(!absent(dest+L"\\created.bin"))unsafe=true;
 nd::require(absent(dest+L"\\created.bin"));if(created)nd::require(read_bytes(ancestor+L"\\created.bin")=="inside");
 });
 run("mutation-between-create-publish",[&]{
 std::atomic<bool> c{false};
 auto parent=base+L"\\late-ancestor";mkdir(parent);auto child=parent+L"\\child";mkdir(child);auto outside=dest+L"\\child";mkdir(outside);fresh(outside+L"\\sentinel.bin","outside-original");
 std::wstring temp;bool published=false;auto renamed=base+L"\\late-renamed";
 {Part p(child+L"\\target.bin");temp=child+L"\\"+p.temporary;write_bytes(p.file.get(),"inside");DWORD e=0;auto h=open_dir(parent,FILE_WRITE_ATTRIBUTES,e);nd::require(h.get()!=INVALID_HANDLE_VALUE);
 bool changed=junction(h.get(),dest,e);record("lateJunctionChanged",changed);record("lateJunctionError",e);
 // NTFS may refuse a mount-point on this nonempty ancestor. That is a
 // blocked mutation, not a successful attack; empty-ancestor cases above
 // must still actually mutate. Require the specific native refusal.
 if(!changed)nd::require(e==ERROR_DIR_NOT_EMPTY);
 bool moved=MoveFileExW(parent.c_str(),renamed.c_str(),0)!=FALSE;DWORD move_error=moved?0:GetLastError();record("lateRenameError",move_error);
 if(moved){unsafe=true;nd::require(MoveFileExW(renamed.c_str(),parent.c_str(),0));}else nd::require(move_error==ERROR_SHARING_VIOLATION);
 try{p.publish(c);published=true;}catch(...){}
 if(changed)nd::require(unjunction(h.get(),e));
 if(!absent(outside+L"\\target.bin"))unsafe=true;
 nd::require(absent(outside+L"\\target.bin")&&read_bytes(outside+L"\\sentinel.bin")=="outside-original");if(published)nd::require(!p.ownership.owns_part());}
 nd::require(absent(temp));if(published)nd::require(read_bytes(child+L"\\target.bin")=="inside");else nd::require(absent(child+L"\\target.bin"));
 // Positive rename control after all production handles are released.
 nd::require(MoveFileExW(parent.c_str(),renamed.c_str(),0));nd::require(MoveFileExW(renamed.c_str(),parent.c_str(),0));
 });
 nd::require(clean);
 std::wstring dir=base+L"\\part-case",target=dir+L"\\target.bin",ok=dir+L"\\published.bin",cancel=dir+L"\\cancel.bin";mkdir(dir);fresh(target,"original");std::atomic<bool> c{false};std::wstring temp;
 run("no-clobber",[&]{ {Part p(target);temp=dir+L"\\"+p.temporary;write_bytes(p.file.get(),"replacement");bool rejected=false;try{p.publish(c);}catch(...){rejected=true;}nd::require(rejected&&p.ownership.owns_part());nd::require(read_bytes(target)=="original");}
 nd::require(absent(temp)&&read_bytes(target)=="original");
});
 run("publication",[&]{ {Part p(ok);temp=dir+L"\\"+p.temporary;write_bytes(p.file.get(),"published-bytes");p.publish(c);nd::require(!p.ownership.owns_part());}
 nd::require(absent(temp)&&read_bytes(ok)=="published-bytes");
});
 run("failure-cleanup",[&]{ {Part p(cancel);temp=dir+L"\\"+p.temporary;write_bytes(p.file.get(),"discard");c=true;bool rejected=false;try{p.publish(c);}catch(...){rejected=true;}nd::require(rejected&&p.ownership.owns_part());}
 nd::require(absent(temp)&&absent(cancel)&&read_bytes(target)=="original");
});
 run("destructor-cleanup",[&]{ {Part p(target);temp=dir+L"\\"+p.temporary;write_bytes(p.file.get(),"discard");}
 nd::require(absent(temp)&&read_bytes(target)=="original");
});
 // Retain all owned case leaves and receipts for parent review; no recursive cleanup.
 rc=unsafe?93:(failed?90:0);stage=unsafe?"unsafe-under-pin-mutation":(failed?"diagnostic-incomplete":"diagnostic-complete-not-gate-pass");
 }catch(...){failed=true;rc=90;}
 if(owned_root)try{receipt+="stage=";receipt+=stage;receipt+='\n';record("unsafe",unsafe);record("incomplete",failed);record("exitcode",rc);fresh(base+L"\\receipt.txt",receipt);fresh(base+L"\\exitcode.txt",std::to_string(rc)+"\n");}catch(...){return 92;}
 return rc;
}
int WINAPI wWinMain(HINSTANCE,HINSTANCE,PWSTR,int){return wmain();}
