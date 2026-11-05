#pragma once
// Private production local I/O. Native regression includes this exact code.
#include "orangespace/file_transfer.hpp"
#include <windows.h>
#include <winternl.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <system_error>
namespace orangespace::files::local_io {
namespace nd=node_session::detail;
inline void check(BOOL b){if(!b){auto e=GetLastError();throw std::system_error(int(e?e:ERROR_GEN_FAILURE),std::system_category(),"local file operation failed");}}
struct CloseFile {void operator()(void* p)const noexcept{if(p&&p!=INVALID_HANDLE_VALUE)CloseHandle(p);}};
using File=std::unique_ptr<void,CloseFile>;
struct Native {
 using Create=NTSTATUS(NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,PLARGE_INTEGER,ULONG,ULONG,ULONG,ULONG,PVOID,ULONG);
 using Set=NTSTATUS(NTAPI*)(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,FILE_INFORMATION_CLASS);
 Create create{};Set set{};
 Native(){auto m=GetModuleHandleW(L"ntdll.dll");nd::require(m!=nullptr);
 // memcpy avoids incompatible-function-cast warnings; signatures are SDK ABI.
 auto c=GetProcAddress(m,"NtCreateFile"),s=GetProcAddress(m,"NtSetInformationFile");
 static_assert(sizeof(c)==sizeof(create)&&sizeof(s)==sizeof(set));std::memcpy(&create,&c,sizeof(c));std::memcpy(&set,&s,sizeof(s));nd::require(create&&set);}
 static const Native& api(){static const Native value;return value;}
 static void status(NTSTATUS s){if(s<0)throw std::runtime_error("native local file operation failed");}
};
inline void component(std::wstring_view s){nd::require(!s.empty()&&s!=L"."&&s!=L".."&&s.size()<=255&&s.find_first_of(L"\\/:")==s.npos&&nd::explicit_local_path(std::wstring(L"C:\\")+std::wstring(s)));}
inline void directory(HANDLE h){FILE_ATTRIBUTE_TAG_INFO a{};check(GetFileInformationByHandleEx(h,FileAttributeTagInfo,&a,sizeof(a)));nd::require((a.FileAttributes&FILE_ATTRIBUTE_DIRECTORY)&&!(a.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT));}
inline File relative(HANDLE parent,std::wstring_view leaf,ACCESS_MASK access,ULONG disposition,ULONG options,ULONG share){
 component(leaf);UNICODE_STRING name{};name.Buffer=const_cast<PWSTR>(leaf.data());name.Length=static_cast<USHORT>(leaf.size()*sizeof(wchar_t));name.MaximumLength=name.Length;
 OBJECT_ATTRIBUTES attributes{};attributes.Length=sizeof(attributes);attributes.RootDirectory=parent;attributes.ObjectName=&name;
 // Microsoft Windows-Driver-Frameworks public wudfwdm.h defines
 // OBJ_DONT_REPARSE as 0x00001000L; MinGW winternl omits it.
 constexpr ULONG dont_reparse=0x00001000UL;
 attributes.Attributes=OBJ_CASE_INSENSITIVE|dont_reparse;
 IO_STATUS_BLOCK io{};HANDLE result=nullptr;
 auto status=Native::api().create(&result,access|SYNCHRONIZE,&attributes,&io,nullptr,FILE_ATTRIBUTE_NORMAL,share,disposition,options|FILE_OPEN_REPARSE_POINT|FILE_SYNCHRONOUS_IO_NONALERT,nullptr,0);
 File owned(result);Native::status(status);return owned;
}
struct LocalPath {
 std::wstring path,leaf;std::vector<File> parents;
 explicit LocalPath(const std::filesystem::path& p):path(p.native()){
 nd::require(nd::explicit_local_path(path));auto root=path.substr(0,3);nd::require(GetDriveTypeW(root.c_str())==DRIVE_FIXED);
 File h(CreateFileW(root.c_str(),FILE_TRAVERSE|FILE_READ_ATTRIBUTES|SYNCHRONIZE,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS,nullptr));nd::require(h.get()!=INVALID_HANDLE_VALUE);directory(h.get());parents.push_back(std::move(h));
 std::size_t start=3;
 while(true){auto end=path.find(L'\\',start);if(end==path.npos){leaf=path.substr(start);component(leaf);break;}
 auto next=relative(parent(),std::wstring_view(path).substr(start,end-start),FILE_TRAVERSE|FILE_READ_ATTRIBUTES,FILE_OPEN,FILE_DIRECTORY_FILE,FILE_SHARE_READ|FILE_SHARE_WRITE);directory(next.get());parents.push_back(std::move(next));start=end+1;}
 }
 HANDLE parent()const noexcept{return parents.back().get();}
 File open_upload()const{auto h=relative(parent(),leaf,FILE_GENERIC_READ,FILE_OPEN,FILE_NON_DIRECTORY_FILE|FILE_SEQUENTIAL_ONLY,FILE_SHARE_READ);FILE_ATTRIBUTE_TAG_INFO a{};check(GetFileInformationByHandleEx(h.get(),FileAttributeTagInfo,&a,sizeof(a)));nd::require(!(a.FileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))&&GetFileType(h.get())==FILE_TYPE_DISK);return h;}
};
struct Part {
 LocalPath destination;std::wstring temporary;File file;detail::DownloadOwnership ownership;
 explicit Part(const std::filesystem::path& p):destination(p){
 std::array<unsigned char,16> random{};nd::require(BCryptGenRandom(nullptr,random.data(),random.size(),BCRYPT_USE_SYSTEM_PREFERRED_RNG)==0);constexpr wchar_t hex[]=L"0123456789abcdef";
 temporary=L".orangespace-part-";for(auto b:random){temporary+=hex[b>>4];temporary+=hex[b&15];}
 file=relative(destination.parent(),temporary,FILE_GENERIC_WRITE|DELETE,FILE_CREATE,FILE_NON_DIRECTORY_FILE,0);
 }
 ~Part(){if(ownership.owns_part()&&file){FILE_DISPOSITION_INFO d{TRUE};SetFileInformationByHandle(file.get(),FileDispositionInfo,&d,sizeof(d));}}
 void publish(std::atomic<bool>& c){check(FlushFileBuffers(file.get()));
 // Native FileRenameInformation is class 10, omitted from the public SDK enum.
 constexpr auto rename_class=static_cast<FILE_INFORMATION_CLASS>(10);
 const auto bytes=sizeof(FILE_RENAME_INFO)+destination.leaf.size()*sizeof(wchar_t);std::vector<unsigned char> storage(bytes);auto* rename=reinterpret_cast<FILE_RENAME_INFO*>(storage.data());
 rename->ReplaceIfExists=FALSE;rename->RootDirectory=destination.parent();rename->FileNameLength=static_cast<DWORD>(destination.leaf.size()*sizeof(wchar_t));std::copy(destination.leaf.begin(),destination.leaf.end(),rename->FileName);
 ownership.publish(c,[&]{IO_STATUS_BLOCK io{};Native::status(Native::api().set(file.get(),&io,rename,static_cast<ULONG>(bytes),rename_class));});
 }
};
}
