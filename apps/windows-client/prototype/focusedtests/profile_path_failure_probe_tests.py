from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[4]
s=(root/'apps/windows-client/prototype/bootstrap_prototype_win.cc').read_text()
assert 'void ProfilePathFailure(' in s,'missing bounded metadata failure probe'
a=s.index('void ProfilePathFailure(');b=s.index('\nLONG CALLBACK OfflineNativeFailure',a);fn=s[a:b]
assert 'ProfilePathFailure(path.c_str(),profile_depth,attributes==INVALID_FILE_ATTRIBUTES?GetLastError():0);return 244;' in s
code=r"""
#include <string>
#include <cstdio>
#include <cassert>
#include <vector>
using DWORD=unsigned;using HANDLE=long long;using LPCWSTR=const wchar_t*;
constexpr HANDLE INVALID_HANDLE_VALUE=-1;constexpr DWORD OPEN_EXISTING=3,FILE_FLAG_BACKUP_SEMANTICS=0x2000000,FILE_FLAG_OPEN_REPARSE_POINT=0x200000,FILE_SHARE_READ=1,FILE_SHARE_WRITE=2,FILE_SHARE_DELETE=4,INVALID_FILE_ATTRIBUTES=0xffffffff;
struct BY_HANDLE_FILE_INFORMATION{DWORD dwFileAttributes;};
DWORD err=0,mode=0;std::string log;int closed=0;
DWORD GetLastError(){return err;}void SetLastError(DWORD e){err=e;}
HANDLE CreateFileW(LPCWSTR,DWORD access,DWORD share,void*,DWORD creation,DWORD flags,void*){assert(access==0&&share==7&&creation==3&&flags==(FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT));if(mode==0){err=5;return -1;}return 9;}
bool GetFileInformationByHandle(HANDLE,BY_HANDLE_FILE_INFORMATION* i){if(mode==1){err=6;return false;}i->dwFileAttributes=mode==2?16:0x410;return true;}
bool CloseHandle(HANDLE h){assert(h==9);++closed;return true;}
bool OfflineEarlyLog(const char* text){log=text;return true;}
"""+fn+r"""
int main(){for(mode=0;mode<4;++mode){err=17;log.clear();closed=0;ProfilePathFailure(L"fixed-private-fixture",4,5);assert(err==17);assert(log.starts_with("profile-path depth=4 attributes-error=5 "));assert(closed==(mode!=0));assert(log.find("fixed-private-fixture")==std::string::npos);if(mode==0)assert(log.find("open-error=5")!=std::string::npos);if(mode==1)assert(log.find("info-error=6")!=std::string::npos);if(mode==2)assert(log.find("handle-attributes=16")!=std::string::npos);}}
"""
with tempfile.TemporaryDirectory(dir='/root/.hermes/cache/scratch') as d:
 p=Path(d);(p/'t.cpp').write_text(code);subprocess.run(['g++','-std=c++20',str(p/'t.cpp'),'-o',str(p/'t')],check=True);subprocess.run([str(p/'t')],check=True)
print('production failure probe: read-only zero-access, bounded fixed DWORDs, close and LastError preserved; no native claim')
