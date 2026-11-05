"""Injected portable WinAPI policy seam, NOT native Windows AccessCheck/API evidence."""
from pathlib import Path
import subprocess, tempfile, sys
source = Path(sys.argv[1]) if len(sys.argv)>1 else Path(__file__).resolve().parents[1]/'service_win.cpp'
s = source.read_text(); owner=s[s.index('struct TokenObservation {'):s.index('\nbool io(',s.index('struct TokenObservation {'))]
shim=r'''
#include <vector>
#include <array>
#include <cstring>
#include <cassert>
#include <cstdint>
#include <string>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <new>
bool deny_heap=false;
void* operator new(std::size_t n){if(deny_heap)throw std::bad_alloc();if(void*p=std::malloc(n))return p;throw std::bad_alloc();}
void operator delete(void*p) noexcept {std::free(p);}
void operator delete(void*p,std::size_t) noexcept {std::free(p);}
using BYTE=unsigned char;using DWORD=uint32_t;using WORD=uint16_t;using BOOL=int;using HANDLE=void*;using PSID=void*;using LPWSTR=wchar_t*;using SECURITY_INFORMATION=DWORD;using SECURITY_DESCRIPTOR_CONTROL=WORD;
constexpr DWORD TOKEN_QUERY=8,READ_CONTROL=0x20000,WRITE_DAC=0x40000,SE_KERNEL_OBJECT=6,DACL_SECURITY_INFORMATION=4,OWNER_SECURITY_INFORMATION=1,GROUP_SECURITY_INFORMATION=2,MAXDWORD=0xffffffff,ERROR_SUCCESS=0,ERROR_INVALID_DATA=13,ERROR_INSUFFICIENT_BUFFER=122,SECURITY_DESCRIPTOR_REVISION=1,SECURITY_MAX_SID_SIZE=68;
constexpr WORD SE_DACL_PROTECTED=0x1000,SE_DACL_AUTO_INHERITED=0x400,SE_DACL_AUTO_INHERIT_REQ=0x100;
constexpr BYTE ACCESS_ALLOWED_ACE_TYPE=0,ACCESS_DENIED_ACE_TYPE=1;
constexpr BOOL TRUE=1;
struct ACE_HEADER{BYTE AceType,AceFlags;WORD AceSize;};struct ACCESS_ALLOWED_ACE{ACE_HEADER Header;DWORD Mask;DWORD SidStart;};
struct ACL{BYTE AclRevision=2,Sbz1=0;WORD AclSize=0,AceCount=0,Sbz2=0;};using PACL=ACL*;
struct SECURITY_DESCRIPTOR_RELATIVE{BYTE Revision,Sbz1;WORD Control;DWORD Owner,Group,Sacl,Dacl;};
struct SECURITY_DESCRIPTOR{WORD control{};BOOL present=1,def=0;PSID owner{},group{};PACL acl{};};using PSECURITY_DESCRIPTOR=void*;
struct ACL_SIZE_INFORMATION{DWORD AceCount,AclBytesInUse,AclBytesFree;};constexpr int AclSizeInformation=2;
struct Failure{DWORD code;};const char* stage;void report_fixed(const char*,DWORD){};DWORD GetLastError(){return ERROR_INSUFFICIENT_BUFFER;}void need(bool x){if(!x)throw Failure{13};}
struct Handle{HANDLE h{};Handle()=default;Handle(HANDLE x):h(x){};HANDLE get(){return h;}};struct Session{std::wstring sid=L"user";};
DWORD sy=1,user=2,pkg=3,other=4;std::array<BYTE,2048> current{},external{};SECURITY_DESCRIPTOR state{SE_DACL_PROTECTED,1,0,&sy,&sy,(PACL)current.data()};int writes=0,reads=0,drift_at=0,fail_read=0;bool fail_write=false;int logs=0;
bool IsValidSid(PSID p){return p!=nullptr;}DWORD GetLengthSid(PSID){return 4;}BOOL EqualSid(PSID a,PSID b){return a&&b&&*(DWORD*)a==*(DWORD*)b;}BOOL ConvertStringSidToSidW(const wchar_t*,PSID* p){*p=&user;return 1;}void LocalFree(void*){}
HANDLE GetCurrentProcess(){return (void*)1;}BOOL OpenProcessToken(HANDLE,DWORD,HANDLE*p){*p=(void*)2;return 1;}
DWORD used(PACL a){DWORD n=sizeof(ACL);auto*b=(BYTE*)a;for(int i=0;i<a->AceCount;i++)n+=((ACE_HEADER*)(b+n))->AceSize;return n;}
BOOL IsValidAcl(PACL a){return a&&a->AclSize>=sizeof(ACL);}BOOL GetAce(PACL a,DWORD i,void**p){if(i>=a->AceCount)return 0;auto*b=(BYTE*)a+sizeof(ACL);while(i--)b+=((ACE_HEADER*)b)->AceSize;*p=b;return 1;}
BOOL GetAclInformation(PACL a,void*p,DWORD,int){*(ACL_SIZE_INFORMATION*)p={a->AceCount,used(a),DWORD(a->AclSize-used(a))};return 1;}
BOOL InitializeAcl(PACL a,DWORD n,DWORD rev){*a={BYTE(rev),0,WORD(n),0,0};return 1;}
BOOL AddAce(PACL a,DWORD,DWORD,void*p,DWORD n){auto z=used(a);if(z+n>a->AclSize)return 0;memcpy((BYTE*)a+z,p,n);a->AceCount++;return 1;}
BOOL AddAccessAllowedAceEx(PACL a,DWORD r,DWORD flags,DWORD mask,PSID sid){ACCESS_ALLOWED_ACE e{{0,BYTE(flags),sizeof(ACCESS_ALLOWED_ACE)},mask,*(DWORD*)sid};return AddAce(a,r,MAXDWORD,&e,sizeof(e));}
PACL getacl(SECURITY_DESCRIPTOR*s){return uintptr_t(s->acl)<65536?(PACL)((BYTE*)s+uintptr_t(s->acl)):s->acl;}
BOOL GetSecurityDescriptorDacl(void*p,BOOL*present,PACL*a,BOOL*d){auto*s=(SECURITY_DESCRIPTOR*)p;*present=s->present;*a=getacl(s);*d=s->def;return 1;}
BOOL GetSecurityDescriptorControl(void*p,WORD*c,DWORD*r){*c=((SECURITY_DESCRIPTOR*)p)->control;*r=1;return 1;}
BOOL GetSecurityDescriptorOwner(void*p,PSID*s,BOOL*d){*s=((SECURITY_DESCRIPTOR*)p)->owner;*d=0;return 1;}BOOL GetSecurityDescriptorGroup(void*p,PSID*s,BOOL*d){*s=((SECURITY_DESCRIPTOR*)p)->group;*d=0;return 1;}
BOOL IsValidSecurityDescriptor(void*p){return p!=nullptr;}DWORD GetSecurityDescriptorLength(void*p){return sizeof(SECURITY_DESCRIPTOR)+used(getacl((SECURITY_DESCRIPTOR*)p));}
BOOL InitializeSecurityDescriptor(SECURITY_DESCRIPTOR*s,DWORD){*s={};return 1;}BOOL SetSecurityDescriptorDacl(SECURITY_DESCRIPTOR*s,BOOL p,PACL a,BOOL d){s->present=p;s->acl=a;s->def=d;return 1;}BOOL SetSecurityDescriptorControl(SECURITY_DESCRIPTOR*s,WORD m,WORD b){s->control=(s->control&~m)|b;return 1;}
void drift(){state.owner=&other;}
BOOL GetKernelObjectSecurity(HANDLE,DWORD,void*p,DWORD n,DWORD*sz){++reads;if(reads==drift_at)drift();if(reads==fail_read)return 0;*sz=sizeof(SECURITY_DESCRIPTOR)+used(state.acl);if(!p||n<*sz)return 0;auto*s=(SECURITY_DESCRIPTOR*)p;*s=state;s->acl=(PACL)sizeof(*s);memcpy((BYTE*)p+sizeof(*s),state.acl,used(state.acl));return 1;}
BOOL SetKernelObjectSecurity(HANDLE,DWORD info,void*p){assert(info==DACL_SECURITY_INFORMATION);++writes;deny_heap=true;if(fail_write)return 0;auto*s=(SECURITY_DESCRIPTOR*)p;memcpy(current.data(),s->acl,used(s->acl));state.acl=(PACL)current.data();state.def=s->def;state.control=s->control;return 1;}
DWORD GetSecurityInfo(HANDLE,int,DWORD,PSID*,PSID*,PACL*a,void*,void**p){static SECURITY_DESCRIPTOR sd;sd=state;*a=state.acl;*p=&sd;return 0;}
DWORD SetSecurityInfo(HANDLE,int,DWORD,PSID,PSID,PACL a,void*){SECURITY_DESCRIPTOR sd=state;sd.acl=a;return SetKernelObjectSecurity(nullptr,4,&sd)?0:13;}
constexpr int GRANT_ACCESS=1,NO_INHERITANCE=0,TRUSTEE_IS_SID=0,TRUSTEE_IS_UNKNOWN=0;struct EXPLICIT_ACCESSW{DWORD grfAccessPermissions;int grfAccessMode,grfInheritance;struct{int TrusteeForm,TrusteeType;LPWSTR ptstrName;}Trustee;};
// Symbolic model of the known ordering counterexample, not WinAPI emulation proof.
DWORD SetEntriesInAclW(DWORD count,EXPLICIT_ACCESSW*e,PACL old,PACL*out){static std::array<BYTE,2048>b;auto*a=(PACL)b.data();InitializeAcl(a,b.size(),2);for(DWORD i=0;i<count;i++)AddAccessAllowedAceEx(a,2,0,e[i].grfAccessPermissions,e[i].Trustee.ptstrName);for(DWORD i=0;i<old->AceCount;i++){void*p;GetAce(old,i,&p);AddAce(a,2,MAXDWORD,p,((ACE_HEADER*)p)->AceSize);}*out=a;return 0;}
template<class T> void twice(T&o){if constexpr(requires {o.restore();}){o.restore();assert(writes==2);o.restore();assert(writes==2);}}
void reset(bool deny=true){deny_heap=false;writes=reads=drift_at=fail_read=0;fail_write=false;state={SE_DACL_PROTECTED,1,0,&sy,&sy,(PACL)current.data()};InitializeAcl(state.acl,current.size(),2);AddAccessAllowedAceEx(state.acl,2,0,0xffff,&sy);ACCESS_ALLOWED_ACE a{{BYTE(deny?1:0),BYTE(deny?16:0),12},deny?TOKEN_QUERY:DWORD(0x20),user};AddAce(state.acl,2,MAXDWORD,&a,sizeof(a));}
bool query(){DWORD remaining=TOKEN_QUERY;for(DWORD i=0;i<state.acl->AceCount;i++){void*p;GetAce(state.acl,i,&p);auto*a=(ACCESS_ALLOWED_ACE*)p;if(a->SidStart!=user)continue;if(a->Header.AceType==1&&(a->Mask&remaining))return false;if(a->Header.AceType==0)remaining&=~a->Mask;if(!remaining)return true;}return false;}
'''
main=r'''
int main(){Session s;deny_heap=true;try{std::vector<BYTE> positive(10);assert(false);}catch(const std::bad_alloc&){}deny_heap=false;
 reset();{TokenObservation o(s,&pkg);assert(!query() && "baseline inherited deny weakened");assert(writes==1);auto*a=state.acl;assert(a->AceCount==4);void*p;GetAce(a,1,&p);assert(((ACE_HEADER*)p)->AceType==1);GetAce(a,2,&p);assert(((ACCESS_ALLOWED_ACE*)p)->Mask==TOKEN_QUERY);assert(state.owner==&sy&&state.group==&sy&&state.control==SE_DACL_PROTECTED);}assert(writes==2&&state.acl->AceCount==2);
 reset(false);{TokenObservation o(s,&pkg);}void*p;GetAce(state.acl,1,&p);assert(((ACCESS_ALLOWED_ACE*)p)->Mask==0x20);
 reset();{TokenObservation o(s,&user);assert(state.acl->AceCount==3);}assert(writes==2);
 reset();{TokenObservation o(s,&pkg);drift();}assert(writes==1&&state.owner==&other);
 reset();drift_at=3;try{TokenObservation o(s,&pkg);assert(false);}catch(...){}assert(writes==0&&state.owner==&other);
 reset();fail_read=4;try{TokenObservation o(s,&pkg);assert(false);}catch(...){}assert(writes==1); // post-write unknown: retain, do not blindly restore
 reset();drift_at=4;try{TokenObservation o(s,&pkg);assert(false);}catch(...){}assert(writes==1&&state.owner==&other);
 reset();drift_at=6;{TokenObservation o(s,&pkg);}assert(writes==1&&state.owner==&other);
 reset();{TokenObservation o(s,&pkg);state.group=&other;}assert(writes==1&&state.group==&other);
 reset();{TokenObservation o(s,&pkg);state.control=0;}assert(writes==1&&state.control==0);
 reset();{TokenObservation o(s,&pkg);void*p;GetAce(state.acl,1,&p);((ACCESS_ALLOWED_ACE*)p)->Mask=0x80;}assert(writes==1);GetAce(state.acl,1,&p);assert(((ACCESS_ALLOWED_ACE*)p)->Mask==0x80);
 reset();fail_read=5;{TokenObservation o(s,&pkg);}assert(writes==1);
 reset();{TokenObservation o(s,&pkg);twice(o);}assert(writes==2);
 reset();state.def=1;state.control|=SE_DACL_AUTO_INHERITED|SE_DACL_AUTO_INHERIT_REQ;{TokenObservation o(s,&pkg);assert(state.def==1);assert(state.control==(SE_DACL_PROTECTED|SE_DACL_AUTO_INHERITED|SE_DACL_AUTO_INHERIT_REQ));}assert(state.def==1);
 reset();fail_write=true;try{TokenObservation o(s,&pkg);assert(false);}catch(...){}assert(writes==1&&state.acl->AceCount==2);
 reset();{std::array<BYTE,2048> baseline;auto n=used(state.acl);memcpy(baseline.data(),state.acl,n);TokenObservation o(s,&pkg);assert(memcmp(baseline.data()+sizeof(ACL),(BYTE*)state.acl+sizeof(ACL),n-sizeof(ACL))==0);}
 reset();AddAccessAllowedAceEx(state.acl,2,0,TOKEN_QUERY,&user);AddAccessAllowedAceEx(state.acl,2,0,TOKEN_QUERY,&pkg);{TokenObservation o(s,&pkg);assert(writes==0);}assert(writes==0);
 reset();((ACE_HEADER*)(current.data()+sizeof(ACL)))->AceType=9;try{TokenObservation o(s,&pkg);assert(false);}catch(...){}assert(writes==0);
 reset();state.acl=nullptr;try{TokenObservation o(s,&pkg);assert(false);}catch(...){}assert(writes==0);
 puts("injected production TokenObservation: deny/order/query-only/dedup/baseline/identity/control/drift/readback ownership/unsupported/null pass; native pending");
}
'''
# null snapshot is rejected in the shim rather than dereferenced.
shim=shim.replace('*sz=sizeof(SECURITY_DESCRIPTOR)+used(state.acl);','if(!state.acl)return 0;*sz=sizeof(SECURITY_DESCRIPTOR)+used(state.acl);')
with tempfile.TemporaryDirectory(dir='/var/tmp/hermes-runtime/tmp') as d:
 p=Path(d);(p/'test.cpp').write_text(shim+owner+main)
 subprocess.run(['g++','-std=c++20','-Wall','-Wextra',str(p/'test.cpp'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
