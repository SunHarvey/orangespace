#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <sddl.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <stdexcept>
#include "phase1_osb_system_policy.hpp"
namespace osbs {
struct Handle {
 HANDLE h=nullptr;
 Handle()=default; explicit Handle(HANDLE v):h(v){}
 Handle(const Handle&)=delete; Handle& operator=(const Handle&)=delete;
 Handle(Handle&& o) noexcept:h(o.h){o.h=nullptr;}
 ~Handle(){reset();}
 void reset(HANDLE v=nullptr){if(h&&h!=INVALID_HANDLE_VALUE)CloseHandle(h);h=v;}
 explicit operator bool()const{return h&&h!=INVALID_HANDLE_VALUE;}
};
inline void require(bool b){if(!b){throw DWORD(ERROR_INVALID_DATA);}}
inline void win(bool b){if(!b){DWORD e=GetLastError();throw e?e:DWORD(ERROR_GEN_FAILURE);}}
inline std::wstring wide(const std::string& a){return std::wstring(a.begin(),a.end());}
inline std::string narrow(const std::wstring& a){return std::string(a.begin(),a.end());}
inline std::vector<BYTE> info(HANDLE t,TOKEN_INFORMATION_CLASS c){
 DWORD n=0; GetTokenInformation(t,c,nullptr,0,&n); require(n>0&&n<65536);
 std::vector<BYTE>b(n);win(GetTokenInformation(t,c,b.data(),n,&n)!=0);return b;
}
inline std::string sid_text(PSID s){LPWSTR p=nullptr;win(ConvertSidToStringSidW(s,&p)!=0);std::string r=narrow(p);LocalFree(p);return r;}
struct Identity {std::string sid;DWORD session;bool limited; LUID logon;};
inline Identity identity(HANDLE t){
 auto u=info(t,TokenUser),s=info(t,TokenSessionId),e=info(t,TokenElevationType),st=info(t,TokenStatistics),ty=info(t,TokenType);
 require(*reinterpret_cast<TOKEN_TYPE*>(ty.data())==TokenPrimary);
 return {sid_text(reinterpret_cast<TOKEN_USER*>(u.data())->User.Sid),*reinterpret_cast<DWORD*>(s.data()),*reinterpret_cast<TOKEN_ELEVATION_TYPE*>(e.data())==TokenElevationTypeLimited,reinterpret_cast<TOKEN_STATISTICS*>(st.data())->AuthenticationId};
}
inline bool privilege(HANDLE t,const wchar_t* name,bool enabled){
 LUID id{};win(LookupPrivilegeValueW(nullptr,name,&id)!=0);auto b=info(t,TokenPrivileges);auto p=reinterpret_cast<TOKEN_PRIVILEGES*>(b.data());
 for(DWORD i=0;i<p->PrivilegeCount;++i)if(p->Privileges[i].Luid.LowPart==id.LowPart&&p->Privileges[i].Luid.HighPart==id.HighPart)return !enabled||(p->Privileges[i].Attributes&SE_PRIVILEGE_ENABLED);
 return false;
}
inline std::string bytes(HANDLE h){
 LARGE_INTEGER n{},z{};win(GetFileSizeEx(h,&n)!=0);require(n.QuadPart>=0&&n.QuadPart<=1024*1024*16);win(SetFilePointerEx(h,z,nullptr,FILE_BEGIN)!=0);
 std::string b(static_cast<size_t>(n.QuadPart),'\0');DWORD got=0;win(ReadFile(h,b.data(),static_cast<DWORD>(b.size()),&got,nullptr)!=0);require(got==b.size());return b;
}
inline std::string sha256(const std::string& b){
 BCRYPT_ALG_HANDLE alg=nullptr; BCRYPT_HASH_HANDLE hash=nullptr;BYTE out[32]{};
 require(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0)==0);
 NTSTATUS r=BCryptCreateHash(alg,&hash,nullptr,0,nullptr,0,0);
 if(r==0)r=BCryptHashData(hash,reinterpret_cast<PUCHAR>(const_cast<char*>(b.data())),static_cast<ULONG>(b.size()),0);
 if(r==0)r=BCryptFinishHash(hash,out,32,0);
 if(hash){BCryptDestroyHash(hash);}
 BCryptCloseAlgorithmProvider(alg,0);require(r==0);
 std::string s;for(BYTE x:out){s.push_back("0123456789abcdef"[x>>4]);s.push_back("0123456789abcdef"[x&15]);}return s;
}
}
