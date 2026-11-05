#pragma once
#ifndef UNICODE
#define UNICODE
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <algorithm>
#include <windows.h>
#include <string>
#include <vector>
#include <stdexcept>
namespace phase1 {
struct Failure {const char* stage;DWORD code;};
inline void need(bool b,const char* s){if(!b){const DWORD e=GetLastError();throw Failure{s,e?e:ERROR_INVALID_DATA};}}
struct Handle {
 HANDLE h=nullptr;
 Handle()=default;explicit Handle(HANDLE x):h(x){}
 Handle(const Handle&)=delete;Handle& operator=(const Handle&)=delete;
 Handle(Handle&& o) noexcept:h(o.h){o.h=nullptr;}
 Handle& operator=(Handle&& o) noexcept{if(this!=&o){reset();h=o.h;o.h=nullptr;}return *this;}
 ~Handle(){reset();}
 void reset(HANDLE v=nullptr){if(h&&h!=INVALID_HANDLE_VALUE)CloseHandle(h);h=v;}
};
// Only pass a process HANDLE returned by this fixture's own creation or a
// held image/creation-verified service/helper handle; never a guessed PID.
inline bool terminate_owned(HANDLE job,HANDLE process,DWORD timeout) noexcept {
 if(!process||process==INVALID_HANDLE_VALUE)return true;
 if(WaitForSingleObject(process,0)==WAIT_OBJECT_0)return true;
 if(job&&job!=INVALID_HANDLE_VALUE)TerminateJobObject(job,94);
 // Covers the CreateProcess-succeeded/AssignJob-failed suspended interval.
 if(WaitForSingleObject(process,0)!=WAIT_OBJECT_0)TerminateProcess(process,94);
 return WaitForSingleObject(process,timeout)==WAIT_OBJECT_0;
}
inline void read_exact(HANDLE h,void* destination,DWORD n,ULONGLONG deadline){
 auto*p=static_cast<unsigned char*>(destination);
 while(n){DWORD available=0;need(PeekNamedPipe(h,nullptr,0,nullptr,&available,nullptr),"pipe_peek");
  if(!available){if(GetTickCount64()>=deadline)throw Failure{"pipe_timeout",WAIT_TIMEOUT};Sleep(5);continue;}
  DWORD got=0;need(ReadFile(h,p,(std::min)(n,available),&got,nullptr)&&got>0,"pipe_read");p+=got;n-=got;
 }
}
inline std::string read_frame(HANDLE h,DWORD timeout){
 const auto deadline=GetTickCount64()+timeout;unsigned char header[4]{};read_exact(h,header,4,deadline);
 DWORD n=0;for(unsigned i=0;i<4;++i)n|=DWORD(header[i])<<(8*i);
 need(n>0&&n<=32768,"frame_size");std::string result(n,'\0');
 try{read_exact(h,result.data(),n,deadline);}catch(...){SecureZeroMemory(result.data(),result.size());throw;}return result;
}
inline void send_frame(HANDLE h,std::string_view s){
 need(!s.empty()&&s.size()<=32768,"frame_size");std::vector<unsigned char>b(4+s.size());
 DWORD n=DWORD(s.size());for(unsigned i=0;i<4;++i)b[i]=static_cast<unsigned char>(n>>(i*8));
 std::copy(s.begin(),s.end(),b.begin()+4);DWORD wrote=0;const BOOL ok=WriteFile(h,b.data(),DWORD(b.size()),&wrote,nullptr);
 SecureZeroMemory(b.data(),b.size());need(ok&&wrote==4+s.size(),"pipe_write");
}
}
