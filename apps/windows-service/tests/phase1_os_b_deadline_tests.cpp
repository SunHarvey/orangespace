// Injected clock/Win32 seams around freshly extracted production bodies.
// Portable policy evidence only: no native API execution or timing claim.
#include "phase1_os_b_policy.hpp"
#include <algorithm>
#include <iostream>
using namespace phase1_os_b;
using DWORD=std::uint32_t;using ULONGLONG=std::uint64_t;using HANDLE=int;using BOOL=int;
constexpr DWORD WAIT_OBJECT_0=0,WAIT_TIMEOUT=258,ERROR_IO_PENDING=997,ERROR_PIPE_CONNECTED=535;
constexpr BOOL FALSE=0;
struct Failure {const char* stage;DWORD code;};
void need(bool ok,const char* s){if(!ok)throw Failure{s,1};}
ULONGLONG clock_now=999;int tick_calls=0,expire_tick=0,submissions=0,result_calls=0;
ULONGLONG prep_time=0,submit_time=0,wait_time=0,result_time=0;char* read_buffer=nullptr;
bool pending_mode=false,connected_mode=false;
ULONGLONG GetTickCount64(){if(++tick_calls==expire_tick)clock_now=1000;return clock_now;}
DWORD GetLastError(){return connected_mode?ERROR_PIPE_CONNECTED:ERROR_IO_PENDING;}
DWORD WaitForSingleObject(HANDLE,DWORD){if(wait_time)clock_now=wait_time;return WAIT_OBJECT_0;}
struct NativeIo{struct H{HANDLE h=1;}pipe,event;int ov{};struct B{std::string value;}bytes;bool pending=false;};
struct IoLease{std::unique_ptr<NativeIo>op;IoLease(HANDLE,DWORD size):op(std::make_unique<NativeIo>()){op->bytes.value.resize(size);if(prep_time)clock_now=prep_time;}};
BOOL ReadFile(HANDLE,char* p,DWORD size,DWORD* n,int*){++submissions;read_buffer=p;if(submit_time)clock_now=submit_time;if(pending_mode)return FALSE;std::fill_n(p,size,'r');*n=size;return 1;}
BOOL WriteFile(HANDLE h,char* p,DWORD size,DWORD* n,int* ov){return ReadFile(h,p,size,n,ov);}
BOOL GetOverlappedResult(HANDLE,int*,DWORD* n,BOOL){++result_calls;if(result_time)clock_now=result_time;*n=1;if(read_buffer)*read_buffer='r';return 1;}
BOOL ConnectNamedPipe(HANDLE,int*){++submissions;if(submit_time)clock_now=submit_time;return !connected_mode&&!pending_mode;}
#ifndef OSB_EXTRACTED_BODY
#error Define OSB_EXTRACTED_BODY to a freshly generated body include
#endif
#include OSB_EXTRACTED_BODY
void check(bool ok,const char* s){if(!ok){std::cerr<<s<<'\n';std::exit(1);}}
int main(int argc,char** argv){
 check(argc==2,"case required");std::string c=argv[1];bool write=false,connect=false,expect_timeout=true;int expected_submit=1;
 if(c=="sync-read"||c=="sync-write"){write=c=="sync-write";submit_time=1000;}
 else if(c=="pending-event"||c=="pending-transfer-event"){pending_mode=true;wait_time=1000;}
 else if(c=="pending-result"||c=="pending-transfer-result"){pending_mode=true;result_time=1000;}
 else if(c=="prep-read"||c=="prep-write"){write=c=="prep-write";prep_time=1000;expected_submit=0;}
 else if(c=="connect-ok"||c=="connect-already"){connect=true;connected_mode=c=="connect-already";submit_time=1000;}
 else if(c=="connect-prep"){connect=true;prep_time=1000;expected_submit=0;}
 else if(c=="final-progress"||c=="final-write"){write=c=="final-write";expire_tick=4;}
 else if(c=="sync-after"){submit_time=1001;}
 else if(c=="initial-expired"){clock_now=1000;expected_submit=0;}
 else if(c=="connect-pending-late"){connect=true;pending_mode=true;wait_time=1000;}
 else if(c=="ontime-connect-pending"){connect=true;pending_mode=true;expect_timeout=false;}
 else if(c=="ontime-read"||c=="ontime-write"){write=c=="ontime-write";expect_timeout=false;}
 else if(c=="ontime-pending"){pending_mode=true;expect_timeout=false;}
 else if(c=="ontime-connect"||c=="ontime-connected"){connect=true;connected_mode=c=="ontime-connected";expect_timeout=false;}
 else check(false,"unknown case");
 char out='x';bool timed_out=false,accepted=false;
 try{if(c=="pending-event"||c=="pending-result"){NativeIo op;DWORD n=0;expected_submit=0;await_io(op,1000,n);}else if(connect)connect_owned_private(1,1);else transfer_until(1,&out,1,write,1000);accepted=true;}catch(Failure f){timed_out=std::string(f.stage)=="pipe_timeout"&&f.code==WAIT_TIMEOUT;}
 check(expect_timeout?(!accepted&&timed_out):accepted,"deadline acceptance mismatch");
 check(submissions==expected_submit,"expired preparation must not submit");
 if(expect_timeout&&!write&&!connect)check(out=='x',"late bytes copied to caller");
 if(!expect_timeout&&!write&&!connect)check(out=='r',"ontime read must copy");
 std::cout<<c<<" PASS submissions="<<submissions<<" result_calls="<<result_calls<<" now="<<clock_now<<" accepted="<<accepted<<" caller="<<out<<'\n';
}
