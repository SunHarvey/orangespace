// Parent-only native primitive test. No SCM, accounts, Tasks, or persistent writes.
#include "phase1_guardian_win.hpp"
#include <iostream>
using namespace phase1_guardian::win;
int wmain(){try{
 const char abc[]="abc";
 if(hex(sha256(abc,3))!="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")return 1;
 auto i=describe(GetCurrentProcess());
 if(i.pid!=GetCurrentProcessId()||!i.created)return 2;
 Handle h; if(!DuplicateHandle(GetCurrentProcess(),GetCurrentProcess(),GetCurrentProcess(),h.put(),PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,0))return 3;
 if(!same(i,describe(h.get()))||WaitForSingleObject(h.get(),0)!=WAIT_TIMEOUT)return 4;
 auto changed=i;changed.created++;if(same(i,changed))return 5;
 if(valid_nonce(L"abc")||!valid_nonce(L"0123456789abcdef0123456789abcdef"))return 6;
 std::cout<<"{\"native_primitives\":true,\"scm_tested\":false,\"full_acceptance\":false}\n";return 0;
}catch(...){std::cerr<<"{\"error\":\"G_NATIVE_PRIMITIVE_UNKNOWN\",\"full_acceptance\":false}\n";return 10;}}
