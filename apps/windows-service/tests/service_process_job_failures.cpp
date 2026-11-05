// Standalone Windows negative-path test. Fault injection is limited to this
// process's newly-created Job, never system/SCM/other users' process objects.
#include <windows.h>
#include <cstdio>
#include <stdexcept>
#include <initializer_list>
namespace {
int fault=0,closed=0,created=0,sets=0,assigns=0;
DWORD injected_error=ERROR_ACCESS_DENIED;
HANDLE fixture_job{};
void check(bool ok,const char* text){if(!ok)throw std::runtime_error(text);}
HANDLE create_job(LPSECURITY_ATTRIBUTES attributes,LPCWSTR name) {
    check(attributes==nullptr&&name==nullptr,"unnamed/noninherit creation arguments");
    ++created;
    if(fault==1){SetLastError(injected_error);return nullptr;}
    fixture_job=::CreateJobObjectW(attributes,name);return fixture_job;
}
BOOL set_job(HANDLE job,JOBOBJECTINFOCLASS info,LPVOID data,DWORD size) {
    check(job==fixture_job,"fault confined to held fixture Job");++sets;
    check(info==JobObjectExtendedLimitInformation&&size==sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION),"limit structure");
    const auto& limits=*static_cast<JOBOBJECT_EXTENDED_LIMIT_INFORMATION*>(data);
    check(limits.BasicLimitInformation.LimitFlags==JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE&&
        limits.BasicLimitInformation.ActiveProcessLimit==0,"only kill-on-close flags");
    if(fault==2){SetLastError(injected_error);return FALSE;}
    return ::SetInformationJobObject(job,info,data,size);
}
BOOL assign_job(HANDLE job,HANDLE process) {
    check(job==fixture_job&&process==GetCurrentProcess(),"assign actual current process only");++assigns;
    if(fault==3){SetLastError(injected_error);return FALSE;}
    return ::AssignProcessToJobObject(job,process);
}
BOOL close_job(HANDLE job) {
    check(job==fixture_job,"close only fixture-owned Job");++closed;
    const auto result=::CloseHandle(job);
    SetLastError(ERROR_SUCCESS); // Cleanup must not erase the saved failure.
    return result;
}
}
#define CreateJobObjectW create_job
#define SetInformationJobObject set_job
#define AssignProcessToJobObject assign_job
#define CloseHandle close_job
#include "orangespace/service_process_job.hpp"
#undef CreateJobObjectW
#undef SetInformationJobObject
#undef AssignProcessToJobObject
#undef CloseHandle
int main() {
    try {
        using namespace orangespace::service::win;
        for(int stage=1;stage<=3;++stage)for(DWORD error:{DWORD(ERROR_ACCESS_DENIED),DWORD(ERROR_SUCCESS)}) {
            fault=stage;injected_error=error;closed=created=sets=assigns=0;
            DWORD before{},after{};check(GetProcessHandleCount(GetCurrentProcess(),&before)!=FALSE,"before count");
            const auto result=install_service_process_job();
            check(result==(error?error:DWORD(ERROR_GEN_FAILURE)),"failure must remain nonzero even with zero last-error");
            check(detail::service_process_job_handle==nullptr,"failure cannot publish installed flag");
            check(closed==(stage==1?0:1),"preassignment failure closes only unassigned Job");
            check(created==1&&sets==(stage>=2?1:0)&&assigns==(stage>=3?1:0),"failure short circuits later operations");
            check(GetProcessHandleCount(GetCurrentProcess(),&after)&&after==before,"failure does not leak native handles");
            std::printf("PASS injected_stage=%d error=%lu nonzero_result=%lu native_handle_delta=0\n",stage,error,result);
        }
        fault=0;closed=created=sets=assigns=0;
        check(install_service_process_job()==ERROR_SUCCESS,"retry after failures succeeds");
        const auto installed=detail::service_process_job_handle;
        for(int i=0;i<16;++i)check(install_service_process_job()==ERROR_SUCCESS,"repeat success");
        check(installed!=nullptr&&installed==detail::service_process_job_handle&&created==1&&sets==1&&assigns==1&&closed==0,
            "successful handle retained until OS teardown, install once");
        std::puts("PASS native retry_success retained_raw_job no_explicit_close repeated_install_once");
        return 0;
    } catch(const std::exception& e){std::fprintf(stderr,"FAIL %s\n",e.what());return 1;}
}
