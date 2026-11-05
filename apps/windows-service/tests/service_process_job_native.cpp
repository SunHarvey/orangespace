// Standalone Windows kernel fixture. No SCM, accounts, network, or PID-based kills.
// Build baseline with -DSERVICE_PROCESS_JOB_BASELINE before adding the header.
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <winternl.h>
#include <tlhelp32.h>
#ifndef SERVICE_PROCESS_JOB_BASELINE
#include "orangespace/service_process_job.hpp"
#endif
namespace {
struct H {
    HANDLE h{};
    H() = default; explicit H(HANDLE v):h(v){}
    H(const H&)=delete; H& operator=(const H&)=delete;
    ~H(){if(h && h!=INVALID_HANDLE_VALUE) CloseHandle(h);}
};
void require(bool b,const char* s){if(!b) throw std::runtime_error(s);}
std::wstring exe;
struct Message { DWORD kind; std::uintptr_t handle; };
HANDLE report{}, supervisor{};
bool normal_exit_witness=false;
struct CrtWitness {
    ~CrtWitness(){if(normal_exit_witness){Message m{6,0};DWORD n{};WriteFile(report,&m,sizeof(m),&n,nullptr);}}
} crt_witness;
void send(DWORD kind,HANDLE h=nullptr) {
    Message m{kind,reinterpret_cast<std::uintptr_t>(h)}; DWORD n{};
    require(WriteFile(report,&m,sizeof(m),&n,nullptr)&&n==sizeof(m),"report write");
}
bool read_bounded(HANDLE h,void* p,DWORD size,DWORD ms) {
    const auto end=GetTickCount64()+ms;
    while(GetTickCount64()<end) {
        DWORD available{};
        if(!PeekNamedPipe(h,nullptr,0,nullptr,&available,nullptr)) return false;
        if(available>=size){DWORD n{};return ReadFile(h,p,size,&n,nullptr)&&n==size;}
        Sleep(5);
    }
    return false;
}
PROCESS_INFORMATION spawn(const std::wstring& args,const std::vector<HANDLE>& handles,DWORD flags=0,
                          const wchar_t* image=nullptr,HANDLE input=nullptr,HANDLE output=nullptr) {
    SIZE_T bytes{}; InitializeProcThreadAttributeList(nullptr,1,0,&bytes);
    std::vector<unsigned char> storage(bytes);
    auto list=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
    require(InitializeProcThreadAttributeList(list,1,0,&bytes)!=FALSE,"attribute init");
    struct Cleanup{LPPROC_THREAD_ATTRIBUTE_LIST p;~Cleanup(){DeleteProcThreadAttributeList(p);}} cleanup{list};
    require(UpdateProcThreadAttribute(list,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        const_cast<HANDLE*>(handles.data()),handles.size()*sizeof(HANDLE),nullptr,nullptr)!=FALSE,"handle list");
    STARTUPINFOEXW si{};si.StartupInfo.cb=sizeof(si);si.lpAttributeList=list;
    if(input){si.StartupInfo.dwFlags=STARTF_USESTDHANDLES;si.StartupInfo.hStdInput=input;
        si.StartupInfo.hStdOutput=output;si.StartupInfo.hStdError=output;}
    const std::wstring image_path=image?image:exe;
    std::wstring command=L"\""+image_path+L"\" "+args;
    PROCESS_INFORMATION pi{};
    require(CreateProcessW(image_path.c_str(),command.data(),nullptr,nullptr,TRUE,
        flags|EXTENDED_STARTUPINFO_PRESENT,nullptr,nullptr,&si.StartupInfo,&pi)!=FALSE,"CreateProcess fixture");
    return pi;
}
std::wstring number(HANDLE h){return std::to_wstring(reinterpret_cast<std::uintptr_t>(h));}
HANDLE parse(const wchar_t* s){return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(_wcstoui64(s,nullptr,10)));}
std::vector<HANDLE> inner_jobs; // Owner process lifetime, fixture only.
void inspect_self_job() {
#ifndef SERVICE_PROCESS_JOB_BASELINE
    using namespace orangespace::service::win;
    const HANDLE job=detail::service_process_job_handle;
    DWORD flags{};
    require(GetHandleInformation(job,&flags)&&!(flags&HANDLE_FLAG_INHERIT),"SelfJob noninherit handle");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    require(QueryInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof(limits),nullptr)!=FALSE,"query SelfJob limits");
    require(limits.BasicLimitInformation.LimitFlags==JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        "SelfJob ONLY kill-on-close; no active limit or breakaway");
    require(limits.BasicLimitInformation.ActiveProcessLimit==0,"SelfJob unlimited processes");
    BOOL member{};require(IsProcessInJob(GetCurrentProcess(),job,&member)&&member,"actual owner membership");
    using Query=LONG (NTAPI*)(HANDLE,ULONG,PVOID,ULONG,PULONG);
    const auto address=GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryObject");
    Query query{};static_assert(sizeof(query)==sizeof(address));std::memcpy(&query,&address,sizeof(query));
    require(query!=nullptr,"native object-name query");
    alignas(void*) unsigned char name[1024]{};ULONG used{};
    require(query(job,1,name,sizeof(name),&used)>=0,"query SelfJob object name");
    require(reinterpret_cast<UNICODE_STRING*>(name)->Length==0,"SelfJob unnamed");
    DWORD before{},after{};require(GetProcessHandleCount(GetCurrentProcess(),&before)!=FALSE,"handle count before");
    for(int i=0;i<16;++i)require(install_service_process_job()==ERROR_SUCCESS,"idempotent install");
    require(GetProcessHandleCount(GetCurrentProcess(),&after)&&before==after&&job==detail::service_process_job_handle,
        "duplicate install must not leak/replace Job");
    send(4);
#endif
}
void child(const wchar_t* role,bool nested=false) {
    const bool go=std::wstring(role)==L"go";
    H config_read,config_write,nul;
    PROCESS_INFORMATION pi{};
    if(go){
        SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};HANDLE r{},w{};
        require(CreatePipe(&r,&w,&sa,0)!=FALSE,"Go config pipe");config_read.h=r;config_write.h=w;
        require(SetHandleInformation(w,HANDLE_FLAG_INHERIT,0)!=FALSE,"private config writer");
        nul.h=CreateFileW(L"NUL",GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,&sa,OPEN_EXISTING,0,nullptr);
        require(nul.h!=INVALID_HANDLE_VALUE,"Go NUL output");
        // No inbound listener, credentials, node, or external connection.
        const char config[]=R"({"log":{"disabled":true},"route":{"rules":[{"action":"reject"}]}})";
        DWORD n{};require(WriteFile(w,config,sizeof(config)-1,&n,nullptr)&&n==sizeof(config)-1,"Go stdin config");
        CloseHandle(config_write.h);config_write.h=nullptr;
        const auto image=exe.substr(0,exe.find_last_of(L"\\/")+1)+L"sing-box.exe";
        pi=spawn(L"run --config stdin",{r,nul.h},CREATE_SUSPENDED,image.c_str(),r,nul.h);
    }else pi=spawn(std::wstring(role)+L" "+number(report)+L" "+number(supervisor),{report,supervisor},CREATE_SUSPENDED);
    H thread(pi.hThread); H process(pi.hProcess);
    if(nested){
        HANDLE inner=CreateJobObjectW(nullptr,nullptr);require(inner!=nullptr,"nested Job");
        inner_jobs.push_back(inner);
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        limits.BasicLimitInformation.ActiveProcessLimit=1;
        require(SetInformationJobObject(inner,JobObjectExtendedLimitInformation,&limits,sizeof(limits))!=FALSE,"nested single-member flags");
        require(AssignProcessToJobObject(inner,process.h)!=FALSE,"inherited outer -> inner nested admission");
        BOOL member{};require(IsProcessInJob(process.h,inner,&member)&&member,"actual inner membership");
    }
    HANDLE remote{};
    require(DuplicateHandle(GetCurrentProcess(),process.h,supervisor,&remote,
        SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,0)!=FALSE,"retain exact child object");
    send(1,remote);
    require(ResumeThread(thread.h)!=static_cast<DWORD>(-1),"resume child");
    if(go){require(WaitForSingleObject(process.h,1000)==WAIT_TIMEOUT,"real Go runtime stayed alive after stdin config");send(2);}
    // Local handles are closed, but supervisor retains the actual process object.
}
int owner(int argc,wchar_t** argv) {
    require(argc==6,"owner args");
    HANDLE activation=parse(argv[2]);report=parse(argv[3]);supervisor=parse(argv[4]);
    char byte{};
    // No children or SelfJob until supervisor has assigned its cleanup Job.
    // EOF/timeout means the supervisor died before activation: bounded clean exit.
    if(!read_bounded(activation,&byte,1,5000)||byte!='A')return 71;
    H activation_handle(activation);
#ifndef SERVICE_PROCESS_JOB_BASELINE
    require(orangespace::service::win::install_service_process_job()==ERROR_SUCCESS,"SelfJob install");
#endif
    inspect_self_job();
    const std::wstring mode=argv[5];
    child(mode==L"multi"?L"branch":(mode==L"go-gap"||mode==L"go-nested"?L"go":L"leaf"),
        mode==L"nested"||mode==L"go-nested");
    if(mode==L"multi")child(L"leaf");
    send(3);
    if(mode==L"normal") {
        require(read_bounded(activation,&byte,1,5000)&&byte=='R',"normal-return command");
        normal_exit_witness=true;
        return 0; // Must reach wmain AND CRT static destruction before kernel exit.
    }
    Sleep(INFINITE); return 0;
}
int run_case(const wchar_t* mode=L"gap") {
    SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};HANDLE rr{},rw{},ar{},aw{};
    require(CreatePipe(&rr,&rw,&sa,0)!=FALSE,"report pipe");H reader(rr),writer(rw);
    require(CreatePipe(&ar,&aw,&sa,0)!=FALSE,"activation pipe");H activation_reader(ar),activation_writer(aw);
    require(SetHandleInformation(rr,HANDLE_FLAG_INHERIT,0)!=FALSE,"private read");
    require(SetHandleInformation(aw,HANDLE_FLAG_INHERIT,0)!=FALSE,"private write");
    HANDLE sh{};require(DuplicateHandle(GetCurrentProcess(),GetCurrentProcess(),GetCurrentProcess(),&sh,
        PROCESS_DUP_HANDLE,TRUE,0)!=FALSE,"supervisor duplicate right");H self(sh);
    H fallback(CreateJobObjectW(nullptr,nullptr));require(fallback.h!=nullptr,"fallback job");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    require(SetInformationJobObject(fallback.h,JobObjectExtendedLimitInformation,&limits,sizeof(limits))!=FALSE,"fallback flags");
    auto pi=spawn(L"owner "+number(ar)+L" "+number(rw)+L" "+number(sh)+L" "+mode,{ar,rw,sh});
    H process(pi.hProcess),thread(pi.hThread);std::vector<HANDLE> children;
    struct Cleanup { HANDLE job,owner;std::vector<HANDLE>& children;~Cleanup(){
        // Only exact fixture-owned objects. Never PID lookup or broad process kill.
        TerminateJobObject(job,90);TerminateProcess(owner,90);WaitForSingleObject(owner,5000);
        for(auto h:children){WaitForSingleObject(h,5000);CloseHandle(h);}
    }} cleanup{fallback.h,process.h,children};
    if(std::wstring(mode)==L"activation-eof") {
        // Simulates loss of supervisor's only activation writer before fallback
        // assignment. Owner must exit with no descendants, without any cleanup kill.
        CloseHandle(activation_writer.h);activation_writer.h=nullptr;
        require(WaitForSingleObject(process.h,6000)==WAIT_OBJECT_0,"unactivated owner bounded EOF exit");
        DWORD code{},available{};require(GetExitCodeProcess(process.h,&code)&&code==71,"unactivated exit status");
        require(PeekNamedPipe(rr,nullptr,0,nullptr,&available,nullptr)&&available==0,"no child before activation");
        std::puts("activation_eof owner_exit=71 children=0 before_fallback_assignment");
        return 0;
    }
    require(AssignProcessToJobObject(fallback.h,process.h)!=FALSE,"fallback assignment");
    CloseHandle(activation_reader.h);activation_reader.h=nullptr;
    CloseHandle(writer.h);writer.h=nullptr;
    DWORD n{};char a='A';require(WriteFile(aw,&a,1,&n,nullptr)&&n==1,"activation");
    std::size_t ready=0;bool owner_ready=false,inspected=false;
    const std::size_t expected=std::wstring(mode)==L"multi"?3:1;
    const auto end=GetTickCount64()+10000;
    while((ready!=expected||!owner_ready||children.size()!=expected)&&GetTickCount64()<end){
        Message m{};require(read_bounded(rr,&m,sizeof(m),3000),"bounded readiness");
        if(m.kind==1)children.push_back(reinterpret_cast<HANDLE>(m.handle));
        else if(m.kind==2)++ready;
        else if(m.kind==3)owner_ready=true;
        else if(m.kind==4)inspected=true;
        else require(false,"unexpected message");
    }
    require(ready==expected&&owner_ready&&children.size()==expected,"complete readiness");
#ifndef SERVICE_PROCESS_JOB_BASELINE
    require(inspected,"owner verified native limits/noninherit/name/idempotence");
#else
    (void)inspected;
#endif
    for(auto h:children)require(WaitForSingleObject(h,0)==WAIT_TIMEOUT,"dummy child alive before owner hard exit");
    if(std::wstring(mode)==L"normal") {
        char r='R';require(WriteFile(aw,&r,1,&n,nullptr)&&n==1,"release normal return");
        Message m{};require(read_bounded(rr,&m,sizeof(m),5000)&&m.kind==5,"owner reached wmain after run return");
        require(read_bounded(rr,&m,sizeof(m),5000)&&m.kind==6,"owner reached CRT static destruction");
    } else require(TerminateProcess(process.h,83)!=FALSE,"hard terminate exact owner");
    require(WaitForSingleObject(process.h,5000)==WAIT_OBJECT_0,"owner kernel exit");
    // This check MUST precede fallback termination/close (including stack unwinding).
    bool dead=true;
    for(auto h:children)dead=(WaitForSingleObject(h,3000)==WAIT_OBJECT_0)&&dead;
    std::printf("%ls descendants=%zu child_exit_before_fallback=%s flags_noninherit_unnamed_idempotent=%s\n",
        mode,children.size(),dead?"true":"false",inspected?"true":"false");std::fflush(stdout);
    require(dead,"SelfJob must kill pre-inner-assignment child BEFORE fallback cleanup");
    return 0;
}
int audit() {
    const auto root=exe.substr(0,exe.find_last_of(L"\\/")+1);
    H snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0));
    require(snapshot.h!=INVALID_HANDLE_VALUE,"audit process snapshot");
    PROCESSENTRY32W entry{};entry.dwSize=sizeof(entry);unsigned count=0;
    require(Process32FirstW(snapshot.h,&entry)!=FALSE,"audit first process");
    do {
        if(entry.th32ProcessID==GetCurrentProcessId())continue;
        // Enumeration is read-only, not a kill target. Require exact executable
        // path before attribution; all actual termination uses retained handles.
        if(_wcsicmp(entry.szExeFile,L"selfjob-red.exe")&&_wcsicmp(entry.szExeFile,L"selfjob-green.exe")&&
           _wcsicmp(entry.szExeFile,L"selfjob-native.exe")&&_wcsicmp(entry.szExeFile,L"sing-box.exe"))continue;
        H process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,entry.th32ProcessID));
        require(process.h!=nullptr,"audit candidate query");
        wchar_t path[32768]{};DWORD size=32768;
        require(QueryFullProcessImageNameW(process.h,0,path,&size)!=FALSE,"audit exact candidate path");
        const std::wstring full(path,size);
        if(full.size()>=root.size()&&_wcsnicmp(full.c_str(),root.c_str(),root.size())==0)++count;
    }while(Process32NextW(snapshot.h,&entry));
    std::printf("cleanup_readback exact_fixture_processes=%u\n",count);
    require(count==0,"fixture process cleanup");return 0;
}
}
int wmain(int argc,wchar_t** argv) {
    wchar_t path[32768]{};require(GetModuleFileNameW(nullptr,path,32768)>0,"module path");exe=path;
    try {
        if(argc>1&&std::wstring(argv[1])==L"owner"){
            const int result=owner(argc,argv);if(normal_exit_witness)send(5);return result;
        }
        if(argc>1&&(std::wstring(argv[1])==L"leaf"||std::wstring(argv[1])==L"branch")){
            require(argc==4,"leaf args");report=parse(argv[2]);supervisor=parse(argv[3]);
            if(std::wstring(argv[1])==L"branch")child(L"leaf");
            send(2);
            // Deliberately ignores stdin and pipe EOF; only kernel termination ends it.
            Sleep(INFINITE);return 0;
        }
        if(argc==2&&std::wstring(argv[1])==L"audit")return audit();
        if(argc==2&&std::wstring(argv[1])==L"go"){run_case(L"go-gap");run_case(L"go-nested");return audit();}
        require(argc==1,"supervisor args");
        DWORD session{};require(ProcessIdToSessionId(GetCurrentProcessId(),&session)!=FALSE,"session query");
        std::printf("native Windows supervisor session=%lu\n",session);
        run_case(L"activation-eof");run_case();run_case(L"nested");run_case(L"multi");run_case(L"normal");
        return audit();
    }catch(const std::exception& e){std::fprintf(stderr,"FAIL %s (last_error=%lu)\n",e.what(),GetLastError());return 1;}
}
