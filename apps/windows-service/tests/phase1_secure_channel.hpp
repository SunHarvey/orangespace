#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>
#include <array>
#include <algorithm>
#include <string>
#include <string_view>
#include <vector>
#include <cstdint>
#include <utility>
#include <cstring>

// Fixture primitive only. HeldPeer is exact OS identity, NOT proof that its
// origin/role/image is authoritative. No credential-bearing integration until
// a protected prelaunch scope supplies BOTH held expected peers independently.
namespace phase1::secure {
struct Failure {const char* stage; DWORD code;};
inline void require(bool condition,const char* stage) {
 if(!condition) {const DWORD e=GetLastError();throw Failure{stage,e?e:ERROR_INVALID_DATA};}
}
class Handle {
 HANDLE h_{};
public:
 Handle()=default;explicit Handle(HANDLE h):h_(h){}
 Handle(const Handle&)=delete;Handle& operator=(const Handle&)=delete;
 Handle(Handle&& o) noexcept:h_(std::exchange(o.h_,nullptr)){}
 Handle& operator=(Handle&& o) noexcept {if(this!=&o){Handle old(std::exchange(h_,std::exchange(o.h_,nullptr)));}return *this;}
 ~Handle(){if(h_&&h_!=INVALID_HANDLE_VALUE)CloseHandle(h_);}
 HANDLE get() const noexcept{return h_;}
 explicit operator bool() const noexcept{return h_&&h_!=INVALID_HANDLE_VALUE;}
};
struct Local {void* p{};~Local(){if(p)LocalFree(p);}};
#define PHASE1_SECURE_TYPED_PIPE 1
// Only the two local OVERLAPPED factories can adopt a handle. In particular a
// synchronous stdin/stdout/anonymous pipe cannot be passed to SecureChannel.
class Pipe {
 Handle handle_;
 explicit Pipe(Handle h):handle_(std::move(h)){}
 friend Pipe create_server(const std::wstring&,const std::wstring&);
 friend Pipe open_client(const std::wstring&);
public:
 Pipe()=default;Pipe(Pipe&&)=default;Pipe& operator=(Pipe&&)=default;
 Pipe(const Pipe&)=delete;Pipe& operator=(const Pipe&)=delete;
 HANDLE get() const noexcept{return handle_.get();}
 explicit operator bool() const noexcept{return bool(handle_);}
};
struct Identity {
 std::wstring sid; DWORD session{}; LUID logon{}; DWORD integrity{};
 TOKEN_ELEVATION_TYPE elevation{};bool restricted{};
 bool operator==(const Identity& o) const {
  return sid==o.sid&&session==o.session&&logon.HighPart==o.logon.HighPart&&logon.LowPart==o.logon.LowPart&&integrity==o.integrity&&elevation==o.elevation&&restricted==o.restricted;
 }
};
inline Identity token_identity(HANDLE token) {
 DWORD n{};GetTokenInformation(token,TokenUser,nullptr,0,&n);
 require(n&&n<65536,"token_user_size");std::vector<BYTE> b(n);
 require(GetTokenInformation(token,TokenUser,b.data(),n,&n),"token_user");
 LPWSTR raw{};require(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(b.data())->User.Sid,&raw),"token_sid");Local text{raw};
 Identity x;x.sid=raw;
 require(GetTokenInformation(token,TokenSessionId,&x.session,sizeof(x.session),&n),"token_session");
 TOKEN_STATISTICS stats{};require(GetTokenInformation(token,TokenStatistics,&stats,sizeof(stats),&n),"token_logon");x.logon=stats.AuthenticationId;
 require(GetTokenInformation(token,TokenElevationType,&x.elevation,sizeof(x.elevation),&n),"token_elevation");
 x.restricted=IsTokenRestricted(token)!=FALSE;
 GetTokenInformation(token,TokenIntegrityLevel,nullptr,0,&n);require(n&&n<65536,"token_integrity_size");b.resize(n);
 require(GetTokenInformation(token,TokenIntegrityLevel,b.data(),n,&n),"token_integrity");
 auto sid=reinterpret_cast<TOKEN_MANDATORY_LABEL*>(b.data())->Label.Sid;
 x.integrity=*GetSidSubAuthority(sid,*GetSidSubAuthorityCount(sid)-1);return x;
}
inline Identity process_identity(HANDLE process) {
 HANDLE raw{};require(OpenProcessToken(process,TOKEN_QUERY,&raw),"process_token");Handle token(raw);return token_identity(token.get());
}
class HeldPeer {
 Handle process_; Identity identity_; DWORD pid_{};FILETIME created_{};
 HeldPeer(Handle p,Identity x,DWORD pid,FILETIME time):process_(std::move(p)),identity_(std::move(x)),pid_(pid),created_(time){}
public:
 HeldPeer(HeldPeer&&)=default;HeldPeer& operator=(HeldPeer&&)=default;
 HeldPeer(const HeldPeer&)=delete;HeldPeer& operator=(const HeldPeer&)=delete;
 static HeldPeer capture(HANDLE held) {
  HANDLE raw{};require(DuplicateHandle(GetCurrentProcess(),held,GetCurrentProcess(),&raw,PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,0),"retain_expected_process");Handle p(raw);
  FILETIME a{},b{},c{},d{};require(GetProcessTimes(p.get(),&a,&b,&c,&d),"expected_creation");
  DWORD pid=GetProcessId(p.get());require(pid!=0,"expected_pid");auto identity=process_identity(p.get());
  return HeldPeer(std::move(p),std::move(identity),pid,a);
 }
 const Identity& identity() const noexcept{return identity_;}
 HANDLE process() const noexcept{return process_.get();}
 DWORD pid() const noexcept{return pid_;}
 FILETIME creation() const noexcept{return created_;}
 void verify_live(DWORD actual_pid) const {
  require(actual_pid==pid_&&WaitForSingleObject(process_.get(),0)==WAIT_TIMEOUT,"exact_live_process");
  FILETIME a{},b{},c{},d{};require(GetProcessTimes(process_.get(),&a,&b,&c,&d)&&a.dwLowDateTime==created_.dwLowDateTime&&a.dwHighDateTime==created_.dwHighDateTime,"exact_creation");
  require(process_identity(process_.get())==identity_,"primary_token_continuity");
 }
};
class Deadline {
 ULONGLONG end_;
public:
 explicit Deadline(DWORD ms):end_(GetTickCount64()+ms){}
 DWORD remaining() const {auto now=GetTickCount64();if(now>=end_)throw Failure{"absolute_deadline",WAIT_TIMEOUT};return static_cast<DWORD>((std::min)(end_-now,static_cast<ULONGLONG>(MAXDWORD-1)));}
 void check() const {(void)remaining();}
};
// On EVERY pending operation, completion or cancellation is joined before the
// OVERLAPPED, private event and buffer may die. Never FlushFileBuffers/Peek.
inline DWORD completed(HANDLE pipe,OVERLAPPED& op,const Deadline& deadline) {
 DWORD transferred{};DWORD wait{};
 try{wait=WaitForSingleObject(op.hEvent,deadline.remaining());}
 catch(...){CancelIoEx(pipe,&op);GetOverlappedResult(pipe,&op,&transferred,TRUE);throw;}
 if(wait!=WAIT_OBJECT_0){CancelIoEx(pipe,&op);GetOverlappedResult(pipe,&op,&transferred,TRUE);throw Failure{"io_deadline_or_wait",static_cast<DWORD>(wait==WAIT_TIMEOUT?WAIT_TIMEOUT:ERROR_OPERATION_ABORTED)};}
 require(GetOverlappedResult(pipe,&op,&transferred,FALSE),"io_completion");deadline.check();return transferred;
}
inline void transfer(HANDLE pipe,void* data,DWORD n,bool writing,const Deadline& deadline) {
 auto p=static_cast<BYTE*>(data);
 while(n){deadline.check();Handle event(CreateEventW(nullptr,TRUE,FALSE,nullptr));require(bool(event),"io_event");OVERLAPPED op{};op.hEvent=event.get();DWORD count{};
  BOOL done=writing?WriteFile(pipe,p,n,&count,&op):ReadFile(pipe,p,n,&count,&op);
  if(!done){require(GetLastError()==ERROR_IO_PENDING,"io_start");count=completed(pipe,op,deadline);}
  deadline.check();require(count&&count<=n,"io_progress");p+=count;n-=count;
 }
}
class SecretBuffer {
 std::array<char,32768> data_{};DWORD size_{};
public:
 SecretBuffer()=default;SecretBuffer(const SecretBuffer&)=delete;SecretBuffer& operator=(const SecretBuffer&)=delete;
 SecretBuffer(SecretBuffer&& o) noexcept:data_(o.data_),size_(o.size_){SecureZeroMemory(o.data_.data(),o.data_.size());o.size_=0;}
 SecretBuffer& operator=(SecretBuffer&&)=delete;
 ~SecretBuffer(){SecureZeroMemory(data_.data(),data_.size());}
 void assign(std::string_view s){require(!s.empty()&&s.size()<=data_.size(),"frame_size");std::memmove(data_.data(),s.data(),s.size());size_=static_cast<DWORD>(s.size());SecureZeroMemory(data_.data()+size_,data_.size()-size_);}
 std::string_view view() const noexcept{return {data_.data(),size_};}
 char* data() noexcept{return data_.data();}DWORD size() const noexcept{return size_;}
 void set_size(DWORD n){require(n&&n<=data_.size(),"frame_size");size_=n;}
};
inline void send_frame(HANDLE pipe,const SecretBuffer& body,const Deadline& deadline) {
 DWORD n=body.size();require(n&&n<=32768,"frame_size");std::array<BYTE,4> header{};
 for(unsigned i=0;i<4;++i)header[i]=static_cast<BYTE>(n>>(8*i));
 transfer(pipe,header.data(),4,true,deadline);transfer(pipe,const_cast<char*>(body.view().data()),n,true,deadline);
}
inline SecretBuffer receive_frame(HANDLE pipe,const Deadline& deadline) {
 std::array<BYTE,4> header{};transfer(pipe,header.data(),4,false,deadline);DWORD n{};
 for(unsigned i=0;i<4;++i)n|=DWORD(header[i])<<(8*i);
 SecretBuffer body;body.set_size(n);transfer(pipe,body.data(),n,false,deadline);return body;
}
inline Pipe create_server(const std::wstring& name,const std::wstring& sid) {
 // Never splice caller-controlled SDDL syntax/aliases into a security boundary.
 PSID raw_sid{};require(ConvertStringSidToSidW(sid.c_str(),&raw_sid),"canonical_numeric_peer_sid");Local parsed_sid{raw_sid};
 LPWSTR canonical{};require(ConvertSidToStringSidW(raw_sid,&canonical),"canonical_numeric_peer_sid");Local canonical_text{canonical};
 require(sid==canonical,"canonical_numeric_peer_sid");
 // OWNER RIGHTS suppresses implicit owner WRITE_DAC. No generic-write or
 // FILE_CREATE_PIPE_INSTANCE grant, even to the expected user. Medium MIC NW.
 std::wstring sddl=L"D:P(A;;RC;;;OW)(A;;0x00120083;;;SY)(A;;0x00120083;;;"+sid+L")S:(ML;;NW;;;ME)";
 PSECURITY_DESCRIPTOR raw{};require(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&raw,nullptr),"pipe_descriptor");Local sd{raw};SECURITY_ATTRIBUTES sa{sizeof(sa),raw,FALSE};
 Handle pipe(CreateNamedPipeW(name.c_str(),PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED|FILE_FLAG_FIRST_PIPE_INSTANCE,PIPE_TYPE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,4096,4096,0,&sa));require(bool(pipe),"pipe_create_first_local_single");return Pipe(std::move(pipe));
}
inline Pipe open_client(const std::wstring& name) {
 Handle pipe(CreateFileW(name.c_str(),FILE_READ_DATA|FILE_WRITE_DATA|FILE_READ_ATTRIBUTES|READ_CONTROL|SYNCHRONIZE,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IMPERSONATION,nullptr));require(bool(pipe),"pipe_client_explicit_rights");return Pipe(std::move(pipe));
}
inline void connect(HANDLE pipe,const Deadline& deadline) {
 deadline.check();Handle event(CreateEventW(nullptr,TRUE,FALSE,nullptr));require(bool(event),"connect_event");OVERLAPPED op{};op.hEvent=event.get();
 if(!ConnectNamedPipe(pipe,&op)){DWORD e=GetLastError();if(e!=ERROR_PIPE_CONNECTED){require(e==ERROR_IO_PENDING,"connect_start");(void)completed(pipe,op,deadline);}}
 deadline.check();
}
inline void authenticate_server(HANDLE pipe,const HeldPeer& expected) {
 ULONG pid{};require(GetNamedPipeServerProcessId(pipe,&pid),"server_pid");expected.verify_live(pid);
}
inline void authenticate_client(HANDLE pipe,const HeldPeer& expected) {
 ULONG pid{};require(GetNamedPipeClientProcessId(pipe,&pid),"client_pid");expected.verify_live(pid);
 require(ImpersonateNamedPipeClient(pipe),"impersonate_actual_connection");
 struct Revert {~Revert(){if(!RevertToSelf())TerminateProcess(GetCurrentProcess(),ERROR_CANNOT_IMPERSONATE);}} revert;
 HANDLE raw{};require(OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&raw),"connection_token");Handle token(raw);
 SECURITY_IMPERSONATION_LEVEL level{};DWORD size{};
 require(GetTokenInformation(token.get(),TokenImpersonationLevel,&level,sizeof(level),&size)&&level>=SecurityImpersonation,"connection_impersonation_level");
 require(token_identity(token.get())==expected.identity(),"connection_sid_session_logon_role");
}
#define PHASE1_SECURE_BOUND_CHANNEL 1
// Nonsecret 0x71 / 0x72 exchange establishes an actual read impersonation
// context before any framed content can be sent by the server. A timeout,
// malformed frame, disconnect or auth mismatch permanently closes this object.
class SecureChannel {
 Pipe pipe_; HeldPeer expected_; bool server_;
 SecureChannel(Pipe pipe,HeldPeer peer,bool server):pipe_(std::move(pipe)),expected_(std::move(peer)),server_(server){}
 void authenticate() const {
  require(bool(pipe_),"channel_closed");
  if(server_)authenticate_client(pipe_.get(),expected_);else authenticate_server(pipe_.get(),expected_);
 }
public:
 SecureChannel(SecureChannel&&)=default;SecureChannel& operator=(SecureChannel&&)=delete;
 SecureChannel(const SecureChannel&)=delete;SecureChannel& operator=(const SecureChannel&)=delete;
 bool open() const noexcept{return bool(pipe_);}
 static SecureChannel client(Pipe pipe,HeldPeer expected,const Deadline& deadline) {
  SecureChannel channel(std::move(pipe),std::move(expected),false);channel.authenticate();
  BYTE marker=0x71;transfer(channel.pipe_.get(),&marker,1,true,deadline);
  transfer(channel.pipe_.get(),&marker,1,false,deadline);require(marker==0x72,"server_ack");channel.authenticate();return channel;
 }
 static SecureChannel server(Pipe pipe,HeldPeer expected,const Deadline& deadline) {
  SecureChannel channel(std::move(pipe),std::move(expected),true);BYTE marker{};
  transfer(channel.pipe_.get(),&marker,1,false,deadline);require(marker==0x71,"client_hello");channel.authenticate();
  marker=0x72;transfer(channel.pipe_.get(),&marker,1,true,deadline);return channel;
 }
 void send(const SecretBuffer& body,const Deadline& deadline) {
  try{deadline.check();authenticate();send_frame(pipe_.get(),body,deadline);authenticate();}
  catch(...){pipe_=Pipe{};throw;}
 }
 SecretBuffer receive(const Deadline& deadline) {
  try{deadline.check();auto body=receive_frame(pipe_.get(),deadline);authenticate();return body;}
  catch(...){pipe_=Pipe{};throw;}
 }
};
}
