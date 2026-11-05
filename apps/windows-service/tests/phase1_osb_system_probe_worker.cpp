#include "phase1_osb_system_win.hpp"
// Fixed executable: no commands, credentials, arbitrary paths or children.
int wmain(int argc,wchar_t** argv){
 try {
  if(argc!=4 || std::wstring(argv[2])!=L"2" || !osbs::valid_nonce(osbs::narrow(argv[3])))return 64;
  osbs::Handle token;HANDLE t=nullptr;
  if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&t)){return 65;}
  token.reset(t);
  // identity() reads actual TokenSessionId and TokenElevationType from this OS token.
  auto id=osbs::identity(token.h);BOOL job=FALSE;
  if(!IsProcessInJob(GetCurrentProcess(),nullptr,&job))return 66;
  if(!osbs::admission_identity(id.sid,osbs::narrow(argv[1]),id.session,id.limited)||!job)return 67;
  return 63; // all six fixed admission checks passed; not B/full acceptance.
 }catch(...){return 68;}
}
