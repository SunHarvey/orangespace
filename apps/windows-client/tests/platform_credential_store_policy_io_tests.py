"""Execute extracted production bodies with RAM-only OS seams + real SDK restore.
This is policy evidence, NOT native DPAPI/NTFS acceptance.
"""
import os
import pathlib
import subprocess
import tempfile
import sys
ROOT = pathlib.Path(__file__).resolve().parents[3]
CLIENT = ROOT / 'apps/windows-client'
source = pathlib.Path(sys.argv[1]) if len(sys.argv)>1 else CLIENT/'src/credential_store_win.cpp'
text = source.read_text()
if 'namespace orangespace::platform_session {' not in text:
    raise SystemExit('RED: central CredentialStore implementations are missing')
section = text.split('namespace orangespace::platform_session {',1)[1]
methods = section[section.index('void CredentialStore::save('):section.rindex('} // namespace orangespace::platform_session')]
main = r'''
int main(){
  using namespace orangespace::platform_session;
  using namespace orangespace::node_session;
  auto config=orangespace::platform_session::detail::TestAccess::config();
  auto s=Session::restore(config,envelope());
  CredentialStore::save(config,s);
  int calls=restores;
  auto restored=CredentialStore::load(config);
  assert(restores==calls+1 && restored.identity().username=="alice");
  // Pending marker rejects before crypto or central request, including old save.
  auto& r=records[config.api_origin()];r.marker=true;calls=restores;crypto_failure=true;
  denied([&]{CredentialStore::load(config);});denied([&]{CredentialStore::save(config,s);});
  assert(restores==calls && r.marker);crypto_failure=false;
  CredentialStore::erase(config);assert(!r.marker && r.encrypted.empty());
  // Config/session source mismatch cannot publish in the other centre's slot.
  auto other=orangespace::platform_session::detail::TestAccess::config("https://other.example.test");
  denied([&]{CredentialStore::save(other,s);});assert(records[other.api_origin()].encrypted.empty());
  CredentialStore::save(config,s);auto original=r.encrypted;
  // SDK restore actually rejects revoked central sessions, not decrypt-and-login.
  central.status=401;calls=restores;
  denied([&]{CredentialStore::load(config);});assert(restores==calls+1 && r.encrypted.empty() && !r.marker);
  central.status=200;CredentialStore::save(config,s);
  // Failed deletion after invalidation retains marker and the original blob.
  central.status=401;r.fail_delete=true;calls=restores;
  bool original_error=false;
  try{CredentialStore::load(config);}catch(const orangespace::platform_session::HttpStatusError& e){original_error=e.status_code()==401;}
  assert(original_error && restores==calls+1 && r.marker && r.encrypted==original && r.opened==0);
  calls=restores;denied([&]{CredentialStore::load(config);});assert(restores==calls);
  r.fail_delete=false;CredentialStore::erase(config);assert(!r.marker && r.encrypted.empty());central.status=200;
  // Failed marker removal is retryable and denies later saves.
  CredentialStore::save(config,s);r.fail_clear=true;
  denied([&]{CredentialStore::erase(config);});assert(r.marker && r.encrypted.empty());
  denied([&]{CredentialStore::save(config,s);});r.fail_clear=false;CredentialStore::erase(config);
  // Tamper / expiry fails before SDK restore and uses identical cleanup.
  for(bool expire:{false,true}) {
    CredentialStore::save(config,s);
    if(expire){auto pos=r.encrypted.find("\"expires_at\":2000");assert(pos!=std::string::npos);r.encrypted.replace(pos,17,"\"expires_at\":1000");}
    else r.encrypted[0]='!';
    calls=restores;denied([&]{CredentialStore::load(config);});
    assert(restores==calls && r.encrypted.empty() && !r.marker);
  }
  // Restore source-binding rejects a foreign envelope even with local scope.
  Directory d(StoreKind::platform);auto key=storage_key(config);
  auto wrong=encrypt(envelope(other.api_origin()),d.scope(key));atomic_write(d,key,wrong);
  calls=restores;denied([&]{CredentialStore::load(config);});assert(restores==calls && r.encrypted.empty());
  std::cout<<"actual central store bodies + real SDK restore policy passed\n";
}
'''
# Disambiguate fixture-only using-directives; production namespace lookup is exact.
main=main.replace('CredentialStore::','orangespace::platform_session::CredentialStore::')
with tempfile.TemporaryDirectory(prefix='platform-store-policy-',dir=os.environ.get('TMPDIR')) as td:
    cpp=pathlib.Path(td)/'policy.cpp'; exe=pathlib.Path(td)/'policy'
    cpp.write_text('#include "platform_credential_store_policy_io.hpp"\nnamespace orangespace::platform_session {\n'+methods+'}\n'+main)
    subprocess.run(['g++','-std=c++20','-Wall','-Wextra','-Werror','-I'+str(CLIENT/'include'),'-I'+str(CLIENT/'tests'),str(cpp),str(CLIENT/'src/platform_session_win.cpp'),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
