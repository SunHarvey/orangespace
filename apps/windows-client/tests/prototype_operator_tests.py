"""Narrow source glue and extracted bounded-input policy; no native login claim."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[3]
SOURCE=ROOT/'apps/windows-client/prototype/prototype_operator_win.cpp'
P=Path('/var/tmp/hermes-runtime/tmp/orangespace-single-prototype-20261102')
class OperatorTests(unittest.TestCase):
    def test_login_is_sdk_owned_not_a_new_auth_stack(self):
        self.assertTrue(SOURCE.exists(),'missing ordinary-user Prototype operator')
        s=SOURCE.read_text()
        for token in ['CredentialStore::load(config)','Session::login(config','sc::authorize_platform(', 'sc::register_sandbox(', 'sc::start_tunnel(', 'ORANGESPACE_PROTOTYPE_NODE_UUID','TokenElevation','WinInteractiveSid','FILE_TYPE_PIPE','--login-stdin','platform.json','请求已接受']:
            self.assertIn(token,s)
        for forbidden in ['CredentialStore::save','CredentialStore::erase','CreateProcess','WinHttp','getenv','ofstream','sc::logout(']:self.assertNotIn(forbidden,s)
    def test_native_dialog_reuses_sdk_without_secret_transport(self):
        s=SOURCE.read_text()
        self.assertIn('--login-dialog',s)
        self.assertIn('CredUIPromptForCredentialsW',s)
        self.assertIn('CREDUI_FLAGS_DO_NOT_PERSIST',s)
        self.assertIn('CREDUI_FLAGS_GENERIC_CREDENTIALS',s)
        self.assertIn('SecureZeroMemory',s)
        self.assertLess(s.index('ordinary_user();'),s.index('const bool login_dialog'))
        self.assertIn('session.emplace(ps::Session::login(config,username.view(),password.view()))',s)
        for bad in ['CreateRestrictedToken','DuplicateTokenEx','AdjustTokenPrivileges','CredentialStore::save','WriteFile(','getenv','CryptProtectData']:
            self.assertNotIn(bad,s)
    def test_bounded_secret_lines(self):
        self.assertTrue(SOURCE.exists(),'missing ordinary-user Prototype operator')
        code=SOURCE.read_text().split('// OPERATOR_INPUT_BEGIN\n')[1].split('// OPERATOR_INPUT_END')[0]
        test='#include "orangespace/platform_session.hpp"\n#include <cassert>\n'+code+r'''
int main(){
 auto parse=[](std::string_view s,std::size_t limit){std::size_t n=0;return prototype_input::line([&](char& c){if(n==s.size())return false;c=s[n++];return true;},limit);};
 assert(parse("abc\n",3).view()=="abc");
 auto reject=[&](std::string_view s,std::size_t limit){bool denied=false;try{parse(s,limit);}catch(...){denied=true;}assert(denied);};
 reject("\n",3);reject("abcd\n",3);reject("abc",3);reject("a\rb\n",3);reject("a\0b\n",3);
 std::string full(1024,'x');full+='\n';assert(parse(full,1024).view().size()==1024);
}
'''
        with tempfile.TemporaryDirectory(prefix='operator-input-',dir=P) as d:
            src=Path(d)/'test.cpp';src.write_text(test);exe=Path(d)/'test'
            subprocess.run(['g++','-std=c++20','-Wall','-Wextra','-Werror','-I'+str(ROOT/'apps/windows-client/include'),str(src),'-o',str(exe)],check=True)
            subprocess.run([str(exe)],check=True)
if __name__=='__main__':unittest.main()
