"""Extract production candidate predicates; no claim of native BFE timing."""
from pathlib import Path
import unittest, subprocess, tempfile, os, hashlib
ROOT=Path(__file__).resolve().parents[4]
S=(ROOT/'drivers/wfp-prototype/network_policy_win.cpp').read_text()
V=(ROOT/'apps/windows-service/prototype/service_win.cpp').read_text()
class PairedSnapshot(unittest.TestCase):
 def test_one_transaction_capture(self):
  self.assertIn('void NetworkPolicy::withPairedSnapshot(',S)
  p=S[S.index('void NetworkPolicy::withPairedSnapshot('):S.index('void NetworkPolicy::cleanupAfterExactTreeExit')]
  for x in ['std::scoped_lock lock(s.mutex,t.mutex)','Transaction tx(s.engine)','s.metadata(s.engine)','t.metadata(s.engine)','s.inspectCandidate(f,wanted,out)','t.inspectCandidate(f,packageWanted,packaged)','callback(s.engine,out)','tx.commit()']:
   self.assertIn(x,p)
  self.assertEqual(p.count('FwpmFilterEnum0(s.engine,enumeration,128'),1)
  self.assertNotIn('else',p)
  self.assertLess(p.index('std::scoped_lock'),p.index('Transaction tx'))
  self.assertLess(p.index('t.metadata'),p.index('FwpmFilterEnum0'))
  self.assertLess(p.index('inventory-missing-filter'),p.index('callback(s.engine,out)'))
  self.assertLess(p.index('callback(s.engine,out)'),p.index('tx.commit()'))
  v=V[V.index('std::array<BYTE,32> rules_snapshot('):V.index('bool scm_self()')]
  self.assertIn('net.withPairedSnapshot(',v)
  self.assertNotIn('verifyExactPolicy',v)
  self.assertNotIn('FwpmEngineOpen0',v)
  # Freeze the serialized WFP proof, independently of startup changes.
  self.assertEqual(hashlib.sha256((v[v.index(' Canonical c;'):v.index(' digest=hashbytes')]).encode()).hexdigest(),"2bf60204986588ff95bef0c6f94e60cb6f8895e49fcd35595b6ec25e0e6db268")
 def test_actual_shared_candidate_negatives(self):
  self.assertIn('void inspectCandidate(',S)
  helper=S[S.index('  void inspectCandidate('):S.index('  void add(Rule r)')]
  self.assertIn('inspectCandidate(*batch.p[i],wanted,out);',S)
  prefix=S[S.index('// Independent namespace:'):S.index('struct Transaction {')]
  native=S[S.index('struct NativeRule {'):S.index('struct NetworkPolicy::Impl {')]
  harness='''
#include "package_native_test_shim.hpp"
#include <algorithm>
#include <iostream>
namespace orangespace::wfp_prototype { namespace {
PREFIX
NATIVE
enum class IdentityScope { ExecutablePath, ExactAppContainerSid };
struct VerifiedFilter { std::uint64_t filterId; Rule rule; IdentityScope identityScope; };
struct Owner {
 bool package=false; GUID provider=wfp_prototype::provider,sublayer=wfp_prototype::sublayer;
 FWP_BYTE_BLOB* app=nullptr; PSID packageSid=nullptr; PSID sid(){return packageSid;}
 std::array<UINT64,7> createdIds{};
 GUID key(unsigned n){return package ? packageKey(n) : wfp_prototype::key(n);}
HELPER
};
template<class F>void reject(F f){bool bad=false;try{f();}catch(const std::runtime_error&){bad=true;}require(bad,"negative accepted");}
}
int main(){using namespace orangespace::wfp_prototype;
 Owner o; auto wanted=policyRules(Mode::ProxyOnly,3210);std::vector<VerifiedFilter> out;
 unsigned char bytes[]={1,2}; FWP_BYTE_BLOB app{2,bytes};o.app=&app;
 NativeRule n(wanted[0],&app);n.filter.filterId=42;
 o.inspectCandidate(n.filter,wanted,out);require(out.size()==1,"valid missing");
 reject([&]{o.inspectCandidate(n.filter,wanted,out);});
 out.clear();n.filter.flags=0;reject([&]{o.inspectCandidate(n.filter,wanted,out);});n.filter.flags=FWPM_FILTER_FLAG_PERSISTENT|FWPM_FILTER_FLAG_INDEXED;
 auto old=n.filter.filterKey;n.filter.filterKey.Data1=99;reject([&]{o.inspectCandidate(n.filter,wanted,out);});n.filter.filterKey=old;
 Owner pkg;pkg.package=true;pkg.provider=packageProvider;pkg.sublayer=packageSublayer;
 n.filter.providerKey=&pkg.provider;reject([&]{o.inspectCandidate(n.filter,wanted,out);});
 reject([&]{pkg.inspectCandidate(n.filter,wanted,out);});
 struct FullSid { BYTE revision=1,count=8; SID_IDENTIFIER_AUTHORITY auth=SECURITY_APP_PACKAGE_AUTHORITY; DWORD sub[8]={2,1,2,3,4,5,6,7}; } sid;
 pkg.packageSid=&sid;
 NativeRule pn(wanted[0],nullptr,pkg.sid());pn.filter.filterId=77;
 reject([&]{pkg.inspectCandidate(pn.filter,wanted,out);});
 pkg.createdIds[slot(wanted[0])]=77;pkg.inspectCandidate(pn.filter,wanted,out);
 require(out.size()==1,"package receipt missing");out.clear();
 std::vector<VerifiedFilter> packaged;
 CLOSED
 reject([&]{closed();});
 for(auto rule:wanted){NativeRule f(rule,&app);f.filter.filterId=100+slot(rule);o.inspectCandidate(f.filter,wanted,out);}
 for(auto rule:wanted){NativeRule f(rule,nullptr,pkg.sid());f.filter.filterId=200+slot(rule);pkg.createdIds[slot(rule)]=f.filter.filterId;pkg.inspectCandidate(f.filter,wanted,packaged);}
 closed();out.clear();
 // created ID guard is evaluated only after exact native metadata succeeds.
 require(out.empty(),"failed candidate appended");
 std::cout<<"PASS actual candidate duplicate/extra/metadata/crossing rejection\\n";
}
'''
  with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as d:
   p=Path(d);(p/'test.cpp').write_text(harness.replace('PREFIX',prefix).replace('NATIVE',native).replace('HELPER',helper).replace('CLOSED', 'auto packageWanted=wanted;auto closed=[&]{'+next(l.strip() for l in S.splitlines() if 'out.size()==wanted.size() && packaged.size()' in l)+'};'))
   r=subprocess.run(['c++','-std=c++20','-I',str(ROOT/'drivers/wfp-prototype'),str(p/'test.cpp'),'-o',str(p/'test')],capture_output=True,text=True)
   self.assertEqual(r.returncode,0,r.stderr)
   r=subprocess.run([str(p/'test')],capture_output=True,text=True);self.assertEqual(r.returncode,0,r.stderr)
if __name__=='__main__':unittest.main()
