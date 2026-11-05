"""Focused package-policy source contracts; not Windows enforcement evidence."""
from pathlib import Path
import unittest
import subprocess
import tempfile
import os

ROOT = Path(__file__).resolve().parent
H = (ROOT / "network_policy_win.hpp").read_text()
S = (ROOT / "network_policy_win.cpp").read_text()

class PackagePolicyContracts(unittest.TestCase):
    def test_separate_native_api(self):
        self.assertIn("class PackageNetworkPolicy final", H)
        self.assertIn("void installOffline(PSID exactAppContainerSid)", H)
        self.assertIn("IdentityScope identityScope", H)

    def test_native_sid_not_image_and_strict_value(self):
        self.assertIn("FWPM_CONDITION_ALE_PACKAGE_ID", S)
        self.assertIn("FWP_SID", S)
        self.assertIn("EqualSid", S)
        self.assertIn("GetSidSubAuthorityCount", S)
        self.assertIn("GetSidIdentifierAuthority", S)
        self.assertIn("GetSidSubAuthority", S)
        self.assertIn("actual.flags==wanted.flags", S)

    def test_shared_algorithm_and_fresh_ownership(self):
        self.assertEqual(S.count("struct NativeRule {"), 1)
        self.assertEqual(S.count("void replace(Mode next"), 1)
        self.assertIn("packageProvider", S)
        self.assertIn("packageSublayer", S)
        self.assertIn("package-namespace-not-fresh", S)
        self.assertIn("s.lifecycle=Impl::Lifecycle::Installed", S)
        self.assertIn("namespaceOwned", S)
        install = S[S.index("void PackageNetworkPolicy::installOffline"):S.index("void PackageNetworkPolicy::switchToProxyOnly")]
        self.assertLess(install.index("validatePackageSid(exactAppContainerSid)"), install.index('check("FwpmEngineOpen0"'))
        self.assertLess(install.index("package-namespace-not-fresh-filter"), install.index('check("FwpmProviderAdd0"'))
        self.assertLess(install.index("tx.commit()"), install.index("s.namespaceOwned=true"))
        self.assertLess(install.index("s.namespaceOwned=true"), install.index("Transaction readback"))
        self.assertIn("createdIds[slot(*it)]==f.filterId", S)
        self.assertIn("if(!committed) target=old", S)
        self.assertNotIn("NetworkIsolation", S)

    def test_assigned_sublayer_weight_pinned_once(self):
        self.assertIn("void pinAssignedWeight(", S, "old implementation has no one-time OS assignment pin")
        methods = S[S.index("  void pinAssignedWeight("):S.index("  std::vector<VerifiedFilter> inventory(")]
        fields = S[S.index("  bool assignedWeightPinned="):S.index("  std::array<UINT64,7> createdIds")]
        inventory = S[S.index("  std::vector<VerifiedFilter> inventory("):S.index("  void add(Rule r)")]
        self.assertLess(inventory.index('require(out.size()==wanted.size()'), inventory.index("if(recovering) pinAssignedWeight"))
        self.assertIn("!package && lifecycle==Lifecycle::Empty && !assignedWeightPinned", inventory)
        self.assertEqual(S.count("s.pinAssignedWeight(s.readSublayerWeight());"), 2)
        self.assertEqual(S.count("l.weight=0xffff;"), 2)
        harness = r'''
#include "package_native_test_shim.hpp"
#include <iostream>
using HANDLE=void*;
constexpr UINT32 FWPM_SUBLAYER_FLAG_PERSISTENT=1, FWPM_PROVIDER_FLAG_PERSISTENT=1;
struct FWPM_SUBLAYER0 { GUID subLayerKey{}; UINT32 flags=1; GUID* providerKey=nullptr; std::uint16_t weight=65534; FWP_BYTE_BLOB providerData{}; };
struct FWPM_PROVIDER0 { GUID providerKey{}; UINT32 flags=1; FWP_BYTE_BLOB providerData{}; wchar_t* serviceName=nullptr; };
FWPM_SUBLAYER0 actual;
FWPM_PROVIDER0 actualProvider;
template<class T> struct Memory { T* p=nullptr; };
DWORD FwpmSubLayerGetByKey0(void*,const GUID*,FWPM_SUBLAYER0** out) { *out=&actual; return 0; }
DWORD FwpmProviderGetByKey0(void*,const GUID*,FWPM_PROVIDER0** out) { *out=&actualProvider; return 0; }
bool eq(const GUID&a,const GUID&b) { return IsEqualGUID(a,b); }
void fail(const char* label,DWORD) { throw std::runtime_error(label); }
void require(bool ok,const char* label) { if(!ok) fail(label,13); }
void check(const char* label,DWORD code) { if(code) fail(label,code); }
struct Owner {
 bool package=false; GUID provider{2,0,0,{}}, sublayer{1,0,0,{}}; void* engine=nullptr;
FIELDS
METHODS
};
template<class F> void rejects(F f) { bool rejected=false; try { f(); } catch(const std::runtime_error&) { rejected=true; } require(rejected,"negative accepted"); }
int main() {
 Owner o; actual.subLayerKey=o.sublayer;
 rejects([&]{o.metadata();});
 o.pinAssignedWeight(o.readSublayerWeight()); o.metadata();
 actual.weight=65533; rejects([&]{o.metadata();}); rejects([&]{o.pinAssignedWeight(o.readSublayerWeight());});
 actual.weight=65534; o.metadata(); rejects([&]{o.pinAssignedWeight(65534);});
 actual.flags=3; rejects([&]{o.readSublayerWeight();}); actual.flags=1;
 actual.providerKey=&o.provider; rejects([&]{o.readSublayerWeight();}); actual.providerKey=nullptr;
 actual.weight=0xfeff; rejects([&]{o.readSublayerWeight();});
 actual.weight=0xff00; Owner fresh; fresh.pinAssignedWeight(fresh.readSublayerWeight()); fresh.metadata();
 actual.weight=65535; Owner high; high.pinAssignedWeight(high.readSublayerWeight()); high.metadata();
 actual.weight=65534; actual.providerData.size=1; rejects([&]{o.readSublayerWeight();}); actual.providerData.size=0;
 actual.subLayerKey.Data1=99; rejects([&]{o.readSublayerWeight();}); actual.subLayerKey=o.sublayer;
 Owner pkg; pkg.package=true; actual.providerKey=&pkg.provider; actualProvider.providerKey=pkg.provider;
 pkg.pinAssignedWeight(pkg.readSublayerWeight()); pkg.metadata();
 actual.providerKey=&pkg.sublayer; rejects([&]{pkg.metadata();});
 std::cout << "PASS one-time assigned sublayer weight and strict drift rejection\n";
}
'''
        with tempfile.TemporaryDirectory(prefix="weight-wfp-", dir=os.environ.get("TMPDIR")) as d:
            p = Path(d)
            (p / "test.cpp").write_text(harness.replace("FIELDS", fields).replace("METHODS", methods))
            result = subprocess.run(["c++", "-std=c++20", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT), str(p / "test.cpp"), "-o", str(p / "test")], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(p / "test")], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("PASS one-time", result.stdout)

    @unittest.skipIf(os.name == "nt", "Linux extracted-body lane; native CTest is separate")
    def test_actual_native_rule_predicates(self):
        # Preserve the actual production builders, SID validation and readback
        # predicates byte-for-byte; only Win32 types/SID APIs are shimmed.
        prefix = S[S.index("// Independent namespace:"):S.index("struct Transaction {")]
        native = S[S.index("struct NativeRule {"):S.index("struct NetworkPolicy::Impl {")]
        with tempfile.TemporaryDirectory(prefix="package-wfp-", dir=os.environ.get("TMPDIR")) as d:
            p = Path(d)
            (p / "package_native_extracted.hpp").write_text(
                '#include "package_native_test_shim.hpp"\nnamespace orangespace::wfp_prototype { namespace {\n'
                + prefix + native + '}\n')
            compiled = subprocess.run(["c++", "-std=c++20", "-Wall", "-Wextra", "-Werror", "-UNDEBUG",
                            "-I", str(ROOT), "-I", d, str(ROOT / "package_native_tests.cpp"),
                            "-o", str(p / "test")], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([str(p / "test")], check=True, capture_output=True, text=True)
            self.assertIn("PASS actual native rule", result.stdout)

if __name__ == "__main__":
    unittest.main()
