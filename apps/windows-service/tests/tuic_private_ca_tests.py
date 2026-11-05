"""Exact production backend injection; not native Windows acceptance."""
from pathlib import Path
import importlib.util
import subprocess
import sys
r = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
spec = importlib.util.spec_from_file_location('extract', Path(__file__).with_name('extract_lease_v2_backend.py'))
assert spec is not None and spec.loader is not None
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
source = (r/'apps/windows-service/src/chain_windows.cpp').read_text()
fixture = Path(__file__).with_name('lease_v2_backend_tests.cpp').read_text()
fixture = fixture.replace('void* os_runtime_new_with_ca_v1(const std::uint8_t* p,std::size_t n,unsigned t,const std::uint8_t*,std::size_t) {return os_runtime_new(p,n,t);}', '')
fixture = fixture.replace('void os_runtime_free(void*) {++frees;}', '''
static std::string passed_ca;
void* os_runtime_new_with_ca_v1(const std::uint8_t* p,std::size_t n,unsigned t,const std::uint8_t* ca,std::size_t len) {
  passed_ca.assign(reinterpret_cast<const char*>(ca),len);return os_runtime_new(p,n,t);
}
struct FixtureCatalog {
  orangespace::node_session::detail::NodeEntry entry;
  FixtureCatalog() {entry.node_id="33333333-3333-4333-8333-333333333333";entry.ca_pem=std::make_shared<const std::string>("protected-static-ca");}
  const auto& federation_node(std::string_view id) {if(id!=entry.node_id)throw std::runtime_error("node mismatch");return entry;}
};
void os_runtime_free(void*) {++frees;}
''')
header = m.generate(source).replace('  std::function<void()> on_call;', '  std::shared_ptr<FixtureCatalog> catalog_=std::make_shared<FixtureCatalog>();\n  std::function<void()> on_call;')
header = header.replace('std::shared_ptr<const std::string> trusted_ca_for_node(std::string_view) {return {};}', m.block(source, 'std::shared_ptr<const std::string> trusted_ca_for_node('))
(out/'lease_v2_backend_under_test.hpp').write_text(header)
fixture = fixture.replace('  auto start=orangespace::json::parse', '''  check(passed_ca=="protected-static-ca","static catalog CA must reach explicit runtime constructor");
  auto other=binding;other.node="55555555-5555-4555-8555-555555555555";other.tunnel="66666666-6666-4666-8666-666666666666";
  denies([&]{b.reserve(realm,other);});
  ExtractedBackend missing;missing.catalog_.reset();missing.reserve("missing",binding);
  denies([&]{(void)missing.start("missing",binding,lease);});
  ExtractedBackend mismatch;mismatch.catalog_->entry.node_id=other.node;mismatch.reserve("mismatch",binding);
  denies([&]{(void)mismatch.start("mismatch",binding,lease);});
  auto start=orangespace::json::parse''')
(out/'test.cpp').write_text(fixture)
subprocess.run(['g++','-std=c++20','-pthread','-Wall','-Wextra','-Werror','-I'+str(r/'apps/windows-service/include'),'-I'+str(r/'apps/windows-client/include'),'-I'+str(out),str(out/'test.cpp'),'-o',str(out/'test')],check=True)
subprocess.run([str(out/'test')],check=True)
