"""Extract production diagnostics and predicate; portable seam, not native evidence."""
from pathlib import Path
import ast, subprocess, tempfile, sys
source=Path(sys.argv[1]) if len(sys.argv)>1 else Path(__file__).resolve().parents[1]/'service_win.cpp'
s=source.read_text(); owner=s[s.index('struct TokenObservation {'):s.index('\nbool io(',s.index('struct TokenObservation {'))]
assert 'check(got&&identity(current,baseline)&&same_acl(acl(current),next));' in owner, 'missing readback diagnostics with original short-circuit order'
boundary=owner[owner.index('changed=true;'):owner.index('verified=true;')]
assert boundary.count('read(current')==1
assert boundary.index('read(current')<boundary.index('diagnose_readback(')<boundary.index('check(got&&')
helper=owner[owner.index(' void diagnose_readback('):owner.index(' void restore()')]
for forbidden in ['sidtext','ConvertSid','e.what','SetKernel','AddAce','SetEntries','std::string','snprintf']:
 assert forbidden not in helper, forbidden
assert 'noexcept' in helper and 'catch(...)' in helper
for name in ['read-ok','read-error','baseline-control','current-control','owner-equal','group-equal','actual-revision','wanted-revision','actual-count','wanted-count','actual-used','wanted-used']:
 assert '"token-rb-'+name+'"' in helper,name
for i in range(8):
 for field in ['actual-mask','wanted-mask','actual-type','wanted-type','actual-flags','wanted-flags','actual-size','wanted-size','sid-equal']:
  assert f'"token-rb-{i}-{field}"' in helper
# Reuse only the existing injected API seam; execute actual extracted production.
tree=ast.parse((Path(__file__).parent/'token_observation_tests.py').read_text())
shim=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='shim' for t in n.targets))
shim=shim.replace('void report_fixed(const char*,DWORD){};', 'char labels[256][64]{};DWORD values[256]{};unsigned logged=0;void report_fixed(const char*l,DWORD v){assert(logged<256);std::strcpy(labels[logged],l);values[logged++]=v;}')
main=r'''
DWORD value(const char*l){for(unsigned i=0;i<logged;i++)if(!strcmp(labels[i],l))return values[i];assert(false);return 0;}
int main(){Session s;reset();{TokenObservation o(s,&pkg);assert(o.verified);assert(value("token-rb-read-ok")==1);assert(value("token-rb-read-error")==0);assert(value("token-rb-owner-equal")==1);assert(value("token-rb-group-equal")==1);assert(value("token-rb-actual-used")==value("token-rb-wanted-used"));assert(value("token-rb-0-actual-mask")==0xffff);assert(value("token-rb-0-sid-equal")==1);}assert(writes==2);
logged=0;reset();fail_read=4;try{TokenObservation o(s,&pkg);assert(false);}catch(Failure&){}assert(writes==1);assert(value("token-rb-read-ok")==0);assert(value("token-rb-read-error")==ERROR_INSUFFICIENT_BUFFER);
logged=0;reset();drift_at=4;try{TokenObservation o(s,&pkg);assert(false);}catch(Failure&){}assert(writes==1);assert(value("token-rb-owner-equal")==0);assert(value("token-rb-group-equal")==1);puts("production readback scalars/order/no-secret portable seam passed; native pending");}
'''
with tempfile.TemporaryDirectory(dir='/root/.hermes/cache/scratch') as d:
 p=Path(d);(p/'test.cpp').write_text(shim+owner+main)
 subprocess.run(['g++','-std=c++20','-Wall','-Wextra',str(p/'test.cpp'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
