"""Offline cross-builder only. No install, remote execution, SCM or policy writes."""
import argparse,hashlib,json,pathlib,re,subprocess
P=pathlib.Path(__file__).resolve().parent
SCRATCH=pathlib.Path('/root/.hermes/cache/scratch')
def validate(nonce,sid):
 if not re.fullmatch(r'[0-9a-f]{24}',nonce):raise ValueError('24 lowercase hex nonce required')
 if not re.fullmatch(r'S-1-5-21-(?:[0-9]{1,10}-){3}[0-9]{1,10}',sid):raise ValueError('explicit approved account SID required')
 if any(int(x)>4294967295 for x in sid.split('-')[4:]):raise ValueError('SID subauthority overflow')
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 a=argparse.ArgumentParser();a.add_argument('--nonce',required=True);a.add_argument('--approved-sid',required=True);a.add_argument('--out',type=pathlib.Path,required=True);args=a.parse_args()
 validate(args.nonce,args.approved_sid)
 out=args.out.absolute()
 if out.parent.resolve()!=SCRATCH.resolve() or out.exists():raise ValueError('fresh direct scratch child required')
 out.mkdir();payload=out/'payload';payload.mkdir()
 root='C:\\Program Files\\OrangeSpace-OSB-Admission-'+args.nonce
 compiler='x86_64-w64-mingw32-g++'
 flags=['-std=c++17','-O2','-Wall','-Wextra','-Werror','-municode','-static','-static-libgcc','-static-libstdc++','-Wl,--no-insert-timestamp','-I'+str(P),'-I'+str(out)]
 commands=[]
 def build(name):
  cmd=[compiler,*flags,str(P/(name+'.cpp')),'-o',str(payload/(name+'.exe')),'-ladvapi32','-lbcrypt','-lwtsapi32'];commands.append(cmd);subprocess.run(cmd,check=True)
 build('phase1_osb_system_probe_worker')
 plan=payload/'phase1_osb_system_plan.txt';plan.write_bytes((args.nonce+'\n'+args.approved_sid+'\n2\n'+digest(payload/'phase1_osb_system_probe_worker.exe')+'\n').encode('ascii'))
 config=out/'phase1_osb_system_config.hpp'
 config.write_text('#pragma once\n#define OSBS_ROOT L'+json.dumps(root)+'\n#define OSBS_NONCE L"'+args.nonce+'"\n#define OSBS_NONCE_A "'+args.nonce+'"\n#define OSBS_PLAN_SHA256 "'+digest(plan)+'"\n',encoding='ascii')
 build('phase1_osb_system_service')
 imports={}
 for exe in sorted(payload.glob('*.exe')):
  output=subprocess.check_output(['x86_64-w64-mingw32-objdump','-p',str(exe)],text=True)
  (out/(exe.stem+'_imports.txt')).write_text(output)
  dlls=re.findall(r'DLL Name:\s*(\S+)',output)
  if any(re.search(r'(libstdc|libgcc|libwinpthread|vcruntime|msvcp)',d,re.I) for d in dlls):raise RuntimeError('non-system runtime DLL import')
  imports[exe.name]=dlls
 sources={p.name:digest(p) for p in sorted(P.glob('phase1_osb_system_*')) if p.is_file()}
 report={'schema':'osb-system-admission-build-v1','service_name':'OrangeSpaceOSBAdmission-'+args.nonce,'module_root':root,'service_type':'SERVICE_WIN32_OWN_PROCESS','account':'LocalSystem','arguments':[],'service_leaf':'phase1_osb_system_service.exe','worker_leaf':'phase1_osb_system_probe_worker.exe','manifest_leaf':plan.name,'manifest_sha256':digest(plan),'files':{p.name:{'sha256':digest(p),'bytes':p.stat().st_size} for p in sorted(payload.iterdir())},'source_sha256':sources,'config_sha256':digest(config),'imports':imports,'compiler':subprocess.check_output([compiler,'--version'],text=True),'commands':commands,'native_execution':'UNRUN','guardian_approved':False,'os_b':False,'full_acceptance':False,'cleanup_verified':False}
 (out/'phase1_osb_system_provenance.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'output':str(out),'files':report['files'],'native_execution':'UNRUN'},indent=2))
if __name__=='__main__':main()
