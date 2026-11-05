#!/usr/bin/env python3
"""Fresh exact-body extraction. Output stays in the caller's scratch directory."""
from pathlib import Path
import argparse, hashlib, json, subprocess
p=argparse.ArgumentParser();p.add_argument('out',type=Path);p.add_argument('cases',nargs='+');p.add_argument('--sanitized',action='store_true');p.add_argument('--no-elide',action='store_true');a=p.parse_args()
d=Path(__file__).resolve().parent;a.out.mkdir(parents=True,exist_ok=True)
s=(d/'phase1_os_b_win.hpp').read_text()
start=s.index('inline void require_io_time(') if 'inline void require_io_time(' in s else s.index('inline void await_io(')
body=s[start:s.index('inline void send_private(')]+s[s.index('inline void connect_owned_private('):s.index('inline Local descriptor(')]
h=a.out/'deadline_body.inc';h.write_text(body)
exe=a.out/('deadline_tests'+('_sanitized' if a.sanitized else '')+('_noelide' if a.no_elide else ''))
cmd=['g++','-std=c++20','-Wall','-Wextra','-Werror',f'-I{d}',f'-DOSB_EXTRACTED_BODY="{h}"']
if a.sanitized:cmd+=['-fsanitize=address,undefined','-fno-omit-frame-pointer','-fno-pie','-no-pie']
if a.no_elide:cmd+=['-fno-elide-constructors']
cmd += [str(d/'phase1_os_b_deadline_tests.cpp'),'-o',str(exe)]
records=[]
for c in [cmd]+[[str(exe),case] for case in a.cases]:
 q=subprocess.run(c,capture_output=True,text=True);records.append({'command':c,'exit':q.returncode,'stdout':q.stdout,'stderr':q.stderr});print(q.stdout+q.stderr,end='')
 if q.returncode and c==cmd:break
r={'body_sha256':hashlib.sha256(body.encode()).hexdigest(),'source_sha256':hashlib.sha256(s.encode()).hexdigest(),'records':records}
(a.out/'results.json').write_text(json.dumps(r,indent=2));raise SystemExit(any(x['exit'] for x in records))
