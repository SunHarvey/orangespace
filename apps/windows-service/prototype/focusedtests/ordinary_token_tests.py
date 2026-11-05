from pathlib import Path
import re, subprocess, tempfile
source=Path(__file__).resolve().parents[1]/"service_win.cpp"
s=source.read_text()
match=re.search(r"const bool allowed=([^;]+);",s)
assert match is not None
expression=match.group(1)
with tempfile.TemporaryDirectory(dir="/var/tmp/hermes-runtime/tmp") as d:
 p=Path(d)
 cpp="#include <cassert>\nbool observed(bool app,bool same,unsigned count,unsigned elevated){(void)elevated;return "+expression+";}\nint main(){assert(observed(true,true,0,0));assert(!observed(true,true,0,1));assert(!observed(false,true,0,0));assert(!observed(true,false,0,0));assert(!observed(true,true,1,0));}\n"
 (p/"test.cpp").write_text(cpp)
 subprocess.run(["g++","-std=c++20","-Wall","-Wextra","-Werror",str(p/"test.cpp"),"-o",str(p/"test")],check=True)
 subprocess.run([str(p/"test")],check=True)
session=s[s.index("struct Session"):s.index("std::vector<wchar_t> environment")]
for field in ["TokenElevation","TokenIsAppContainer","TokenCapabilities"]:assert field in session,field
assert session.index("TokenElevation")<session.index("peer=token_peer")
print("actual Root predicate 5 cases and Session token-query source fences pass; not native token evidence")
