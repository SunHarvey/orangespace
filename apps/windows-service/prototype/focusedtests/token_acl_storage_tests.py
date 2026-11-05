"""Source-derived ACL size policy only; not native InitializeAcl evidence."""
from pathlib import Path
import ctypes
import re
import sys

source = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "service_win.cpp"
text = source.read_text()
owner = text[text.index("struct TokenObservation {"):text.index("\nbool io(", text.index("struct TokenObservation {"))]
match = re.search(r"std::vector<BYTE> storage=std::vector<BYTE>\((\d+)\);", owner)
assert match, "must extract actual production TokenObservation storage initializer"
size = int(match.group(1))

class ACL(ctypes.Structure):
    _fields_ = [("AclRevision", ctypes.c_uint8), ("Sbz1", ctypes.c_uint8),
                ("AclSize", ctypes.c_uint16), ("AceCount", ctypes.c_uint16),
                ("Sbz2", ctypes.c_uint16)]

DWORD = ctypes.c_uint32
assert size > ctypes.sizeof(ACL), f"ACL storage too small: {size}"
assert size <= 65535, f"ACL storage exceeds WORD maximum: {size}"
assert size % ctypes.sizeof(DWORD) == 0, f"ACL storage must be DWORD aligned: {size}"
print(f"production TokenObservation ACL storage={size}: >sizeof(ACL), <=65535, DWORD aligned; policy only, not native API evidence")
