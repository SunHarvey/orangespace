"""Non-executing final-PE regression: python gui_manifest_tests.py <GUI.exe>."""
from pathlib import Path
import struct
import sys
import xml.etree.ElementTree as ET


def resources(path):
    data = Path(path).read_bytes()
    u16 = lambda p: struct.unpack_from('<H', data, p)[0]
    u32 = lambda p: struct.unpack_from('<I', data, p)[0]
    pe = u32(0x3c)
    assert data[pe:pe + 4] == b'PE\0\0'
    opt = pe + 24
    dd = opt + (112 if u16(opt) == 0x20b else 96)
    sections = opt + u16(pe + 20)
    def offset(rva):
        for n in range(u16(pe + 6)):
            s = sections + n * 40
            va = u32(s + 12)
            if va <= rva < va + max(u32(s + 8), u32(s + 16)):
                return u32(s + 20) + rva - va
        raise AssertionError('unmapped RVA')
    base = offset(u32(dd + 16))
    result = {}
    def walk(relative, keys):
        d = base + relative
        for i in range(u16(d + 12) + u16(d + 14)):
            e = d + 16 + 8 * i
            name, target = u32(e), u32(e + 4)
            assert not name & 0x80000000, 'unexpected named resource'
            key = keys + (name,)
            if target & 0x80000000:
                walk(target & 0x7fffffff, key)
            else:
                leaf = base + target
                start, size = offset(u32(leaf)), u32(leaf + 4)
                result[key] = data[start:start + size]
    walk(0, ())
    return result


def verify(exe):
    source = Path(__file__).resolve().parents[1] / 'src/app.manifest'
    entries = resources(exe)
    manifests = [(k, v) for k, v in entries.items() if k[0] == 24]
    assert len(manifests) == 1, 'exactly one RT_MANIFEST required'
    key, embedded = manifests[0]
    assert key[1] == 1, 'manifest must be resource 1'
    assert embedded == source.read_bytes(), 'embedded resource 1 differs from source XML'
    root = ET.fromstring(embedded)
    levels = root.findall('.//{urn:schemas-microsoft-com:asm.v3}requestedExecutionLevel')
    assert len(levels) == 1 and levels[0].attrib == {'level': 'asInvoker', 'uiAccess': 'false'}
    assert len([e for e in root.iter() if e.tag.endswith('requestedExecutionLevel')]) == 1
    identity = root.find('{urn:schemas-microsoft-com:asm.v1}assemblyIdentity')
    assert identity is not None and identity.get('name') == 'OrangeSpace.Client'
    assert any(k[0] == 3 for k in entries), 'Logo icon missing'
    assert any(k[0] == 14 for k in entries), 'Logo icon group missing'
    print('PASS: exact source XML, RT_MANIFEST 1 only, asInvoker, identity and Logo')
    return entries


if __name__ == '__main__':
    verify(sys.argv[1])
