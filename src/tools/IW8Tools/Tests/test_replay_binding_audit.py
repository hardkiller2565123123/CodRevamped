"""PE section/RVA mapping and signature discovery on an invented PE fixture."""
from pathlib import Path
import importlib.util
import struct
import tempfile
root=Path(__file__).resolve().parents[4]
p=root/'src/tools/IW8Tools/Utilities/replay120_binding_audit.py'
spec=importlib.util.spec_from_file_location('replayaudit',p)
import sys
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
d=bytearray(0x1000)
d[0:2]=b'MZ';struct.pack_into('<I',d,0x3c,0x80)
d[0x80:0x84]=b'PE\0\0'
struct.pack_into('<HHIIIHH',d,0x84,0x8664,1,0x5E9BAF80,0,0,0xF0,0)
o=0x98;struct.pack_into('<H',d,o,0x20b)
struct.pack_into('<I',d,o+16,0x1010);struct.pack_into('<I',d,o+56,0x5000)
sec=o+0xF0;d[sec:sec+5]=b'.text'
struct.pack_into('<IIII',d,sec+8,0x200,0x1000,0x200,0x400)
struct.pack_into('<I',d,sec+36,0x60000020)
d[0x420:0x427]=b'EXAMPLE';d[0x500:0x507]=b'EXAMPLE'
pe=m.PEFile(bytes(d))
assert pe.locate(0x1020,7)==0x420
assert pe.locate(0x1020,500) is None
assert [x['rva'] for x in pe.find_signature(b'EXAMPLE')]==['0x1020','0x1100']
with tempfile.TemporaryDirectory() as tmp:
    file=Path(tmp)/'test.exe';file.write_bytes(d)
    result=m.inspect_file(file, {'Example':(0x1020,b'EXAMPLE'.hex()),'Mismatch':(0x1030,b'EXAMPLE'.hex())})
    assert result['matchedBindings']==1
    assert result['bindings'][1]['otherExactMatches'][0]['rva']=='0x1020'
print('Replay PE loader binding audit: PASS')
