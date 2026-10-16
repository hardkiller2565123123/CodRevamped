"""Synthetic five-zone package validation exercises the stricter stored framing gate."""
import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory

PACK = Path(sys.argv[1]).resolve()
MAP = 'mp_crtest'
FILES = [f'{MAP}.ff', f'srv_{MAP}.ff', f'eng_{MAP}.ff', f'ww_{MAP}.ff', f'techsets_{MAP}.ff']

def zone(target):
    raw=bytes(range(96))
    h=bytearray(0x88)
    h[:8]=b'IWffc100'
    struct.pack_into('<II',h,8,11,4087)
    struct.pack_into('<I',h,0x14,len(raw)+4)
    struct.pack_into('<Q',h,0x20,len(raw))
    struct.pack_into('<Q',h,0x30,len(raw))
    target.write_bytes(h+b'\x01IWC'+raw)

def validate(folder,ok):
    p=subprocess.run([str(PACK),'validate',str(folder),MAP],text=True,capture_output=True)
    assert (p.returncode==0)==ok, (p.stdout,p.stderr)

with TemporaryDirectory() as d:
    root=Path(d)
    for name in FILES:zone(root/name)
    (root/'map.json').write_text(json.dumps({'id':MAP,'title':'Test map'}))
    validate(root,True)
    # A valid-looking header with a damaged body-length contract must fail.
    target=root/FILES[0]
    original=target.read_bytes()
    target.write_bytes(original[:-5])
    validate(root,False)
    target.write_bytes(original)
    broken=bytearray(original);broken[16]=1
    target.write_bytes(broken)
    validate(root,False)
    target.write_bytes(original)
    broken=bytearray(original);broken[0x88:0x8C]=b'abcd'
    target.write_bytes(broken)
    validate(root,False)
    target.write_bytes(original)
    validate(root,True)
print('IW8MapPack stored-frame validation: PASS (5 assertions)')
