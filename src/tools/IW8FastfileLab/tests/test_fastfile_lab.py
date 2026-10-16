"""Portable synthetic IW8 container tests. They do not establish game compatibility."""
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

EXE = Path(sys.argv[1]) if len(sys.argv)>1 else Path(__file__).parents[4] / 'i8fftest'

def fixture(path, *, version=4087, compression=0, magic=b'IWffc100', broken=False):
    raw = b'\x00' * 16 + struct.pack('<I', 2) + b'\x00' * 12 + b'CODREVAMPED-TEST\0' * 7
    header = bytearray(0x88)
    header[:8]=magic
    struct.pack_into('<II',header,8,11,version)
    header[0x10]=compression
    struct.pack_into('<I',header,0x14,len(raw)+4 if compression==0 else len(raw)+20)
    struct.pack_into('<Q',header,0x20,len(raw))
    struct.pack_into('<Q',header,0x30,len(raw))
    if compression==0:
        frame=b'\x01IWC'+raw
    else:
        frame=b'IWffs100'+b'\0'*12+raw
    if broken:header[0x14]=0
    path.write_bytes(header+frame)
    return raw

def run(*args, ok=True):
    p=subprocess.run([str(EXE.resolve()), *map(str,args)],capture_output=True,text=True)
    assert (p.returncode==0)==ok, (p.returncode,p.stdout,p.stderr)
    return p

with tempfile.TemporaryDirectory() as temp:
    root=Path(temp)
    ff=root/'1_20.ff';raw=fixture(ff)
    r=json.loads(run('inspect',ff).stdout)
    assert r['xfileVersion']==4087 and r['canExtractStoredBody'] and not r['assetSchemaDecoded']
    assert r['hasPlausibleXAssetListRoot'] and r['assetCountCandidate']==2
    extracted=root/'extracted'
    run('extract-stored',ff,extracted)
    assert (extracted/'zone.raw').read_bytes()==raw
    assert (extracted/'header_prefix.bin').stat().st_size==0x8C
    rebuilt=root/'rebuilt.ff'
    run('rebuild-stored',extracted,rebuilt)
    assert rebuilt.read_bytes()==ff.read_bytes(), 'extract/rebuild must be byte-exact'
    run('rebuild-stored',extracted,rebuilt,ok=False) # no overwrite
    newer=root/'newer.ff';fixture(newer,version=4090)
    comparison=json.loads(run('compare',ff,newer).stdout)
    assert not comparison['sameXFileVersion']
    assert comparison['sameCompressionByte']
    assert comparison['compatibleByHeaderAlone'] is False
    r=json.loads(run('inspect',newer).stdout)
    assert r['canExtractStoredBody'] and not r['replay120XFile']
    run('extract-stored',newer,root/'newer-stored')
    run('rebuild-stored',root/'newer-stored',root/'bad-repack.ff',ok=False)
    signed=root/'signed.ff';fixture(signed,compression=1,magic=b'IWffa100')
    r=json.loads(run('inspect',signed).stdout)
    assert r['requiresExternalOodleDecode'] and not r['canExtractStoredBody']
    run('extract-stored',signed,root/'not-output',ok=False)
    assert not (root/'not-output').exists()
    damaged=root/'damaged.ff';fixture(damaged,broken=True)
    r=json.loads(run('inspect',damaged).stdout)
    assert not r['canExtractStoredBody']
    run('extract-stored',damaged,root/'not-output',ok=False)
    (extracted/'zone.raw').write_bytes(raw + b'\0')
    run('rebuild-stored',extracted,root/'tampered.ff',ok=False)
    assert not (root/'tampered.ff').exists()
    report=root/'report.json';run('inspect',ff,report)
    assert json.loads(report.read_text())['magic']=='IWffc100'
    run('inspect',ff,report,ok=False)
print('IW8FastfileLab: 13 checks passed')
