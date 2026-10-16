#!/usr/bin/env python3
"""Read-only audit of Replay 1.20 loader/map selection prologues.

Parses a PE64 executable on disk: RVA -> raw file offset is done using the PE
section table (RVA is not usually a file offset). Never writes the executable,
loads the DLL, or injects engine hooks. A matching prologue is evidence of a
version match, not a complete decompilation or a proof of correct hook ABI.

Usage: python replay120_binding_audit.py game_dx12_ship_replay.exe --json audit.json
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path

KNOWN_MD5='1c238fe327f2ecc3b0db924c5b425439'
# Anchored against IDARETW/mw120rproxy replay_bindings.h (Replay 1.20.4.7623265).
SIGNATURES={
 'Sys_OpenFileReliable':(0x13F4D50, '48895c2408574883ec408bda488bf9'),
 'ResetReader':(0xD871E0, '40534883ec204c8b81b0000000488bd9'),
 'InitInflator':(0xD88120, '48895c240848896c24104889742418'),
 'Com_GameInfo_LoadMapInfoList':(0x10C7E70,'41554883ec504533ed44892d345a430b'),
 'DB_FindXAssetHeader':(0x11AA890,'48895c2410488974241848897c2420'),
 'DB_LinkXAssetEntry':(0x11AC760,'48895c2418574154415541564157'),
}

@dataclass(frozen=True)
class Section:
    name:str
    rva:int
    virtual_size:int
    raw_offset:int
    raw_size:int
    characteristics:int

class PEFile:
    def __init__(self,data:bytes):
        self.data=data
        if len(data)<0x100 or data[:2]!=b'MZ':raise ValueError('Not a Windows MZ executable')
        pe=struct.unpack_from('<I',data,0x3c)[0]
        if pe+24>len(data) or data[pe:pe+4]!=b'PE\0\0':raise ValueError('Missing PE signature')
        machine,count,timestamp,_,_,optional_size,_=struct.unpack_from('<HHIIIHH',data,pe+4)
        if machine!=0x8664:raise ValueError('Expected a PE64 x86-64 executable')
        optional=pe+24
        if optional+optional_size>len(data) or optional_size<0x70 or struct.unpack_from('<H',data,optional)[0]!=0x20b:
            raise ValueError('Invalid PE32+ optional header')
        self.timestamp=timestamp
        self.entry_rva=struct.unpack_from('<I',data,optional+16)[0]
        self.image_size=struct.unpack_from('<I',data,optional+56)[0]
        self.sections=[]
        pos=optional+optional_size
        if count>96 or pos+40*count>len(data):raise ValueError('Bad PE section count/table')
        for i in range(count):
            off=pos+i*40
            name=data[off:off+8].split(b'\0',1)[0].decode('ascii','replace')
            vs,rva,size,raw=struct.unpack_from('<IIII',data,off+8)
            flags=struct.unpack_from('<I',data,off+36)[0]
            if raw+size>len(data):raise ValueError(f'Section {name} exceeds file')
            self.sections.append(Section(name,rva,vs,raw,size,flags))
    def locate(self,rva:int,size:int):
        if size<=0:return None
        for sec in self.sections:
            if sec.rva<=rva and rva+size<=sec.rva+sec.raw_size:
                return sec.raw_offset+(rva-sec.rva)
        return None
    def find_signature(self,pattern:bytes,limit:int=8):
        candidates=[]
        for sec in self.sections:
            # Only scan code (IMAGE_SCN_MEM_EXECUTE=0x20000000).
            if not (sec.characteristics&0x20000000):continue
            buf=self.data[sec.raw_offset:sec.raw_offset+sec.raw_size]
            offset=0
            while len(candidates)<limit:
                index=buf.find(pattern,offset)
                if index<0:break
                candidates.append({'section':sec.name,'rva':f'0x{sec.rva+index:X}',
                                   'fileOffset':f'0x{sec.raw_offset+index:X}'})
                offset=index+1
        return candidates

def inspect_file(file:Path,bindings=None):
    data=file.read_bytes()
    pe=PEFile(data)
    md5=hashlib.md5(data).hexdigest()
    bindings=bindings or SIGNATURES
    reports=[]
    for name,(rva,hexbytes) in bindings.items():
        expected=bytes.fromhex(hexbytes)
        off=pe.locate(rva,len(expected))
        observed=data[off:off+len(expected)] if off is not None else None
        status='matched' if observed==expected else ('unmapped_rva' if off is None else 'mismatch')
        reports.append({'name':name,'expectedRVA':f'0x{rva:X}',
                        'rawFileOffset':f'0x{off:X}' if off is not None else None,
                        'status':status,'expectedBytes':hexbytes,
                        'observedBytes':observed.hex() if observed is not None else None,
                        'otherExactMatches':[] if status=='matched' else pe.find_signature(expected)})
    return {'file':str(file),'fileBytes':len(data),'md5':md5,'replay120ExactMd5':md5==KNOWN_MD5,
            'timestamp':f'0x{pe.timestamp:X}','entryRVA':f'0x{pe.entry_rva:X}',
            'sizeOfImage':f'0x{pe.image_size:X}',
            'sections':[s.__dict__ for s in pe.sections],
            'bindings':reports,'matchedBindings':sum(x['status']=='matched' for x in reports),
            'totalBindings':len(reports),
            'note':'Function signature match is not a proof of complete engine compatibility; do not hook without ABI and lifecycle verification.'}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('exe',type=Path)
    ap.add_argument('--json',type=Path,help='Save full JSON report')
    args=ap.parse_args()
    try: report=inspect_file(args.exe)
    except (OSError,ValueError,struct.error) as ex:ap.exit(2,f'ERROR: {ex}\n')
    if args.json:args.json.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(f"{args.exe.name}: {report['matchedBindings']}/{report['totalBindings']} exact anchored loader/map signatures")
    print(f"MD5={report['md5']} exactSupportedReplay120={report['replay120ExactMd5']}")
    for row in report['bindings']:
        print(f"  {row['name']:32} {row['expectedRVA']:>12} {row['status']}")
        if row['otherExactMatches']:print('    candidate occurrences:',row['otherExactMatches'])
    return 0 if report['replay120ExactMd5'] and report['matchedBindings']==report['totalBindings'] else 1

if __name__=='__main__':raise SystemExit(main())
