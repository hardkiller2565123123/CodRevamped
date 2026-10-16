"""Self-contained PE fixture regression tests: python3 test_reverse_lab.py <built CLI>.
Fixtures are synthetic and contain no game code."""
import json
import pathlib
import struct
import subprocess
import sys
import tempfile


def pe(path, string_marker):
    b = bytearray(0x1000)
    def u16(off, v): struct.pack_into('<H', b, off, v)
    def u32(off, v): struct.pack_into('<I', b, off, v)
    def u64(off, v): struct.pack_into('<Q', b, off, v)
    def text(off, s): b[off:off + len(s) + 1] = s.encode('ascii') + b'\0'
    def raw(rva): return rva - 0x1000 + 0x400
    u16(0, 0x5a4d); u32(0x3c, 0x80)
    b[0x80:0x84] = b'PE\0\0'
    coff = 0x84
    u16(coff, 0x8664);u16(coff + 2, 1);u32(coff + 4, 0x5E9BAF80)
    u16(coff + 16, 0xF0)
    opt = coff + 20
    u16(opt, 0x20b);u32(opt+16, 0x1010);u64(opt+24, 0x140000000)
    u32(opt+56, 0x2000);u32(opt+60, 0x400);u32(opt+108, 16)
    u32(opt+112, 0x1020);u32(opt+116, 40) # export
    u32(opt+120, 0x1120);u32(opt+124, 40) # imports
    sec=opt+0xf0
    b[sec:sec+8]=b'.rdata\0\0'
    u32(sec+8, 0xc00);u32(sec+12, 0x1000)
    u32(sec+16, 0xc00);u32(sec+20, 0x400);u32(sec+36, 0x60000040)  # executable fixture section
    # export directory with 1 name and 1 function
    ex=raw(0x1020)
    u32(ex+20,1);u32(ex+24,1)
    u32(ex+28,0x10A0);u32(ex+32,0x10B0);u32(ex+36,0x10C0)
    u32(raw(0x10A0),0x1010);u32(raw(0x10B0),0x10D0)
    u16(raw(0x10C0),0);text(raw(0x10D0), 'NativeFixture')
    # import descriptor with one kernel32 named import
    imp=raw(0x1120)
    u32(imp,0x1160);u32(imp+12,0x11A0);u32(imp+16,0x1180)
    u64(raw(0x1160),0x11C0);u64(raw(0x1180),0x11C0)
    text(raw(0x11A0),'KERNEL32.dll');text(raw(0x11C0)+2,'GetProcAddress')
    text(raw(0x1300),string_marker)
    # Synthetic x64 LEA RCX,[RIP+disp32], pointing to the anchored text.
    b[raw(0x1400):raw(0x1400)+3] = bytes((0x48,0x8d,0x0d))
    struct.pack_into('<i',b,raw(0x1400)+3,0x1300-(0x1400+7))
    path.write_bytes(b)


def main(binary):
    with tempfile.TemporaryDirectory() as root:
        root=pathlib.Path(root)
        a=root/'old.dll';b=root/'new.dll';report=root/'report.json'
        pe(a,'DB_LoadXAssets');pe(b,'GfxWorld')
        subprocess.run([binary,'scan',str(a),str(report)],check=True,capture_output=True)
        data=json.loads(report.read_text())['image']
        assert data['format']=='PE32+' and data['timestamp']==0x5e9baf80
        assert data['entryRva']==0x1010
        assert data['imports']['KERNEL32.dll']==['GetProcAddress']
        assert data['exports'][0]['name']=='NativeFixture'
        assert {'name':'DB_LoadXAssets','rva':0x1300,'fileOffset':raw(0x1300)}.items() <= data['stringAnchors'][0].items()
        assert any(x['instructionRva']==0x1400 and x['targetRva']==0x1300 for x in data['candidateRipReferences'])
        subprocess.run([binary,'compare',str(a),str(b),str(report)],check=True,capture_output=True)
        diff=json.loads(report.read_text())
        assert diff['mode']=='compare'
        anchors={v['string']:(v['oldCount'],v['newCount']) for v in diff['anchorCountChanges']}
        assert anchors['DB_LoadXAssets']==(1,0) and anchors['GfxWorld']==(0,1)
        assert not diff['importChanges']['onlyOld'] and not diff['importChanges']['onlyNew']
        bad=root/'bad.dll';bad.write_bytes(b'MZ')
        assert subprocess.run([binary,'scan',str(bad),str(report)],capture_output=True).returncode != 0
        assert subprocess.run([binary,'scan',str(a),str(a)],capture_output=True).returncode != 0
        print('IW8ReverseLab synthetic PE scan/compare/error tests: PASS')


def raw(rva): return rva-0x1000+0x400


if __name__=='__main__':
    main(sys.argv[1])
