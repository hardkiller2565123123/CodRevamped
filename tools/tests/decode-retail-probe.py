"""Disassemble bounded code-only captures; annotate static RIP-relative strings."""
import argparse
import capstone
import pefile
import sys
from contextlib import nullcontext

p=argparse.ArgumentParser()
p.add_argument('log')
p.add_argument('exe')
p.add_argument('--field', default='title-data-error')
a=p.parse_args()
pe=pefile.PE(a.exe, fast_load=True)
d=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
d.detail=True
active=False
with (nullcontext(sys.stdin) if a.log == '-' else open(a.log)) as f:
    for line in f:
        if line.startswith('XREF'):
            active=f'field={a.field} ' in line
        if not active:
            continue
        if not line.startswith('CODE'):
            print(line.strip())
            continue
        head,hexbytes=line.strip().split(' bytes=')
        rva=int(head.split('rva=')[1],16)
        for i in d.disasm(bytes.fromhex(hexbytes),rva):
            annotation=''
            for op in i.operands:
                if op.type==capstone.CS_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:
                    target=i.address+i.size+op.mem.disp
                    try:
                        raw=pe.get_data(target,100).split(b'\0')[0]
                        if raw and all(32<=c<127 for c in raw): annotation=' ; '+repr(raw.decode())
                    except pefile.PEFormatError:
                        pass
            print(f'{i.address:#x} {i.mnemonic} {i.op_str}{annotation}')
