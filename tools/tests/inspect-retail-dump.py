"""Read-only, bounded code/string references from the user's mapped retail PE dump."""
import argparse
import re
import struct
import capstone
import pefile

p = argparse.ArgumentParser()
p.add_argument('dump')
p.add_argument('--string')
p.add_argument('--rva', type=lambda x: int(x, 0))
p.add_argument('--size', type=lambda x: int(x, 0), default=256)
p.add_argument('--follow-jumps', action='store_true')
p.add_argument('--calls', type=lambda x: int(x, 0), help='Find direct CALL references to an RVA')
a = p.parse_args()
pe = pefile.PE(a.dump, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
d = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
d.detail = True

def show(rva):
    seen = set()
    remaining = min(a.size, 4096)
    while remaining > 0 and rva not in seen:
        seen.add(rva)
        ins = next(d.disasm(pe.get_data(rva, 15), rva), None)
        if ins is None:
            break
        label = ''
        for op in ins.operands:
            if op.type == capstone.CS_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                target = ins.address + ins.size + op.mem.disp
            elif op.type == capstone.CS_OP_IMM and base <= op.imm < base + pe.OPTIONAL_HEADER.SizeOfImage:
                target = op.imm - base
            else:
                continue
            raw = pe.get_data(target, 160).split(b'\0')[0]
            if raw and all(32 <= c < 127 for c in raw):
                label = ' ; ' + repr(raw.decode())
        print(f'{ins.address:08X} {ins.mnemonic} {ins.op_str}{label}')
        remaining -= ins.size
        rva += ins.size
        if a.follow_jumps:
            if ins.mnemonic == 'jmp':
                if ins.operands[0].type != capstone.CS_OP_IMM:
                    break
                rva = ins.operands[0].imm
            elif ins.mnemonic in ('ret', 'int3'):
                break

if a.rva is not None:
    show(a.rva)
if a.calls is not None:
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        data = section.get_data()
        for match in re.finditer(b'\xe8', data):
            offset = match.start()
            if offset + 5 > len(data):
                continue
            rva = section.VirtualAddress + offset
            if rva + 5 + struct.unpack_from('<i', data, offset+1)[0] == a.calls:
                print('CALL XREF', hex(rva))
                show(rva)
if a.string:
    needle = a.string.encode() + b'\0'
    targets = set()
    for m in re.finditer(re.escape(needle), pe.__data__):
        targets.add(pe.get_rva_from_offset(m.start()))
    print('String RVAs:', [hex(x) for x in sorted(targets)])
    for s in pe.sections:
        if not s.Characteristics & 0x20000000:
            continue
        data = s.get_data()
        for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', data):
            i = m.start()
            if i + 7 > len(data):
                continue
            rva = s.VirtualAddress + i
            if rva + 7 + struct.unpack_from('<i', data, i+3)[0] in targets:
                print('RIP XREF', hex(rva))
                show(rva)
        for target in sorted(targets):
            for m in re.finditer(re.escape(struct.pack('<Q', base+target)), data):
                rva = s.VirtualAddress + m.start() - 2
                print('Absolute candidate', hex(rva))
                show(rva)
