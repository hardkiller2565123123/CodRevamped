"""Read-only, bounded PE disassembly; never starts or modifies the game."""
import argparse
import capstone
import pefile

parser = argparse.ArgumentParser()
parser.add_argument("exe")
parser.add_argument("rva", type=lambda value: int(value, 16))
parser.add_argument("--size", type=lambda value: int(value, 16), default=0x200)
args = parser.parse_args()
if not 0 < args.size <= 0x10000:
    parser.error("size must be 1..10000 hex")
pe = pefile.PE(args.exe, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
print(f"base={base:X} timestamp={pe.FILE_HEADER.TimeDateStamp:X}")
dis = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
dis.detail = True
for ins in dis.disasm(pe.get_data(args.rva, args.size), base + args.rva):
    print(f"{ins.address-base:08X} {ins.mnemonic:8} {ins.op_str}")
    for op in ins.operands:
        if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
            target = ins.address + ins.size + op.mem.disp - base
            if 0 <= target < pe.OPTIONAL_HEADER.SizeOfImage:
                raw = pe.get_data(target, 80)
                print(f"    -> RVA {target:08X}: {raw!r}")
pe.close()
