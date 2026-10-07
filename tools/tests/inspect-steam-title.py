"""Read-only PE string references for the exact Steam retail login parser."""
import argparse
import re
import pefile
import capstone
import ctypes as C

p = argparse.ArgumentParser()
p.add_argument('exe')
p.add_argument('--rva', type=lambda s: int(s, 0))
p.add_argument('--pid', type=int)
p.add_argument('--length', type=lambda s: int(s, 0), default=256)
a = p.parse_args()
pe = pefile.PE(a.exe, fast_load=True)
assert (pe.FILE_HEADER.TimeDateStamp, pe.OPTIONAL_HEADER.SizeOfImage,
        pe.OPTIONAL_HEADER.AddressOfEntryPoint) == (0x69DD404E, 0x21679200, 0x06E4931C)
d = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
handle = None
if a.pid:
    k = C.WinDLL('kernel32', use_last_error=True)
    k.OpenProcess.restype = C.c_void_p
    k.ReadProcessMemory.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]
    k.K32EnumProcessModules.argtypes = [C.c_void_p, C.c_void_p, C.c_uint32, C.c_void_p]
    handle = k.OpenProcess(0x410, False, a.pid)
    if not handle:
        raise C.WinError(C.get_last_error())
    modules = (C.c_void_p * 1024)()
    needed = C.c_uint32()
    if not k.K32EnumProcessModules(handle, modules, C.sizeof(modules), C.byref(needed)):
        raise C.WinError(C.get_last_error())
    base = modules[0]
    print(f'Live base={base:#x}', flush=True)

def read(rva, length):
    if not handle:
        return pe.get_data(rva, length)
    data = bytearray(length)
    for offset in range(0, length, 0x1000):
        take = min(0x1000, length-offset)
        buf = C.create_string_buffer(take)
        got = C.c_size_t()
        if k.ReadProcessMemory(handle, base+rva+offset, buf, take, C.byref(got)):
            data[offset:offset+got.value] = buf.raw[:got.value]
    return bytes(data)

if handle:
    live = pefile.PE(data=read(0,4096), fast_load=True)
    assert (live.FILE_HEADER.TimeDateStamp, live.OPTIONAL_HEADER.SizeOfImage,
            live.OPTIONAL_HEADER.AddressOfEntryPoint) == (0x69DD404E, 0x21679200, 0x06E4931C)
if a.rva is not None:
    for ins in d.disasm(read(a.rva, a.length), a.rva):
        print(f'{ins.address:#x} {ins.mnemonic} {ins.op_str}')
else:
    targets = {}
    for term in (b'Failed to load title data from login service response.', b'title',
                 b'titleID', b'titleId', b'titleData', b'clientTicket', b'serverTicket'):
        start = 0
        while True:
            off = pe.__data__.find(term + b'\0', start)
            if off < 0:
                break
            if not off or pe.__data__[off - 1] == 0:
                targets[pe.get_rva_from_offset(off)] = term.decode()
            start = off + len(term) + 1
    print('Strings:', targets)
    for s in pe.sections:
        if not s.Characteristics & 0x20000000:
            continue
        data = read(s.VirtualAddress, s.Misc_VirtualSize) if handle else s.get_data()
        for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', data):
            off = m.start()
            if off + 7 > len(data):
                continue
            rva = s.VirtualAddress + off
            target = rva + 7 + int.from_bytes(data[off+3:off+7], 'little', signed=True)
            if target not in targets:
                continue
            print(f'{targets[target]} xref={rva:#x}')
            for ins in d.disasm(data[off:off+48], rva):
                print(f'  {ins.address:#x} {ins.mnemonic} {ins.op_str}')
                if ins.mnemonic in ('ret', 'jmp'):
                    break
