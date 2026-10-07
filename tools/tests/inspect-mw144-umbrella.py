"""Read-only, exact-build Umbrella string xref inspection; never writes process memory."""
import argparse
import ctypes as C
import re

import capstone
import pefile

parser = argparse.ArgumentParser()
parser.add_argument("exe")
parser.add_argument("pid", type=int)
parser.add_argument("base", type=lambda value: int(value, 0))
args = parser.parse_args()
pe = pefile.PE(args.exe, fast_load=True)
assert (pe.FILE_HEADER.TimeDateStamp, pe.OPTIONAL_HEADER.SizeOfImage,
        pe.OPTIONAL_HEADER.AddressOfEntryPoint) == (0x61671CE8, 0x22C1BA00, 0x06D429F8)
k = C.WinDLL("kernel32", use_last_error=True)
k.OpenProcess.argtypes = [C.c_uint32, C.c_int, C.c_uint32]
k.OpenProcess.restype = C.c_void_p
k.ReadProcessMemory.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p, C.c_size_t,
                               C.POINTER(C.c_size_t)]
k.CloseHandle.argtypes = [C.c_void_p]
handle = k.OpenProcess(0x410, False, args.pid)
if not handle:
    raise C.WinError(C.get_last_error())

def read(rva, length):
    buffer = C.create_string_buffer(length)
    count = C.c_size_t()
    if not k.ReadProcessMemory(handle, args.base + rva, buffer, length, C.byref(count)):
        raise C.WinError(C.get_last_error())
    return buffer.raw[:count.value]

try:
    # Confirm the opened process is the same build as the file, not just a stale PID.
    header = pefile.PE(data=read(0, 4096), fast_load=True)
    assert (header.FILE_HEADER.TimeDateStamp, header.OPTIONAL_HEADER.SizeOfImage,
            header.OPTIONAL_HEADER.AddressOfEntryPoint) == (0x61671CE8, 0x22C1BA00, 0x06D429F8)
    keys = [b"token", b"lsgEndpoint", b"crossPlatformProgressionEnabled",
            b"umbrellaID", b"accessToken", b"expires", b"accounts"]
    targets = {}
    for key in keys:
        start = 0
        while True:
            offset = pe.__data__.find(key + b"\0", start)
            if offset < 0:
                break
            # Exclude suffixes of other identifiers.
            if offset == 0 or pe.__data__[offset - 1] == 0:
                targets[pe.get_rva_from_offset(offset)] = key.decode()
            start = offset + len(key) + 1
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        data = read(section.VirtualAddress, section.Misc_VirtualSize)
        # x64 RIP-relative LEA; validate target against exact string addresses.
        for match in re.finditer(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", data):
            offset = match.start()
            if offset + 7 > len(data):
                continue
            rva = section.VirtualAddress + offset
            target = rva + 7 + int.from_bytes(data[offset + 3:offset + 7], "little", signed=True)
            if target not in targets:
                continue
            print(f"FIELD={targets[target]} stringRva={target:#x} xrefRva={rva:#x}")
            for ins in decoder.disasm(data[offset:offset + 96], rva):
                print(f"  {ins.address:#x} {ins.mnemonic} {ins.op_str}")
                if ins.mnemonic in ("jmp", "ret"):
                    break
finally:
    k.CloseHandle(handle)
