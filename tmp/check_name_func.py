#!/usr/bin/env python3
"""Examine the name construction function at 0x139e10 and string at 0x201130"""
import struct

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

with open('/Users/xmxx/pinganhuijia/tmp/libmir1server.so', 'rb') as f:
    data = f.read()

# Check string at 0x201130
print("=== String at 0x201130 ===")
end = data.find(b'\0', 0x201130)
s = data[0x201130:min(end, 0x201130+200)]
print(repr(s))

# Check strings in range around 0x201130
for off in [0x201100, 0x201110, 0x201120, 0x201130, 0x201140, 0x201150]:
    end = data.find(b'\0', off)
    s = data[off:min(end, off+80)]
    try:
        print(f"  0x{off:06x}: {s.decode('ascii')}")
    except:
        print(f"  0x{off:06x}: <binary> {s[:20].hex()}")

# Dump function 0x139e10 (the name constructor)
print("\n=== Function at 0x139e10 ===")
for off in range(0x139e10, min(len(data), 0x139e10 + 200), 4):
    insn = read_u32(data, off)

    d = ""
    if insn == 0xd65f03c0: d = "RET"
    elif insn == 0xd503201f: d = "NOP"
    elif (insn >> 26) == 0x25:
        imm26 = insn & 0x3ffffff
        if imm26 & 0x2000000: imm26 -= 0x4000000
        d = f"BL 0x{off + imm26*4:x}"
    elif (insn >> 26) == 0x05:
        imm26 = insn & 0x3ffffff
        if imm26 & 0x2000000: imm26 -= 0x4000000
        d = f"B 0x{off + imm26*4:x}"
    elif (insn & 0x9f000000) == 0x90000000:
        rd = insn & 0x1f
        immhi = (insn >> 5) & 0x7ffff
        immlo = (insn >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm & 0x100000: imm -= 0x200000
        page = (off & ~0xfff) + (imm << 12)
        d = f"ADRP X{rd}, 0x{page:x}"
    elif (insn & 0x7f800000) == 0x11000000:
        sf = (insn >> 31) & 1
        sh = (insn >> 22) & 1
        imm12 = (insn >> 10) & 0xfff
        rn = (insn >> 5) & 0x1f
        rd = insn & 0x1f
        if sh: imm12 <<= 12
        rp = "X" if sf else "W"
        rn_s = "SP" if rn == 31 else f"{rp}{rn}"
        rd_s = "SP" if rd == 31 else f"{rp}{rd}"
        d = f"ADD {rd_s}, {rn_s}, #0x{imm12:x}"
    elif (insn & 0xffc00000) == 0xf9000000:
        imm12 = (insn >> 10) & 0xfff
        rn = (insn >> 5) & 0x1f
        rt = insn & 0x1f
        rn_s = "SP" if rn == 31 else f"X{rn}"
        d = f"STR X{rt}, [{rn_s}, #0x{imm12*8:x}]"
    elif (insn & 0xffc00000) == 0xf9400000:
        imm12 = (insn >> 10) & 0xfff
        rn = (insn >> 5) & 0x1f
        rt = insn & 0x1f
        rn_s = "SP" if rn == 31 else f"X{rn}"
        d = f"LDR X{rt}, [{rn_s}, #0x{imm12*8:x}]"
    elif (insn & 0xffc00000) == 0x39000000:
        imm12 = (insn >> 10) & 0xfff
        rn = (insn >> 5) & 0x1f
        rt = insn & 0x1f
        rn_s = "SP" if rn == 31 else f"X{rn}"
        d = f"STRB W{rt}, [{rn_s}, #0x{imm12:x}]"
    elif (insn & 0x7f800000) == 0x52800000:
        hw = (insn >> 21) & 3
        imm16 = (insn >> 5) & 0xffff
        rd = insn & 0x1f
        sf = (insn >> 31) & 1
        rp = "X" if sf else "W"
        val = imm16 << (hw*16)
        d = f"MOV {rp}{rd}, #0x{val:x}"
    elif (insn & 0x7fe0ffe0) == 0x2a0003e0:
        sf = (insn >> 31) & 1
        rm = (insn >> 16) & 0x1f
        rd = insn & 0x1f
        rp = "X" if sf else "W"
        d = f"MOV {rp}{rd}, {rp}{rm}"
    elif (insn & 0xffe0fc00) == 0xaa0003e0:
        rm = (insn >> 16) & 0x1f
        rd = insn & 0x1f
        d = f"MOV X{rd}, X{rm}"
    else:
        d = f"??? 0x{insn:08x}"

    print(f"  0x{off:06x}: {insn:08x}  {d}")
    if d == "RET":
        break

# Also check what open_session looks like at the known addresses
print("\n=== AbstractShell::open_session at 0x17ad60 ===")
for off in range(0x17ad60, min(len(data), 0x17ad60 + 120), 4):
    insn = read_u32(data, off)
    d = ""
    if insn == 0xd65f03c0: d = "RET"
    elif (insn >> 26) == 0x25:
        imm26 = insn & 0x3ffffff
        if imm26 & 0x2000000: imm26 -= 0x4000000
        d = f"BL 0x{off + imm26*4:x}"
    elif (insn & 0xfffffc1f) == 0xd63f0000:
        rn = (insn >> 5) & 0x1f
        d = f"BLR X{rn}"
    elif (insn & 0x9f000000) == 0x90000000:
        rd = insn & 0x1f
        immhi = (insn >> 5) & 0x7ffff
        immlo = (insn >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm & 0x100000: imm -= 0x200000
        page = (off & ~0xfff) + (imm << 12)
        d = f"ADRP X{rd}, 0x{page:x}"
    else:
        d = f"??? 0x{insn:08x}"
    print(f"  0x{off:06x}: {insn:08x}  {d}")
    if d == "RET": break

# Look for the pattern at the BLR X23 destination - what vtable entry is it?
# virtual thunk offsets from the summary:
# AbstractShell::open_session at 0x17ad60 [272 bytes]
# virtual thunk at 0x17ae70
# ShellWrapper::open_session at 0x184f70 [116 bytes]
print("\n=== ShellWrapper::open_session at 0x184f70 ===")
for off in range(0x184f70, min(len(data), 0x184f70 + 120), 4):
    insn = read_u32(data, off)
    d = ""
    if insn == 0xd65f03c0: d = "RET"
    elif (insn >> 26) == 0x25:
        imm26 = insn & 0x3ffffff
        if imm26 & 0x2000000: imm26 -= 0x4000000
        d = f"BL 0x{off + imm26*4:x}"
    elif (insn & 0xfffffc1f) == 0xd63f0000:
        rn = (insn >> 5) & 0x1f
        d = f"BLR X{rn}"
    elif (insn & 0xffe0fc00) == 0xaa0003e0:
        rm = (insn >> 16) & 0x1f
        rd = insn & 0x1f
        d = f"MOV X{rd}, X{rm}"
    elif (insn & 0xffc00000) == 0xf9400000:
        imm12 = (insn >> 10) & 0xfff
        rn = (insn >> 5) & 0x1f
        rt = insn & 0x1f
        rn_s = "SP" if rn == 31 else f"X{rn}"
        d = f"LDR X{rt}, [{rn_s}, #0x{imm12*8:x}]"
    else:
        d = f"??? 0x{insn:08x}"
    print(f"  0x{off:06x}: {insn:08x}  {d}")
    if d == "RET": break
