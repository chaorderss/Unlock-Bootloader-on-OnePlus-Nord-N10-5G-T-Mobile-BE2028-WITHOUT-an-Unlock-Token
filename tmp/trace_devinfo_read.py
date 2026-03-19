#!/usr/bin/env python3
"""Disassemble ReadDeviceInfo and trace how it calls ReadWritePartition"""
import struct

with open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb') as f:
    pe = f.read()

def u32(off):
    return struct.unpack('<I', pe[off:off+4])[0]

def disasm_aarch64(addr, word):
    """Simple AArch64 disassembler for key instructions."""
    # BL imm
    if (word >> 26) == 0x25:
        imm = word & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        target = addr + imm * 4
        return f"BL 0x{target:X}"
    # ADRP
    if (word & 0x9F000000) == 0x90000000:
        rd = word & 0x1F
        immhi = (word >> 5) & 0x7FFFF
        immlo = (word >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm -= 0x200000
        page = (addr & ~0xFFF) + (imm << 12)
        return f"ADRP x{rd}, 0x{page:X}"
    # ADD imm
    if (word >> 24) == 0x91:
        rd = word & 0x1F
        rn = (word >> 5) & 0x1F
        imm12 = (word >> 10) & 0xFFF
        sh = (word >> 22) & 1
        if sh:
            imm12 <<= 12
        return f"ADD x{rd}, x{rn}, #0x{imm12:X}"
    # MOV (ORR with xzr)
    if (word & 0xFF000000) == 0xAA000000:
        rd = word & 0x1F
        rm = (word >> 16) & 0x1F
        return f"MOV x{rd}, x{rm}"
    # MOVZ
    if (word & 0xFF800000) == 0xD2800000:
        rd = word & 0x1F
        imm16 = (word >> 5) & 0xFFFF
        hw = (word >> 21) & 3
        return f"MOVZ x{rd}, #0x{imm16:X}, LSL #{hw*16}"
    if (word & 0x7F800000) == 0x52800000:
        rd = word & 0x1F
        imm16 = (word >> 5) & 0xFFFF
        hw = (word >> 21) & 3
        return f"MOVZ w{rd}, #0x{imm16:X}, LSL #{hw*16}"
    # LDR/STR
    if (word & 0x3B200C00) == 0x39000000:
        size = (word >> 30) & 3
        v = (word >> 26) & 1
        opc = (word >> 22) & 3
        imm12 = (word >> 10) & 0xFFF
        rn = (word >> 5) & 0x1F
        rt = word & 0x1F
        scale = size
        offset = imm12 << scale
        op = "LDR" if opc & 1 else "STR"
        sz = ["B","H","W","X"][size]
        return f"{op}{sz} x{rt}/w{rt}, [x{rn}, #0x{offset:X}]"
    # CBZ/CBNZ
    if (word & 0x7E000000) == 0x34000000:
        sf = (word >> 31) & 1
        op = "CBNZ" if (word >> 24) & 1 else "CBZ"
        imm19 = (word >> 5) & 0x7FFFF
        if imm19 & 0x40000:
            imm19 -= 0x80000
        rt = word & 0x1F
        target = addr + imm19 * 4
        reg = f"x{rt}" if sf else f"w{rt}"
        return f"{op} {reg}, 0x{target:X}"
    # STP/LDP
    if (word & 0x7C000000) == 0x28000000:
        opc = (word >> 30) & 3
        op = "STP" if ((word >> 22) & 1) == 0 else "LDP"
        return f"{op} ..."
    # RET
    if word == 0xD65F03C0:
        return "RET"
    # NOP
    if word == 0xD503201F:
        return "NOP"
    return f"?? ({word:08X})"

print("=== ReadDeviceInfo (0x232D8) ===")
for i in range(0, 0x180, 4):
    addr = 0x232D8 + i
    word = u32(addr)
    dis = disasm_aarch64(addr, word)
    print(f"  0x{addr:05X}: {word:08X}  {dis}")
    if "RET" in dis:
        break

print("\n=== ReadWritePartition (0x18248) - first 0x100 bytes ===")
for i in range(0, 0x100, 4):
    addr = 0x18248 + i
    word = u32(addr)
    dis = disasm_aarch64(addr, word)
    print(f"  0x{addr:05X}: {word:08X}  {dis}")

# Check what's at the UCS-2 pointer table 0x0685E0
print("\n=== Pointer table at 0x0685E0 ===")
for i in range(0, 0x80, 8):
    ptr = struct.unpack('<Q', pe[0x685E0+i:0x685E0+i+8])[0]
    if ptr == 0:
        break
    if 0x60000 < ptr < 0x70000:
        s = pe[ptr:ptr+40]
        try:
            ucs2 = s.decode('utf-16-le').split('\x00')[0]
        except:
            ucs2 = s.hex()
        print(f"  0x{0x685E0+i:05X}: -> 0x{ptr:05X} = \"{ucs2}\"")
    else:
        print(f"  0x{0x685E0+i:05X}: -> 0x{ptr:X}")
