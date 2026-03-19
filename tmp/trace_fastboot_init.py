#!/usr/bin/env python3
"""
追踪:
1. 0x46AA0 (fastboot init) - 可能在初始化中重置 devinfo
2. 0x47D24 (IsSecureBootEnabled 调用者, 在 fastboot 代码区域)
3. 0x1DA3C/0x1DA50 (IsSecureBootEnabled 调用者)
4. 0x389B0 (从 0x34E50 调用, 在 OemCheckResetDevInfo 前)
5. 0x36938 (从 0x34E50 调用)
6. 搜索 0x1D2E8 作为函数指针
"""
import struct

PE = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
with open(PE, "rb") as f:
    pe = f.read()

def decode(off, inst):
    s = f"0x{off:05X}: 0x{inst:08X}"
    if inst == 0xD65F03C0: return s + "  ret"
    if inst == 0x00000000: return s + "  nop"
    if (inst >> 26) == 0x25:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        return s + f"  bl 0x{(off + (imm << 2)) & 0xFFFFFFFF:05X}"
    if (inst >> 26) == 0x05:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        return s + f"  b 0x{(off + (imm << 2)) & 0xFFFFFFFF:05X}"
    if (inst & 0x9F000000) == 0x90000000:
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF; immlo = (inst >> 29) & 0x3
        iv = (immhi << 2) | immlo
        if iv & 0x100000: iv |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
        return s + f"  adrp x{rd}, 0x{pg:X}"
    if (inst & 0xFF800000) == 0x91000000:
        rd = inst & 0x1F; rn = (inst >> 5) & 0x1F; i12 = (inst >> 10) & 0xFFF
        return s + f"  add x{rd}, x{rn}, #0x{i12:X}"
    if (inst & 0xFF800000) == 0xD1000000:
        rd = inst & 0x1F; rn = (inst >> 5) & 0x1F; i12 = (inst >> 10) & 0xFFF
        return s + f"  sub x{rd}, x{rn}, #0x{i12:X}"
    if (inst & 0xFFC00000) == 0x39000000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; i = (inst >> 10) & 0xFFF
        return s + f"  strb w{rt}, [x{rn}, #{i}]"
    if (inst & 0xFFC00000) == 0x39400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; i = (inst >> 10) & 0xFFF
        return s + f"  ldrb w{rt}, [x{rn}, #{i}]"
    if (inst & 0xFFC00000) == 0xF9400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; i = ((inst >> 10) & 0xFFF) * 8
        return s + f"  ldr x{rt}, [x{rn}, #{i}]"
    if (inst & 0xFFC00000) == 0xF9000000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; i = ((inst >> 10) & 0xFFF) * 8
        return s + f"  str x{rt}, [x{rn}, #{i}]"
    if (inst & 0xFFC00000) == 0xB9400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; i = ((inst >> 10) & 0xFFF) * 4
        return s + f"  ldr w{rt}, [x{rn}, #{i}]"
    if (inst & 0xFF000000) == 0x54000000:
        imm19 = (inst >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x7FFFF
        t = off + (imm19 << 2)
        c = inst & 0xF
        cn = {0:'EQ',1:'NE',2:'CS',3:'CC',4:'MI',5:'PL',6:'VS',7:'VC',8:'HI',9:'LS',10:'GE',11:'LT',12:'GT',13:'LE',14:'AL'}
        return s + f"  b.{cn.get(c,'?')} 0x{t & 0xFFFFFFFF:05X}"
    for pfx, mn in [(0xB4,'cbz x'),(0xB5,'cbnz x'),(0x34,'cbz w'),(0x35,'cbnz w')]:
        if inst >> 24 == pfx:
            rt = inst & 0x1F; imm19 = (inst >> 5) & 0x7FFFF
            if imm19 & 0x40000: imm19 |= ~0x7FFFF
            return s + f"  {mn}{rt}, 0x{(off + (imm19 << 2)) & 0xFFFFFFFF:05X}"
    if (inst & 0x7E000000) == 0x36000000:
        b5 = (inst >> 31) & 1; op = (inst >> 24) & 1
        b40 = (inst >> 19) & 0x1F; bp = (b5 << 5) | b40
        imm14 = (inst >> 5) & 0x3FFF
        if imm14 & 0x2000: imm14 |= ~0x3FFF
        mn = "tbnz" if op else "tbz"
        return s + f"  {mn} w{inst&0x1F}, #{bp}, 0x{(off + (imm14 << 2)) & 0xFFFFFFFF:05X}"
    if (inst & 0xFF800000) == 0x52800000:
        rd = inst & 0x1F; i = (inst >> 5) & 0xFFFF
        return s + f"  mov w{rd}, #{i}"
    if (inst & 0xFFE0FFE0) == 0xAA0003E0:
        rd = inst & 0x1F; rm = (inst >> 16) & 0x1F
        return s + f"  mov x{rd}, x{rm}"
    if (inst & 0xFFE0FFE0) == 0x2A0003E0:
        rd = inst & 0x1F; rm = (inst >> 16) & 0x1F
        return s + f"  mov w{rd}, w{rm}"
    if (inst & 0xFFC0001F) == 0x7100001F:
        rn = (inst >> 5) & 0x1F; i = (inst >> 10) & 0xFFF
        return s + f"  cmp w{rn}, #{i}"
    if (inst & 0xFFFFFC00) == 0xD63F0000:
        rn = (inst >> 5) & 0x1F
        return s + f"  blr x{rn}"
    return s

def disasm(start, end, label):
    print(f"\n{'='*70}")
    print(f"=== {label} ===")
    print(f"{'='*70}")
    for off in range(start, end, 4):
        if off >= len(pe): break
        inst = struct.unpack_from("<I", pe, off)[0]
        line = decode(off, inst)
        if "bl 0x22C18" in line: line += "  ← IsDeviceUnlocked!"
        if "bl 0x22DB8" in line: line += "  ← SetDeviceUnlocked!"
        if "bl 0x384D0" in line: line += "  ← init_defaults!"
        if "bl 0x384B0" in line: line += "  ← SetIsUnlocked!"
        if "bl 0x189E0" in line: line += "  ← IsSecureBootEnabled!"
        if "bl 0x22CA8" in line: line += "  ← WriteDeviceInfo!"
        if "bl 0x232D8" in line: line += "  ← ReadDeviceInfo!"
        if "bl 0x18248" in line: line += "  ← ReadWritePartition!"
        print(line)
        if inst == 0xD65F03C0 and off > start + 8:
            break

# 1. 0x46AA0 fastboot init (first 200 instructions)
disasm(0x46AA0, 0x46E00, "0x46AA0 — fastboot init")

# 2. 0x47D24 context (IsSecureBootEnabled caller in fastboot area)
disasm(0x47C80, 0x47E00, "0x47D24 context — IsSecureBootEnabled in fastboot code")

# 3. 0x1DA00-0x1DA80 (IsSecureBootEnabled callers in unlock area)
disasm(0x1D9C0, 0x1DAC0, "0x1DA3C/0x1DA50 — IsSecureBootEnabled in unlock code")

# 4. 0x389B0 (called from 0x34E50 param processing)
disasm(0x389B0, 0x38A80, "0x389B0 — called from 0x34E50")

# 5. 0x36938 (called from 0x34E50)
disasm(0x36938, 0x36A40, "0x36938 — called from 0x34E50")

# 6. Search for 0x1D2E8 as function pointer in data
print(f"\n{'='*70}")
print("=== 搜索 0x1D2E8 作为函数指针 ===")
print(f"{'='*70}")
target_bytes = struct.pack("<Q", 0x1D2E8)  # 64-bit LE
for off in range(0x60000, len(pe) - 8, 8):  # search data sections
    if pe[off:off+8] == target_bytes:
        print(f"  Found 0x1D2E8 at offset 0x{off:05X}")
# Also search 32-bit
target_bytes32 = struct.pack("<I", 0x1D2E8)
for off in range(0x60000, len(pe) - 4, 4):
    if pe[off:off+4] == target_bytes32:
        print(f"  Found 0x1D2E8 (32-bit) at offset 0x{off:05X}")

# 7. Search for 0x477F4 and 0x48488 callers (fastboot variable registration)
print(f"\n{'='*70}")
print("=== 搜索 BL 0x477F4 / 0x48400 / 0x46AA0 调用者 ===")
print(f"{'='*70}")
for target in [0x477F4, 0x48400, 0x46AA0]:
    for off in range(0, 0x6A000, 4):
        inst = struct.unpack_from("<I", pe, off)[0]
        if (inst >> 26) == 0x25:
            imm = inst & 0x3FFFFFF
            if imm & 0x2000000: imm |= ~0x3FFFFFF
            t = off + (imm << 2)
            if (t & 0xFFFFFFFF) == target:
                print(f"  BL at 0x{off:05X} → 0x{target:05X}")
