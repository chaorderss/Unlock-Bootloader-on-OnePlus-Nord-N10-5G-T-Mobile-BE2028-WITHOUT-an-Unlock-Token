#!/usr/bin/env python3
"""
修正搜索: 找到所有 STRB Wt, [Xn, #13] 指令
以及 ReadDeviceInfo 真正入口和调用者
"""
import struct

PE = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
with open(PE, "rb") as f:
    pe = f.read()

CODE_END = 0x6A000

# ============================================================
# 1. 修正: STRB Wt, [Xn, #13] 正确搜索
# ============================================================
print("=" * 70)
print("=== 1. 所有 STRB Wt, [Xn, #13] 指令 ===")
print("=" * 70)
# STRB encoding: 0x39000000 | (imm12 << 10) | (Rn << 5) | Rt
# imm12=13: 0x39000000 | (13 << 10) = 0x39003400
# Mask: bits[31:10] must match = 0xFFFFFC00
for off in range(0, CODE_END, 4):
    inst = struct.unpack_from("<I", pe, off)[0]
    if (inst & 0xFFFFFC00) == 0x39003400:
        rt = inst & 0x1F
        rn = (inst >> 5) & 0x1F
        print(f"  0x{off:05X}: STRB w{rt}, [x{rn}, #13]  (0x{inst:08X})")

# ============================================================
# 2. ReadDeviceInfo 真正入口 = 0x232D8
# ============================================================
print("\n" + "=" * 70)
print("=== 2. BL 0x232D8 调用者 ===")
print("=" * 70)
for off in range(0, CODE_END, 4):
    inst = struct.unpack_from("<I", pe, off)[0]
    if (inst >> 26) == 0x25:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        target = off + (imm << 2)
        if (target & 0xFFFFFFFF) == 0x232D8:
            print(f"  BL at 0x{off:05X} → 0x232D8")

# ============================================================
# 3. SetDeviceUnlocked (0x22DB8) 调用者
# ============================================================
print("\n" + "=" * 70)
print("=== 3. BL 0x22DB8 (SetDeviceUnlocked) 调用者 ===")
print("=" * 70)
for off in range(0, CODE_END, 4):
    inst = struct.unpack_from("<I", pe, off)[0]
    if (inst >> 26) == 0x25:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        target = off + (imm << 2)
        if (target & 0xFFFFFFFF) == 0x22DB8:
            print(f"  BL at 0x{off:05X} → 0x22DB8")

# ============================================================
# 4. SetIsUnlocked (0x384B0) 调用者
# ============================================================
print("\n" + "=" * 70)
print("=== 4. BL 0x384B0 (SetIsUnlocked) 调用者 ===")
print("=" * 70)
for off in range(0, CODE_END, 4):
    inst = struct.unpack_from("<I", pe, off)[0]
    if (inst >> 26) == 0x25:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        target = off + (imm << 2)
        if (target & 0xFFFFFFFF) == 0x384B0:
            print(f"  BL at 0x{off:05X} → 0x384B0")

# ============================================================
# 5. init_defaults (0x384D0) 调用者 (确认)
# ============================================================
print("\n" + "=" * 70)
print("=== 5. BL 0x384D0 (init_defaults) 调用者 ===")
print("=" * 70)
for off in range(0, CODE_END, 4):
    inst = struct.unpack_from("<I", pe, off)[0]
    if (inst >> 26) == 0x25:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        target = off + (imm << 2)
        if (target & 0xFFFFFFFF) == 0x384D0:
            print(f"  BL at 0x{off:05X} → 0x384D0")

# ============================================================
# 6. 反汇编 ReadDeviceInfo 函数 0x232D8-0x233A8
# ============================================================
print("\n" + "=" * 70)
print("=== 6. ReadDeviceInfo 0x232D8 完整反汇编 ===")
print("=" * 70)

def decode_inst(off, inst):
    s = f"  0x{off:05X}: 0x{inst:08X}"
    if inst == 0xD65F03C0:
        return s + "  ret"
    if (inst >> 26) == 0x25:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        target = off + (imm << 2)
        return s + f"  bl 0x{target & 0xFFFFFFFF:05X}"
    if (inst >> 26) == 0x05:  # B
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        target = off + (imm << 2)
        return s + f"  b 0x{target & 0xFFFFFFFF:05X}"
    if inst >> 24 == 0x90:
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF
        immlo = (inst >> 29) & 0x3
        imm_v = (immhi << 2) | immlo
        if imm_v & 0x100000: imm_v |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (imm_v << 12)) & 0xFFFFFFFF
        return s + f"  adrp x{rd}, 0x{pg:X}"
    if (inst >> 24) == 0xD0:  # ADRP (another encoding range)
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF
        immlo = (inst >> 29) & 0x3
        imm_v = (immhi << 2) | immlo
        if imm_v & 0x100000: imm_v |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (imm_v << 12)) & 0xFFFFFFFF
        return s + f"  adrp x{rd}, 0x{pg:X}"
    if (inst & 0xFF800000) == 0x91000000:  # ADD Xd, Xn, #imm
        rd = inst & 0x1F
        rn = (inst >> 5) & 0x1F
        imm12 = (inst >> 10) & 0xFFF
        sh = (inst >> 22) & 1
        if sh: imm12 <<= 12
        return s + f"  add x{rd}, x{rn}, #0x{imm12:X}"
    if (inst & 0xFFFFFC00) == 0x39003400:
        rt = inst & 0x1F
        rn = (inst >> 5) & 0x1F
        return s + f"  strb w{rt}, [x{rn}, #13]"
    if (inst & 0xFFC00000) == 0x39000000:
        rt = inst & 0x1F
        rn = (inst >> 5) & 0x1F
        imm12 = (inst >> 10) & 0xFFF
        return s + f"  strb w{rt}, [x{rn}, #{imm12}]"
    if (inst & 0xFFC00000) == 0x39400000:
        rt = inst & 0x1F
        rn = (inst >> 5) & 0x1F
        imm12 = (inst >> 10) & 0xFFF
        return s + f"  ldrb w{rt}, [x{rn}, #{imm12}]"
    if (inst & 0xFF000000) == 0x54000000:
        imm19 = (inst >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x7FFFF
        target = off + (imm19 << 2)
        cond = inst & 0xF
        cnames = {0:'EQ',1:'NE',2:'CS',3:'CC',4:'MI',5:'PL',6:'VS',7:'VC',
                  8:'HI',9:'LS',10:'GE',11:'LT',12:'GT',13:'LE',14:'AL'}
        return s + f"  b.{cnames.get(cond,'?')} 0x{target & 0xFFFFFFFF:05X}"
    if inst >> 24 == 0xB4:
        rt = inst & 0x1F
        imm19 = (inst >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x7FFFF
        target = off + (imm19 << 2)
        return s + f"  cbz x{rt}, 0x{target & 0xFFFFFFFF:05X}"
    if inst >> 24 == 0xB5:
        rt = inst & 0x1F
        imm19 = (inst >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x7FFFF
        target = off + (imm19 << 2)
        return s + f"  cbnz x{rt}, 0x{target & 0xFFFFFFFF:05X}"
    if inst >> 24 == 0x34:
        rt = inst & 0x1F
        imm19 = (inst >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x7FFFF
        target = off + (imm19 << 2)
        return s + f"  cbz w{rt}, 0x{target & 0xFFFFFFFF:05X}"
    if inst >> 24 == 0x35:
        rt = inst & 0x1F
        imm19 = (inst >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x7FFFF
        target = off + (imm19 << 2)
        return s + f"  cbnz w{rt}, 0x{target & 0xFFFFFFFF:05X}"
    if (inst & 0xFF800000) == 0x52800000:
        rd = inst & 0x1F
        imm16 = (inst >> 5) & 0xFFFF
        return s + f"  mov w{rd}, #{imm16}"
    if (inst & 0xFFE0FFE0) == 0xAA0003E0:
        rd = inst & 0x1F
        rm = (inst >> 16) & 0x1F
        return s + f"  mov x{rd}, x{rm}"
    if (inst & 0xFFE0FFE0) == 0x2A0003E0:
        rd = inst & 0x1F
        rm = (inst >> 16) & 0x1F
        return s + f"  mov w{rd}, w{rm}"
    return s

for off in range(0x232D8, 0x233B0, 4):
    inst = struct.unpack_from("<I", pe, off)[0]
    print(decode_inst(off, inst))
    if inst == 0xD65F03C0 and off > 0x23300:
        break

# ============================================================
# 7. 反汇编 0x18248 (ReadWritePartition) 入口
# ============================================================
print("\n" + "=" * 70)
print("=== 7. 0x18248 入口 (ReadWritePartition) ===")
print("=" * 70)
for off in range(0x18248, 0x18348, 4):
    inst = struct.unpack_from("<I", pe, off)[0]
    print(decode_inst(off, inst))
    if inst == 0xD65F03C0 and off > 0x18280:
        break

# ============================================================
# 8. 检查 0x232E0 处的 ADRP 值 (x20 即 devinfo buffer 还是其他?)
# ============================================================
print("\n" + "=" * 70)
print("=== 8. 分析 0x232D8 函数中的关键 ADRP ===")
print("=" * 70)
# At 0x232E0: 0xF0000CD4 - check if this is ADRP
inst = struct.unpack_from("<I", pe, 0x232E0)[0]
print(f"  0x232E0: 0x{inst:08X}")
# ADRP: bit[31]=1, bits[28:24]=10000
if (inst & 0x9F000000) == 0x90000000:
    rd = inst & 0x1F
    immhi = (inst >> 5) & 0x7FFFF
    immlo = (inst >> 29) & 0x3
    imm_v = (immhi << 2) | immlo
    if imm_v & 0x100000: imm_v |= ~0x1FFFFF
    pg = ((0x232E0 & ~0xFFF) + (imm_v << 12)) & 0xFFFFFFFF
    print(f"    ADRP x{rd}, 0x{pg:X}")
else:
    print(f"    Not ADRP, raw encoding")

# Check 0x232E4 and the flag at [x20, #904]
print(f"\n  0x232E4: LDRB w8, [x20, {904}] = [x20, #0x388]")
print(f"  This flag controls whether to read devinfo or skip")

# At 0x232EC: ADRP for the buffer/partition name
inst2 = struct.unpack_from("<I", pe, 0x232EC)[0]
print(f"\n  0x232EC: 0x{inst2:08X}")
if (inst2 & 0x9F000000) == 0x90000000:
    rd = inst2 & 0x1F
    immhi = (inst2 >> 5) & 0x7FFFF
    immlo = (inst2 >> 29) & 0x3
    imm_v = (immhi << 2) | immlo
    if imm_v & 0x100000: imm_v |= ~0x1FFFFF
    pg = ((0x232EC & ~0xFFF) + (imm_v << 12)) & 0xFFFFFFFF
    print(f"    ADRP x{rd}, 0x{pg:X}")

# ============================================================
# 9. 搜索 CopyMem/SetMem 到 devinfo buffer
# ============================================================
print("\n" + "=" * 70)
print("=== 9. 搜索 BL 0x4FD10 (CompareMem) 所有调用点 ===")
print("=" * 70)
for off in range(0, CODE_END, 4):
    inst = struct.unpack_from("<I", pe, off)[0]
    if (inst >> 26) == 0x25:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        target = off + (imm << 2)
        if (target & 0xFFFFFFFF) == 0x4FD10:
            print(f"  BL at 0x{off:05X} → 0x4FD10 (CompareMem)")

# Also search for BL 0x4FE50 (likely SetMem/CopyMem?)
print("\n--- BL 0x4FE50 调用点 ---")
for off in range(0, CODE_END, 4):
    inst = struct.unpack_from("<I", pe, off)[0]
    if (inst >> 26) == 0x25:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        target = off + (imm << 2)
        if (target & 0xFFFFFFFF) == 0x4FE50:
            print(f"  BL at 0x{off:05X} → 0x4FE50")

# ============================================================
# 10. 检查 TBNZ/TBZ 指令是否操作 devinfo 相关位
# ============================================================
print("\n" + "=" * 70)
print("=== 10. 0x232E8 处的分支指令 ===")
print("=" * 70)
inst = struct.unpack_from("<I", pe, 0x232E8)[0]
print(f"  0x232E8: 0x{inst:08X}")
# TBZ/TBNZ: bit[31]=b5, [30:25]=011011, [24]=op, [23:19]=b40, [18:5]=imm14, [4:0]=Rt
if (inst & 0x7E000000) == 0x36000000:
    b5 = (inst >> 31) & 1
    op = (inst >> 24) & 1
    b40 = (inst >> 19) & 0x1F
    bit_pos = (b5 << 5) | b40
    imm14 = (inst >> 5) & 0x3FFF
    if imm14 & 0x2000: imm14 |= ~0x3FFF
    target = 0x232E8 + (imm14 << 2)
    rt = inst & 0x1F
    mnemonic = "tbnz" if op else "tbz"
    print(f"    {mnemonic} w{rt}, #{bit_pos}, 0x{target & 0xFFFFFFFF:05X}")
else:
    print(f"    Not TBZ/TBNZ")
