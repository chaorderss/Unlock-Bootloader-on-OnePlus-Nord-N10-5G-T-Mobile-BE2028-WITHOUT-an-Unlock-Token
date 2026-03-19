#!/usr/bin/env python3
"""
追踪:
1. 0x01558 - ReadDeviceInfo 的唯一调用者 (boot init)
2. 0x1D38C - SetDeviceUnlocked 的唯一调用者
3. 0x22FFC 处的 STRB (可能的第二个 devinfo 写入)
4. 0x232E8 处的 TBNZ 解码
5. OemCheckResetDevInfo 完整 skip 路径 (0x365C4-0x36688)
"""
import struct

PE = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
with open(PE, "rb") as f:
    pe = f.read()

def decode(off, inst):
    s = f"  0x{off:05X}: 0x{inst:08X}"
    if inst == 0xD65F03C0: return s + "  ret"
    if inst == 0x00000000: return s + "  (padding/nop)"
    if (inst >> 26) == 0x25:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        target = off + (imm << 2)
        return s + f"  bl 0x{target & 0xFFFFFFFF:05X}"
    if (inst >> 26) == 0x05:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        target = off + (imm << 2)
        return s + f"  b 0x{target & 0xFFFFFFFF:05X}"
    if (inst & 0x9F000000) == 0x90000000:
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF
        immlo = (inst >> 29) & 0x3
        iv = (immhi << 2) | immlo
        if iv & 0x100000: iv |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
        return s + f"  adrp x{rd}, 0x{pg:X}"
    if (inst & 0xFF800000) == 0x91000000:
        rd = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm12 = (inst >> 10) & 0xFFF
        sh = (inst >> 22) & 1
        if sh: imm12 <<= 12
        return s + f"  add x{rd}, x{rn}, #0x{imm12:X}"
    if (inst & 0xFFFFFC00) == 0x39003400:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F
        return s + f"  strb w{rt}, [x{rn}, #13]"
    if (inst & 0xFFC00000) == 0x39000000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = (inst >> 10) & 0xFFF
        return s + f"  strb w{rt}, [x{rn}, #{imm}]"
    if (inst & 0xFFC00000) == 0x39400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = (inst >> 10) & 0xFFF
        return s + f"  ldrb w{rt}, [x{rn}, #{imm}]"
    if (inst & 0xFFC00000) == 0xF9400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 8
        return s + f"  ldr x{rt}, [x{rn}, #{imm}]"
    if (inst & 0xFFC00000) == 0xB9400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 4
        return s + f"  ldr w{rt}, [x{rn}, #{imm}]"
    if (inst & 0xFFC00000) == 0xF9000000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 8
        return s + f"  str x{rt}, [x{rn}, #{imm}]"
    if (inst & 0xFF000000) == 0x54000000:
        imm19 = (inst >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x7FFFF
        target = off + (imm19 << 2)
        cond = inst & 0xF
        cn = {0:'EQ',1:'NE',2:'CS',3:'CC',4:'MI',5:'PL',6:'VS',7:'VC',
              8:'HI',9:'LS',10:'GE',11:'LT',12:'GT',13:'LE',14:'AL'}
        return s + f"  b.{cn.get(cond,'?')} 0x{target & 0xFFFFFFFF:05X}"
    if inst >> 24 == 0xB4:
        rt = inst & 0x1F
        imm19 = (inst >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x7FFFF
        return s + f"  cbz x{rt}, 0x{off + (imm19 << 2) & 0xFFFFFFFF:05X}"
    if inst >> 24 == 0xB5:
        rt = inst & 0x1F
        imm19 = (inst >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x7FFFF
        return s + f"  cbnz x{rt}, 0x{off + (imm19 << 2) & 0xFFFFFFFF:05X}"
    if inst >> 24 == 0x34:
        rt = inst & 0x1F
        imm19 = (inst >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x7FFFF
        return s + f"  cbz w{rt}, 0x{off + (imm19 << 2) & 0xFFFFFFFF:05X}"
    if inst >> 24 == 0x35:
        rt = inst & 0x1F
        imm19 = (inst >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x7FFFF
        return s + f"  cbnz w{rt}, 0x{off + (imm19 << 2) & 0xFFFFFFFF:05X}"
    if (inst & 0xFF800000) == 0x52800000:
        rd = inst & 0x1F; imm16 = (inst >> 5) & 0xFFFF
        return s + f"  mov w{rd}, #{imm16}"
    if (inst & 0xFFE0FFE0) == 0xAA0003E0:
        rd = inst & 0x1F; rm = (inst >> 16) & 0x1F
        return s + f"  mov x{rd}, x{rm}"
    if (inst & 0xFFE0FFE0) == 0x2A0003E0:
        rd = inst & 0x1F; rm = (inst >> 16) & 0x1F
        return s + f"  mov w{rd}, w{rm}"
    if (inst & 0x7E000000) == 0x36000000:
        b5 = (inst >> 31) & 1
        op = (inst >> 24) & 1
        b40 = (inst >> 19) & 0x1F
        bit_pos = (b5 << 5) | b40
        imm14 = (inst >> 5) & 0x3FFF
        if imm14 & 0x2000: imm14 |= ~0x3FFF
        target = off + (imm14 << 2)
        mn = "tbnz" if op else "tbz"
        return s + f"  {mn} w{inst&0x1F}, #{bit_pos}, 0x{target & 0xFFFFFFFF:05X}"
    if (inst & 0xFFE0FC00) == 0x6B00001F:  # CMP (shifted reg)
        rn = (inst >> 5) & 0x1F; rm = (inst >> 16) & 0x1F
        return s + f"  cmp w{rn}, w{rm}"
    if (inst & 0xFFC0001F) == 0x7100001F:  # CMP (imm)
        rn = (inst >> 5) & 0x1F; imm = (inst >> 10) & 0xFFF
        return s + f"  cmp w{rn}, #{imm}"
    if (inst & 0xFFE0FC00) == 0xEB00001F:  # CMP (64 shifted reg)
        rn = (inst >> 5) & 0x1F; rm = (inst >> 16) & 0x1F
        return s + f"  cmp x{rn}, x{rm}"
    if (inst & 0xFFE00000) == 0xD6200000:  # BR/BLR
        rn = (inst >> 5) & 0x1F
        op = (inst >> 21) & 0x3
        if op == 0: return s + f"  br x{rn}"
        if op == 1: return s + f"  blr x{rn}"
        return s + f"  ret (x{rn})" if op == 2 else s
    if (inst & 0xFFC00000) == 0xA9000000:  # STP (pre-idx or signed offset)
        rt = inst & 0x1F; rt2 = (inst >> 10) & 0x1F; rn = (inst >> 5) & 0x1F
        imm7 = (inst >> 15) & 0x7F
        if imm7 & 0x40: imm7 -= 0x80
        return s + f"  stp x{rt}, x{rt2}, [x{rn}, #{imm7*8}]"
    return s

def disasm_range(start, end, label=""):
    print(f"\n{'='*70}")
    print(f"=== {label} (0x{start:05X}-0x{end:05X}) ===")
    print(f"{'='*70}")
    for off in range(start, end, 4):
        inst = struct.unpack_from("<I", pe, off)[0]
        print(decode(off, inst))
        if inst == 0xD65F03C0 and off > start + 8:
            break

# ============================================================
# 1. 0x01558 周围的启动序列上下文 (0x01500-0x01600)
# ============================================================
disasm_range(0x01500, 0x01620, "Boot init around BL ReadDeviceInfo (0x01558)")

# ============================================================
# 2. 0x1D38C 周围 - SetDeviceUnlocked 调用者 (0x1D300-0x1D450)
# ============================================================
disasm_range(0x1D300, 0x1D450, "SetDeviceUnlocked caller (0x1D38C)")

# ============================================================
# 3. 0x22FFC 上下文 - 另一个 STRB to [x1, #13]
# ============================================================
disasm_range(0x22F80, 0x23030, "STRB at 0x22FFC context")

# ============================================================
# 4. OemCheckResetDevInfo skip path (0x365C0-0x366A0)
# ============================================================
disasm_range(0x365C0, 0x366A0, "OemCheckResetDevInfo skip path")

# ============================================================
# 5. 追踪 0x0B764 STRB (可能的 devinfo 写入?)
# ============================================================
disasm_range(0x0B700, 0x0B7B0, "STRB at 0x0B764 context")

# ============================================================
# 6. 追踪 0x0AE94 STRB
# ============================================================
disasm_range(0x0AE40, 0x0AEE0, "STRB at 0x0AE94 context")

# ============================================================
# 7. 0x3988C STRB - 可能相关
# ============================================================
disasm_range(0x39850, 0x398E0, "STRB at 0x3988C context")

# ============================================================
# 8. 读取 devinfo 相关的字符串 "ANDROID-BOOT!" = 0x5BF06
# ============================================================
print(f"\n{'='*70}")
print(f"=== 8. 验证 ANDROID-BOOT! 字符串位置 ===")
print(f"{'='*70}")
magic = pe[0x5BF06:0x5BF13]
print(f"  0x5BF06: {magic}")
print(f"  Hex: {magic.hex()}")

# ============================================================
# 9. 分析 0x232F4 处的 w2=2576 → ReadWritePartition 读取的大小
# ============================================================
print(f"\n{'='*70}")
print(f"=== 9. ReadWritePartition 参数分析 ===")
print(f"{'='*70}")
print(f"  w0 = 0 (read mode)")
print(f"  x1 = 0x1BD978 (devinfo buffer)")
print(f"  w2 = 2576 = 0xA10 (size)")
print(f"  devinfo.bin size = {4096} = 0x1000")
print(f"  注意: 只读取 2576 字节, 不是完整的 4096!")

# ============================================================
# 10. 追踪 0x01558 的调用链更上层
# ============================================================
disasm_range(0x01370, 0x01560, "Boot init function (before ReadDeviceInfo)")
