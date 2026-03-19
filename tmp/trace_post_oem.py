#!/usr/bin/env python3
"""
追踪 OemCheckResetDevInfo 之后的函数 + 0x1B990
+ 搜索所有对 devinfo buffer (0x1BD978) 的引用
"""
import struct

PE = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
with open(PE, "rb") as f:
    pe = f.read()

def decode(off, inst):
    s = f"  0x{off:05X}: 0x{inst:08X}"
    if inst == 0xD65F03C0: return s + "  ret"
    if inst == 0x00000000: return s + "  (nop)"
    if (inst >> 26) == 0x25:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        t = off + (imm << 2)
        return s + f"  bl 0x{t & 0xFFFFFFFF:05X}"
    if (inst >> 26) == 0x05:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        t = off + (imm << 2)
        return s + f"  b 0x{t & 0xFFFFFFFF:05X}"
    if (inst & 0x9F000000) == 0x90000000:
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF; immlo = (inst >> 29) & 0x3
        iv = (immhi << 2) | immlo
        if iv & 0x100000: iv |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
        return s + f"  adrp x{rd}, 0x{pg:X}"
    if (inst & 0xFF800000) == 0x91000000:
        rd = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm12 = (inst >> 10) & 0xFFF
        sh = (inst >> 22) & 1
        if sh: imm12 <<= 12
        return s + f"  add x{rd}, x{rn}, #0x{imm12:X}"
    if (inst & 0xFFC00000) == 0x39000000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = (inst >> 10) & 0xFFF
        return s + f"  strb w{rt}, [x{rn}, #{imm}]"
    if (inst & 0xFFC00000) == 0x39400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = (inst >> 10) & 0xFFF
        return s + f"  ldrb w{rt}, [x{rn}, #{imm}]"
    if (inst & 0xFFC00000) == 0xF9400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 8
        return s + f"  ldr x{rt}, [x{rn}, #{imm}]"
    if (inst & 0xFFC00000) == 0xF9000000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 8
        return s + f"  str x{rt}, [x{rn}, #{imm}]"
    if (inst & 0xFFC00000) == 0xB9400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 4
        return s + f"  ldr w{rt}, [x{rn}, #{imm}]"
    if (inst & 0xFF000000) == 0x54000000:
        imm19 = (inst >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x7FFFF
        t = off + (imm19 << 2)
        c = inst & 0xF
        cn = {0:'EQ',1:'NE',2:'CS',3:'CC',4:'MI',5:'PL',6:'VS',7:'VC',
              8:'HI',9:'LS',10:'GE',11:'LT',12:'GT',13:'LE',14:'AL'}
        return s + f"  b.{cn.get(c,'?')} 0x{t & 0xFFFFFFFF:05X}"
    for pfx, mn in [(0xB4,'cbz x'),(0xB5,'cbnz x'),(0x34,'cbz w'),(0x35,'cbnz w')]:
        if inst >> 24 == pfx:
            rt = inst & 0x1F; imm19 = (inst >> 5) & 0x7FFFF
            if imm19 & 0x40000: imm19 |= ~0x7FFFF
            t = off + (imm19 << 2)
            return s + f"  {mn}{rt}, 0x{t & 0xFFFFFFFF:05X}"
    if (inst & 0xFF800000) == 0x52800000:
        rd = inst & 0x1F; imm16 = (inst >> 5) & 0xFFFF
        return s + f"  mov w{rd}, #{imm16}"
    if (inst & 0xFFE0FFE0) == 0xAA0003E0:
        rd = inst & 0x1F; rm = (inst >> 16) & 0x1F
        return s + f"  mov x{rd}, x{rm}"
    if (inst & 0xFFE0FFE0) == 0x2A0003E0:
        rd = inst & 0x1F; rm = (inst >> 16) & 0x1F
        return s + f"  mov w{rd}, w{rm}"
    if (inst & 0xFFC0001F) == 0x7100001F:
        rn = (inst >> 5) & 0x1F; imm = (inst >> 10) & 0xFFF
        return s + f"  cmp w{rn}, #{imm}"
    if (inst & 0x7E000000) == 0x36000000:
        b5 = (inst >> 31) & 1; op = (inst >> 24) & 1
        b40 = (inst >> 19) & 0x1F; bp = (b5 << 5) | b40
        imm14 = (inst >> 5) & 0x3FFF
        if imm14 & 0x2000: imm14 |= ~0x3FFF
        t = off + (imm14 << 2)
        mn = "tbnz" if op else "tbz"
        return s + f"  {mn} w{inst&0x1F}, #{bp}, 0x{t & 0xFFFFFFFF:05X}"
    if (inst & 0xFFE00000) == 0xD6200000:
        rn = (inst >> 5) & 0x1F; op = (inst >> 21) & 0x3
        ops = {0: 'br', 1: 'blr', 2: 'ret'}
        return s + f"  {ops.get(op,'?')} x{rn}"
    return s

def disasm_range(start, end, label=""):
    print(f"\n{'='*70}")
    print(f"=== {label} ===")
    print(f"{'='*70}")
    for off in range(start, end, 4):
        if off >= len(pe): break
        inst = struct.unpack_from("<I", pe, off)[0]
        print(decode(off, inst))
        if inst == 0xD65F03C0 and off > start + 8:
            break

# ============================================================
# 1. 0x30890 (called after OemCheckResetDevInfo)
# ============================================================
disasm_range(0x30890, 0x30A80, "0x30890 — post-OemCheckResetDevInfo func 1")

# ============================================================
# 2. 0x30AE0 (called after 0x30890)
# ============================================================
disasm_range(0x30AE0, 0x30C00, "0x30AE0 — post-OemCheckResetDevInfo func 2")

# ============================================================
# 3. 0x1B990 (called BEFORE ReadDeviceInfo at 0x01554)
# ============================================================
disasm_range(0x1B990, 0x1BA80, "0x1B990 — called before ReadDeviceInfo")

# ============================================================
# 4. 完整 boot function 0x367F0
# ============================================================
disasm_range(0x367F0, 0x36930, "0x367F0 — full boot function")

# ============================================================
# 5. 搜索所有 ADRP 0x1BD000 + ADD #0x978 + STRB 模式
# ============================================================
print(f"\n{'='*70}")
print("=== 5. 搜索 ADRP 0x1BD000 + ADD #0x978 后面跟 STRB 的位置 ===")
print(f"{'='*70}")

CODE_END = 0x6A000
for off in range(0, CODE_END - 8, 4):
    inst = struct.unpack_from("<I", pe, off)[0]
    if (inst & 0x9F000000) != 0x90000000:
        continue
    rd = inst & 0x1F
    immhi = (inst >> 5) & 0x7FFFF; immlo = (inst >> 29) & 0x3
    iv = (immhi << 2) | immlo
    if iv & 0x100000: iv |= ~0x1FFFFF
    pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
    if pg != 0x1BD000:
        continue

    # Check next few instructions for ADD #0x978
    for d in range(4, 20, 4):
        if off + d >= CODE_END:
            break
        next_inst = struct.unpack_from("<I", pe, off + d)[0]
        if (next_inst & 0xFF800000) == 0x91000000:
            rn2 = (next_inst >> 5) & 0x1F
            imm12 = (next_inst >> 10) & 0xFFF
            if rn2 == rd and imm12 == 0x978:
                rd2 = next_inst & 0x1F
                # Found ADRP+ADD combo, now look for STRBs in next 40 instructions
                writes = []
                for d2 in range(d+4, d+160, 4):
                    if off + d2 >= CODE_END:
                        break
                    si = struct.unpack_from("<I", pe, off + d2)[0]
                    if (si & 0xFFC00000) == 0x39000000:  # STRB
                        rt = si & 0x1F
                        rn = (si >> 5) & 0x1F
                        imm_off = (si >> 10) & 0xFFF
                        if rn == rd2:  # writing to devinfo buffer
                            writes.append((off + d2, rt, imm_off))
                    if si == 0xD65F03C0:  # RET
                        break
                    if (si >> 26) == 0x05:  # B (unconditional)
                        break
                if writes:
                    print(f"\n  ADRP at 0x{off:05X}, ADD at 0x{off+d:05X} → x{rd2} = devinfo_buf")
                    for wa, wrt, wimm in writes:
                        print(f"    STRB w{wrt} at 0x{wa:05X} → devinfo[{wimm}]")

# ============================================================
# 6. 搜索 IsSecureBootEnabled (0x189E0) 调用点
# ============================================================
print(f"\n{'='*70}")
print("=== 6. BL 0x189E0 (IsSecureBootEnabled) 调用者 ===")
print(f"{'='*70}")
for off in range(0, CODE_END, 4):
    inst = struct.unpack_from("<I", pe, off)[0]
    if (inst >> 26) == 0x25:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        t = off + (imm << 2)
        if (t & 0xFFFFFFFF) == 0x189E0:
            print(f"  BL at 0x{off:05X} → 0x189E0")
