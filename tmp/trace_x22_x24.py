#!/usr/bin/env python3
"""
1. 找到 0x48488 所在函数的起始地址
2. 追踪 x22 和 x24 的赋值
3. 找 init_defaults (0x384D0) 的所有调用者
4. 找 0x22E34 附近函数的所有调用者 (写 devinfo[0x0D])
"""
import struct

PE32 = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
TEXT_SIZE = 0x6A000

with open(PE32, "rb") as f:
    pe = f.read()

code = pe[:TEXT_SIZE]

def find_bl_to(target):
    """Find all BL instructions targeting given address"""
    callers = []
    for i in range(0, TEXT_SIZE, 4):
        insn = struct.unpack_from('<I', code, i)[0]
        if (insn & 0xFC000000) == 0x94000000:
            off26 = insn & 0x03FFFFFF
            if off26 & (1 << 25): off26 -= (1 << 26)
            dest = i + off26 * 4
            if dest == target:
                callers.append(i)
    return callers

def decode_insn(addr):
    """Quick instruction decode"""
    insn = struct.unpack_from('<I', code, addr)[0]

    # RET
    if insn == 0xD65F03C0: return "ret"

    # STP pre-index (function prologue)
    if (insn & 0xFFC00000) in (0xA9800000, 0xA9A00000, 0xA9B00000, 0xA9BE0000):
        rt = insn & 0x1f
        rt2 = (insn >> 10) & 0x1f
        rn = (insn >> 5) & 0x1f
        imm7 = (insn >> 15) & 0x7f
        if imm7 & 0x40: imm7 -= 128
        return f"stp x{rt}, x{rt2}, [x{rn}, #{imm7*8}]!"

    # STP signed offset
    if (insn & 0xFFC00000) in (0xA9000000, 0xA9010000, 0xA9020000):
        rt = insn & 0x1f
        rt2 = (insn >> 10) & 0x1f
        rn = (insn >> 5) & 0x1f
        imm7 = (insn >> 15) & 0x7f
        if imm7 & 0x40: imm7 -= 128
        return f"stp x{rt}, x{rt2}, [x{rn}, #{imm7*8}]"

    # LDP pre-index (function epilogue)
    if (insn & 0xFE400000) == 0xA8C00000:
        rt = insn & 0x1f
        rt2 = (insn >> 10) & 0x1f
        rn = (insn >> 5) & 0x1f
        imm7 = (insn >> 15) & 0x7f
        if imm7 & 0x40: imm7 -= 128
        return f"ldp x{rt}, x{rt2}, [x{rn}], #{imm7*8}"

    # BL
    if (insn & 0xFC000000) == 0x94000000:
        off26 = insn & 0x03FFFFFF
        if off26 & (1 << 25): off26 -= (1 << 26)
        return f"bl 0x{addr + off26*4:05X}"

    # B
    if (insn & 0xFC000000) == 0x14000000:
        off26 = insn & 0x03FFFFFF
        if off26 & (1 << 25): off26 -= (1 << 26)
        return f"b 0x{addr + off26*4:05X}"

    # B.cond
    if (insn & 0xFF000010) == 0x54000000:
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1 << 18): imm19 -= (1 << 19)
        conds = {0:'EQ',1:'NE',2:'CS',3:'CC',4:'MI',5:'PL',6:'VS',7:'VC',
                 8:'HI',9:'LS',10:'GE',11:'LT',12:'GT',13:'LE',14:'AL'}
        return f"b.{conds.get(insn&0xf, f'c{insn&0xf}')} 0x{addr + imm19*4:05X}"

    # CBZ/CBNZ
    if (insn & 0x7E000000) == 0x34000000:
        sf = "x" if (insn >> 31) else "w"
        op = "cbnz" if (insn >> 24) & 1 else "cbz"
        rt = insn & 0x1f
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1 << 18): imm19 -= (1 << 19)
        return f"{op} {sf}{rt}, 0x{addr + imm19*4:05X}"

    # TBZ/TBNZ
    if (insn & 0x7E000000) == 0x36000000:
        op = "tbnz" if (insn >> 24) & 1 else "tbz"
        bit = ((insn >> 31) << 5) | ((insn >> 19) & 0x1f)
        rt = insn & 0x1f
        imm14 = (insn >> 5) & 0x3FFF
        if imm14 & (1 << 13): imm14 -= (1 << 14)
        return f"{op} x{rt}, #{bit}, 0x{addr + imm14*4:05X}"

    # ADRP
    if (insn & 0x9F000000) == 0x90000000:
        rd = insn & 0x1f
        immlo = (insn >> 29) & 3
        immhi = (insn >> 5) & 0x7ffff
        imm = (immhi << 2) | immlo
        if imm & (1 << 20): imm -= (1 << 21)
        page = (addr & ~0xFFF) + (imm << 12)
        return f"adrp x{rd}, 0x{page:X}"

    # ADR
    if (insn & 0x9F000000) == 0x10000000:
        rd = insn & 0x1f
        immlo = (insn >> 29) & 3
        immhi = (insn >> 5) & 0x7ffff
        imm = (immhi << 2) | immlo
        if imm & (1 << 20): imm -= (1 << 21)
        return f"adr x{rd}, 0x{addr + imm:X}"

    # ADD immediate
    if (insn & 0xFFC00000) == 0x91000000:
        rd = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm12 = (insn >> 10) & 0xFFF
        sh = (insn >> 22) & 1
        if sh: imm12 <<= 12
        return f"add x{rd}, x{rn}, #0x{imm12:X}"

    # MOV (wide immediate)
    if (insn & 0xFF800000) == 0x52800000:
        rd = insn & 0x1f
        imm16 = (insn >> 5) & 0xFFFF
        return f"mov w{rd}, #{imm16}"
    if (insn & 0xFF800000) == 0xD2800000:
        rd = insn & 0x1f
        imm16 = (insn >> 5) & 0xFFFF
        return f"mov x{rd}, #{imm16}"

    # MOV register
    if (insn & 0xFFE0FFE0) == 0xAA0003E0:
        rd = insn & 0x1f
        rm = (insn >> 16) & 0x1f
        return f"mov x{rd}, x{rm}"
    if (insn & 0xFFE0FFE0) == 0x2A0003E0:
        rd = insn & 0x1f
        rm = (insn >> 16) & 0x1f
        return f"mov w{rd}, w{rm}"

    # STR/LDR unsigned offset
    if (insn & 0xFFC00000) == 0x39000000:
        imm12 = (insn >> 10) & 0xFFF
        return f"strb w{insn & 0x1f}, [x{(insn >> 5) & 0x1f}, #{imm12}]"
    if (insn & 0xFFC00000) == 0x39400000:
        imm12 = (insn >> 10) & 0xFFF
        return f"ldrb w{insn & 0x1f}, [x{(insn >> 5) & 0x1f}, #{imm12}]"

    # CSEL/CSINC/CSINV/CSNEG
    if (insn & 0x7FE00000) in (0x1A800000, 0x5A800000):
        sf = "x" if (insn >> 31) else "w"
        ops = {0: 'csel', 1: 'csinc', 2: 'csinv', 3: 'csneg'}
        op2 = ((insn >> 30) & 1) << 1 | ((insn >> 10) & 1)
        rm = (insn >> 16) & 0x1f
        cond = (insn >> 12) & 0xf
        rn = (insn >> 5) & 0x1f
        rd = insn & 0x1f
        conds = {0:'EQ',1:'NE',2:'CS',3:'CC',4:'MI',5:'PL',6:'VS',7:'VC',
                 8:'HI',9:'LS',10:'GE',11:'LT',12:'GT',13:'LE'}

        # Special cases
        if op2 == 1 and rn == 31 and rm == 31:
            # CSET
            inv_cond = cond ^ 1
            return f"cset {sf}{rd}, {conds.get(inv_cond, f'c{inv_cond}')}"
        return f"{ops.get(op2, '?')} {sf}{rd}, {sf}{rn}, {sf}{rm}, {conds.get(cond, f'c{cond}')}"

    # TST (ANDS with Rd=WZR)
    if (insn & 0x7F800000) == 0x72000000 and (insn & 0x1f) == 0x1f:
        rn = (insn >> 5) & 0x1f
        sf = "x" if (insn >> 31) else "w"
        # Decode bitmask immediate (simplified)
        return f"tst {sf}{rn}, #bitmask_imm"

    # CMP (SUBS with Rd=WZR)
    if (insn & 0x7FE0001F) == 0x6B00001F:
        rn = (insn >> 5) & 0x1f
        rm = (insn >> 16) & 0x1f
        sf = "x" if (insn >> 31) else "w"
        return f"cmp {sf}{rn}, {sf}{rm}"

    # LDR 64-bit unsigned offset
    if (insn & 0xFFC00000) == 0xF9400000:
        imm12 = (insn >> 10) & 0xFFF
        return f"ldr x{insn & 0x1f}, [x{(insn >> 5) & 0x1f}, #{imm12 * 8}]"

    # STR 64-bit unsigned offset
    if (insn & 0xFFC00000) == 0xF9000000:
        imm12 = (insn >> 10) & 0xFFF
        return f"str x{insn & 0x1f}, [x{(insn >> 5) & 0x1f}, #{imm12 * 8}]"

    # ORR immediate (used for MOV #imm)
    if (insn & 0xFF800000) == 0x32000000:
        rd = insn & 0x1f
        # Simplified - just show raw
        return f"orr w{rd}, wzr, #imm  (=mov w{rd}, #bitmask)"

    return f"0x{insn:08X}"


# === 1. Find function containing 0x48488 ===
print("=== 找 0x48488 所在函数的起始地址 ===")
func_start = None
for addr in range(0x48488, 0x46000, -4):
    insn = struct.unpack_from('<I', code, addr)[0]
    # Look for STP with SP pre-index (function prologue)
    if (insn & 0xFF8003E0) == 0xA98003E0:  # STP X*, X*, [SP, #imm]!
        func_start = addr
        break
    # Also check for explicit SUB SP pattern
    if (insn & 0xFFC003FF) == 0xD10003FF:  # SUB SP, SP, #imm
        func_start = addr
        break

if func_start:
    print(f"  Function starts at: 0x{func_start:05X}")
else:
    # Try more aggressive search
    print("  Trying pattern-based search...")
    for addr in range(0x48488, 0x46000, -4):
        insn = struct.unpack_from('<I', code, addr)[0]
        # STP any form with SP
        if (insn >> 22) & 0x3FF in (0x2A6, 0x2A7, 0x2A4, 0x2A5):
            func_start = addr
            print(f"  Possible function start at: 0x{addr:05X}: {decode_insn(addr)}")

# Broader search
print("\n  Looking for STP xN, x30 pattern nearby:")
for addr in range(0x48488, max(0x47000, 0x48488 - 0x1500), -4):
    insn = struct.unpack_from('<I', code, addr)[0]
    rt2 = (insn >> 10) & 0x1f
    # STP with x30 (LR) saved = function prologue
    if (insn & 0x7FC003E0) == 0x298003E0 or (insn & 0x7FC003E0) == 0x2D8003E0:
        pass  # 32-bit STP, skip
    if rt2 == 30:  # x30 saved
        if (insn & 0xFE400000) == 0xA9000000:  # STP (signed offset) or pre-index
            rt = insn & 0x1f
            rn = (insn >> 5) & 0x1f
            if rn == 31:  # SP base
                print(f"    0x{addr:05X}: {decode_insn(addr)}")
                if not func_start or addr > func_start:
                    pass

# === 2. Dump context around 0x48488 ===
print(f"\n=== 0x48340-0x484C0 区域代码 (fastboot var registration) ===")
for addr in range(0x48340, 0x484C0, 4):
    d = decode_insn(addr)
    mark = ""
    if addr == 0x48488: mark = "  ← IsDeviceUnlocked()"
    elif addr == 0x4849C: mark = "  ← publish 'unlocked'"
    elif "x22" in d or "x24" in d: mark = "  !!!"
    print(f"  0x{addr:05X}: {d}{mark}")

# === 3. Find x22 and x24 setup - search wider ===
print(f"\n=== 搜索 x22/x24 赋值 (0x47000-0x48500) ===")
for addr in range(0x47000, 0x48500, 4):
    insn = struct.unpack_from('<I', code, addr)[0]
    d = decode_insn(addr)
    rd = insn & 0x1f
    # Check if destination is x22 or x24
    is_x22_24 = False
    if rd in (22, 24):
        # MOV, ADRP, ADD, LDR
        if any(d.startswith(p) for p in ['mov x22', 'mov x24', 'mov w22', 'mov w24',
                                          'adrp x22', 'adrp x24',
                                          'add x22', 'add x24',
                                          'ldr x22', 'ldr x24',
                                          'ldrb w22', 'ldrb w24',
                                          'csel x22', 'csel x24',
                                          'adr x22', 'adr x24']):
            is_x22_24 = True
    if is_x22_24:
        print(f"  0x{addr:05X}: {d}")
        # If ADRP, check ADD that follows
        if d.startswith('adrp'):
            next_d = decode_insn(addr + 4)
            if next_d.startswith(f'add x{rd}'):
                print(f"  0x{addr+4:05X}: {next_d}")

# === 4. Find callers of init_defaults (0x384D0) ===
print(f"\n=== init_defaults (0x384D0) 的调用者 ===")
callers = find_bl_to(0x384D0)
for c in callers:
    print(f"  0x{c:05X}: bl 0x384D0")
    # Show context
    for ctx in range(max(c-20, 0), min(c+12, TEXT_SIZE), 4):
        print(f"      0x{ctx:05X}: {decode_insn(ctx)}")

# === 5. Find callers of 0x22E00 range (whole function around 0x22E4C) ===
# First find function start near 0x22E34
print(f"\n=== 找 0x22E34 附近的函数入口 ===")
for addr in range(0x22E34, 0x22C00, -4):
    insn = struct.unpack_from('<I', code, addr)[0]
    rt2 = (insn >> 10) & 0x1f
    if rt2 == 30 and (insn & 0xFE400000) in (0xA9000000, 0xA9800000):
        rn = (insn >> 5) & 0x1f
        if rn == 31:
            print(f"  Function prologue at 0x{addr:05X}: {decode_insn(addr)}")
            break
    if insn == 0xD65F03C0:  # RET before our code
        func_entry = addr + 4
        print(f"  Function entry (after ret) at 0x{func_entry:05X}")
        # Find callers of this entry
        callers2 = find_bl_to(func_entry)
        print(f"  Callers of 0x{func_entry:05X}:")
        for c in callers2:
            print(f"    0x{c:05X}: bl 0x{func_entry:05X}")
        break

# === 6. Decode the "yes"/"no" helper at 0x4D984 and find its callers ===
print(f"\n=== 0x4D984 (yes/no helper) callers ===")
callers3 = find_bl_to(0x4D984)
for c in callers3:
    print(f"  0x{c:05X}: bl 0x4D984")

# === 7. Resolve the strings at x22 and x24 lookup addresses ===
# From the context, "yes" is at 0x536BE and "no" at 0x66CE8
# Let's check if x22 or x24 could point to these
print(f"\n=== 检查关键字符串 ===")
for saddr, label in [(0x536BE, '"yes"'), (0x66CE8, '"no"'), (0x5361C, '"unlocked"'),
                      (0x51DB0, '"Unlocked"'), (0x51DB7, '"Locked"')]:
    if saddr < len(pe):
        end = pe.index(0, saddr) if 0 in pe[saddr:saddr+50] else saddr+20
        s = pe[saddr:end]
        print(f"  0x{saddr:05X}: {s}")
