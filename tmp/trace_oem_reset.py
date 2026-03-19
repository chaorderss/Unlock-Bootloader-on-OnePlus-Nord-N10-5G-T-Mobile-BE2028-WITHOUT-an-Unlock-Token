#!/usr/bin/env python3
"""
追踪 OemCheckResetDevInfo 及 init_defaults 调用的完整流程。
关键：0x363CC 调用了 init_defaults，然后 b.NE 到 0x365C4。
"""
import struct

PE32 = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
TEXT_SIZE = 0x6A000

with open(PE32, "rb") as f:
    pe = f.read()

code = pe[:TEXT_SIZE]

def decode_insn(addr):
    insn = struct.unpack_from('<I', code, addr)[0]
    if insn == 0xD65F03C0: return "ret"
    if insn == 0x00000000: return "nop/padding"

    # STP pre-index
    if (insn & 0x7FC00000) == 0x29800000 or (insn & 0x7FC00000) == 0x29000000:
        sf = 8 if (insn >> 31) else 4
        rt = insn & 0x1f; rt2 = (insn >> 10) & 0x1f; rn = (insn >> 5) & 0x1f
        imm7 = (insn >> 15) & 0x7f
        if imm7 & 0x40: imm7 -= 128
        pre = "!" if (insn >> 23) & 1 else ""
        r = "x" if sf == 8 else "w"
        return f"stp {r}{rt}, {r}{rt2}, [x{rn}, #{imm7*sf}]{pre}"

    # LDP post-index
    if (insn & 0x7FC00000) == 0x28C00000:
        sf = 8 if (insn >> 31) else 4
        rt = insn & 0x1f; rt2 = (insn >> 10) & 0x1f; rn = (insn >> 5) & 0x1f
        imm7 = (insn >> 15) & 0x7f
        if imm7 & 0x40: imm7 -= 128
        r = "x" if sf == 8 else "w"
        return f"ldp {r}{rt}, {r}{rt2}, [x{rn}], #{imm7*sf}"

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
        immlo = (insn >> 29) & 3; immhi = (insn >> 5) & 0x7ffff
        imm = (immhi << 2) | immlo
        if imm & (1 << 20): imm -= (1 << 21)
        page = (addr & ~0xFFF) + (imm << 12)
        return f"adrp x{rd}, 0x{page:X}"

    # ADD immediate
    if (insn & 0xFF000000) == 0x91000000:
        rd = insn & 0x1f; rn = (insn >> 5) & 0x1f; imm12 = (insn >> 10) & 0xFFF
        sh = (insn >> 22) & 1
        if sh: imm12 <<= 12
        return f"add x{rd}, x{rn}, #0x{imm12:X}"

    # SUB immediate
    if (insn & 0xFF000000) == 0xD1000000:
        rd = insn & 0x1f; rn = (insn >> 5) & 0x1f; imm12 = (insn >> 10) & 0xFFF
        return f"sub x{rd}, x{rn}, #0x{imm12:X}"

    # MOV wide immediate
    if (insn & 0xFF800000) == 0x52800000:
        return f"mov w{insn & 0x1f}, #{(insn >> 5) & 0xFFFF}"
    if (insn & 0xFF800000) == 0xD2800000:
        return f"mov x{insn & 0x1f}, #{(insn >> 5) & 0xFFFF}"

    # MOV register (ORR Rd, XZR, Rm)
    if (insn & 0xFFE0FFE0) == 0xAA0003E0:
        return f"mov x{insn & 0x1f}, x{(insn >> 16) & 0x1f}"
    if (insn & 0xFFE0FFE0) == 0x2A0003E0:
        return f"mov w{insn & 0x1f}, w{(insn >> 16) & 0x1f}"

    # ORR immediate (often used as MOV)
    if (insn & 0xFF800000) == 0x32000000:
        # Decode bitmask immediate
        n = (insn >> 22) & 1; immr = (insn >> 16) & 0x3f; imms = (insn >> 10) & 0x3f
        rd = insn & 0x1f; rn = (insn >> 5) & 0x1f
        if rn == 31:
            # this is MOV Wd, #imm
            # Simple decode for common cases
            if n == 0 and immr == 0:
                val = (1 << (imms + 1)) - 1
                return f"mov w{rd}, #0x{val:X} ({val})"
            return f"mov w{rd}, #bitmask(N={n},R={immr},S={imms})"
        return f"orr w{rd}, w{rn}, #bitmask"
    if (insn & 0xFF800000) == 0xB2000000:
        rd = insn & 0x1f; rn = (insn >> 5) & 0x1f
        if rn == 31:
            n = (insn >> 22) & 1; immr = (insn >> 16) & 0x3f; imms = (insn >> 10) & 0x3f
            return f"mov x{rd}, #bitmask64(N={n},R={immr},S={imms})"
        return f"orr x{rd}, x{rn}, #bitmask64"

    # STRB unsigned offset
    if (insn & 0xFFC00000) == 0x39000000:
        return f"strb w{insn & 0x1f}, [x{(insn >> 5) & 0x1f}, #{(insn >> 10) & 0xFFF}]"
    # LDRB unsigned offset
    if (insn & 0xFFC00000) == 0x39400000:
        return f"ldrb w{insn & 0x1f}, [x{(insn >> 5) & 0x1f}, #{(insn >> 10) & 0xFFF}]"

    # STR 32-bit unsigned offset
    if (insn & 0xFFC00000) == 0xB9000000:
        return f"str w{insn & 0x1f}, [x{(insn >> 5) & 0x1f}, #{((insn >> 10) & 0xFFF) * 4}]"
    # LDR 32-bit unsigned offset
    if (insn & 0xFFC00000) == 0xB9400000:
        return f"ldr w{insn & 0x1f}, [x{(insn >> 5) & 0x1f}, #{((insn >> 10) & 0xFFF) * 4}]"
    # LDR 64-bit unsigned offset
    if (insn & 0xFFC00000) == 0xF9400000:
        return f"ldr x{insn & 0x1f}, [x{(insn >> 5) & 0x1f}, #{((insn >> 10) & 0xFFF) * 8}]"
    # STR 64-bit unsigned offset
    if (insn & 0xFFC00000) == 0xF9000000:
        return f"str x{insn & 0x1f}, [x{(insn >> 5) & 0x1f}, #{((insn >> 10) & 0xFFF) * 8}]"

    # LDUR/STUR (unscaled offset)
    if (insn & 0xFFE00C00) == 0xB8400000:
        imm9 = (insn >> 12) & 0x1FF
        if imm9 & 0x100: imm9 -= 0x200
        return f"ldur w{insn & 0x1f}, [x{(insn >> 5) & 0x1f}, #{imm9}]"
    if (insn & 0xFFE00C00) == 0xB8000000:
        imm9 = (insn >> 12) & 0x1FF
        if imm9 & 0x100: imm9 -= 0x200
        return f"stur w{insn & 0x1f}, [x{(insn >> 5) & 0x1f}, #{imm9}]"
    if (insn & 0xFFE00C00) == 0xF8400000:
        imm9 = (insn >> 12) & 0x1FF
        if imm9 & 0x100: imm9 -= 0x200
        return f"ldur x{insn & 0x1f}, [x{(insn >> 5) & 0x1f}, #{imm9}]"

    # LDR/STR with pre/post index (various forms)
    if (insn & 0xFFE00C00) == 0xB8400C00:  # LDR pre-index
        imm9 = (insn >> 12) & 0x1FF
        if imm9 & 0x100: imm9 -= 0x200
        return f"ldr w{insn & 0x1f}, [x{(insn >> 5) & 0x1f}, #{imm9}]!"
    if (insn & 0xFFE00C00) == 0xB8400400:  # LDR post-index
        imm9 = (insn >> 12) & 0x1FF
        if imm9 & 0x100: imm9 -= 0x200
        return f"ldr w{insn & 0x1f}, [x{(insn >> 5) & 0x1f}], #{imm9}"

    # CMP immediate
    if (insn & 0xFF80001F) == 0x7100001F:
        rn = (insn >> 5) & 0x1f
        imm12 = (insn >> 10) & 0xFFF
        return f"cmp w{rn}, #{imm12}"
    if (insn & 0xFF80001F) == 0xF100001F:
        rn = (insn >> 5) & 0x1f
        imm12 = (insn >> 10) & 0xFFF
        return f"cmp x{rn}, #{imm12}"

    # CMP register
    if (insn & 0xFFE0FC1F) == 0x6B00001F:
        return f"cmp w{(insn >> 5) & 0x1f}, w{(insn >> 16) & 0x1f}"
    if (insn & 0xFFE0FC1F) == 0xEB00001F:
        return f"cmp x{(insn >> 5) & 0x1f}, x{(insn >> 16) & 0x1f}"

    # TST
    if (insn & 0x7F80001F) == 0x7200001F:
        rn = (insn >> 5) & 0x1f
        return f"tst w{rn}, #bitmask"
    if (insn & 0x7F80001F) == 0xF200001F:
        rn = (insn >> 5) & 0x1f
        return f"tst x{rn}, #bitmask"

    # CSEL/CSINC/CSINV/CSNEG
    if (insn & 0x7FE00000) in (0x1A800000, 0x5A800000):
        sf = "x" if (insn >> 31) else "w"
        ops = {0: 'csel', 1: 'csinc', 2: 'csinv', 3: 'csneg'}
        op2 = ((insn >> 30) & 1) << 1 | ((insn >> 10) & 1)
        rm = (insn >> 16) & 0x1f; cond = (insn >> 12) & 0xf
        rn = (insn >> 5) & 0x1f; rd = insn & 0x1f
        conds = {0:'EQ',1:'NE',2:'CS',3:'CC',4:'MI',5:'PL',6:'VS',7:'VC',
                 8:'HI',9:'LS',10:'GE',11:'LT',12:'GT',13:'LE'}
        if op2 == 1 and rn == 31 and rm == 31:
            return f"cset {sf}{rd}, {conds.get(cond^1, f'c{cond^1}')}"
        return f"{ops[op2]} {sf}{rd}, {sf}{rn}, {sf}{rm}, {conds.get(cond, f'c{cond}')}"

    # AND immediate
    if (insn & 0xFF800000) == 0x12000000:
        rd = insn & 0x1f; rn = (insn >> 5) & 0x1f
        imms = (insn >> 10) & 0x3f
        if imms == 7:
            return f"and w{rd}, w{rn}, #0xFF"
        return f"and w{rd}, w{rn}, #bitmask"

    # NOP
    if insn == 0xD503201F: return "nop"

    return f"0x{insn:08X}"

# === Full dump of the large function containing OemCheckResetDevInfo ===
# Let's find the function start
print("=== 找 OemCheckResetDevInfo 函数的真正起始 ===")
func_start_candidates = []
for addr in range(0x363CC, 0x35000, -4):
    insn = struct.unpack_from('<I', code, addr)[0]
    d = decode_insn(addr)
    # STP with SP pre-index (function prologue)
    if "stp" in d and "!" in d and "x31" not in d and "[x31" not in d:  # exclude x31 as operand
        pass
    if (insn & 0xFF8003E0) == 0xA98003E0:  # STP X*, X*, [SP, #imm]!
        func_start_candidates.append(addr)
        print(f"  STP prologue at 0x{addr:05X}: {d}")
        if len(func_start_candidates) >= 3:
            break
    if insn == 0xD65F03C0 and addr < 0x363C0:  # RET = end of previous function
        print(f"  RET at 0x{addr:05X} → function starts at 0x{addr+4:05X}")
        break

# === Dump code from ~0x36300 to 0x36700 ===
print(f"\n=== 0x362C0-0x36700 完整反汇编 ===")
for addr in range(0x362C0, 0x36700, 4):
    d = decode_insn(addr)
    mark = ""
    if addr == 0x363CC: mark = "  ← init_defaults(1) !!!"
    elif addr == 0x363C4: mark = "  ← KEY BRANCH"
    elif addr == 0x365C4: mark = "  ← branch target from 0x363C4"
    elif "0x384D0" in d: mark = "  ← init_defaults"
    elif "0x384B0" in d or "0x384b0" in d: mark = "  ← set_is_unlocked_1"
    elif "0x22C18" in d: mark = "  ← IsDeviceUnlocked"
    elif "0x22CA8" in d or "0x22ca8" in d: mark = "  ← WriteDeviceInfo?"
    elif "0x18248" in d: mark = "  ← WriteDeviceInfo"
    elif "0x22870" in d: mark = "  ← ReadDeviceInfo?"
    elif "0x280FC" in d: mark = "  ← memcmp?"
    elif "0x189E0" in d: mark = "  ← IsSecureBootEnabled?"
    elif "ret" in d: mark = "  ← RETURN"
    print(f"  0x{addr:05X}: {d}{mark}")

# === Also, dump the ReadDeviceInfo function around 0x23390 ===
print(f"\n=== ReadDeviceInfo 区域 (0x23300-0x23420) ===")
for addr in range(0x23300, 0x23420, 4):
    d = decode_insn(addr)
    mark = ""
    if addr == 0x23390: mark = "  ← init_defaults !!!"
    elif "0x280FC" in d: mark = "  ← memcmp/validate"
    elif "0x18248" in d: mark = "  ← WriteDeviceInfo"
    elif "0x384D0" in d: mark = "  ← init_defaults"
    elif "ret" in d: mark = "  ← RETURN"
    print(f"  0x{addr:05X}: {d}{mark}")

# === Resolve strings used in these functions ===
print(f"\n=== 关键字符串 ===")
for saddr in [0x5BF14, 0x5BF06, 0x5BF00]:
    if saddr < len(pe):
        end = pe.index(0, saddr) if 0 in pe[saddr:saddr+50] else saddr+20
        s = pe[saddr:end]
        print(f"  0x{saddr:05X}: {s}")

# Look for "ANDROID-BOOT" in data
import re
for m in re.finditer(b'ANDROID-BOOT', pe):
    print(f"  'ANDROID-BOOT' at 0x{m.start():05X}")

# === Check what 0x363CC conditional depends on ===
# Decode 0xB85F02E8 manually
insn = 0xB85F02E8
print(f"\n=== 手动解码 0x363BC 指令: 0x{insn:08X} ===")
# This is LDR W8, [X23, #imm] with post-index or pre-index
# Actually let me check all variants
# [31:30] = 10 → size=4 bytes
# [29:27] = 111
# [26] = 0 → not SIMD
# [25:24] = 00
# [23:22] = 01 → LDR (unsigned offset)? or LDUR?
# Actually, let me check bit by bit:
# 10 11 1000 01 0 111110000 00 10111 01000
# size=10, V=1? No...
# Let me just check the full encoding
bits = f"{insn:032b}"
print(f"  Binary: {bits}")
print(f"  [31:30]={bits[0:2]} [29:27]={bits[2:5]} [26]={bits[5]} [25:24]={bits[6:8]}")
print(f"  [23:22]={bits[8:10]} [21]={bits[10]} [20:12]={bits[11:20]} [11:10]={bits[20:22]}")
print(f"  [9:5]={bits[22:27]} [4:0]={bits[27:32]}")

# LDR Wt, [Xn], #simm9 (post-index)
# 10 111000 01 0 simm9 01 Rn Rt
# bits: 10 111000 01 0 111110000 00 10111 01000
# That's: size=10(W), opc=01(LDR), 0, imm9=111110000, post/pre=00(LDUR), Rn=10111(x23), Rt=01000(w8)
# LDUR has bits [11:10]=00
# So this is: LDUR W8, [X23, #-16]
imm9 = int(bits[11:20], 2)
if imm9 & 0x100: imm9 -= 0x200
print(f"  → LDUR W8, [X23, #{imm9}]")

# Also check 0x4D984 function and callers more deeply
print(f"\n=== 0x4D984 function (yes/no helper) ===")
for addr in range(0x4D984, 0x4D9A0, 4):
    print(f"  0x{addr:05X}: {decode_insn(addr)}")

# Callers
print("\nCallers of 0x4D984:")
for i in range(0, TEXT_SIZE, 4):
    insn_val = struct.unpack_from('<I', code, i)[0]
    if (insn_val & 0xFC000000) == 0x94000000:
        off26 = insn_val & 0x03FFFFFF
        if off26 & (1 << 25): off26 -= (1 << 26)
        if i + off26 * 4 == 0x4D984:
            # Show context
            for ctx in range(max(i-16, 0), min(i+16, TEXT_SIZE), 4):
                print(f"  0x{ctx:05X}: {decode_insn(ctx)}{'  ←' if ctx == i else ''}")
            print()
