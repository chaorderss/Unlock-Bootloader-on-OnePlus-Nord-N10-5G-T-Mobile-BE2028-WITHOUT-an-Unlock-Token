#!/usr/bin/env python3
"""
完整解码 fastboot 变量注册区域，聚焦 unlocked 变量。
重点区域:
1. 0x4C080-0x4C180: IsDeviceUnlocked → 0x4D9DC/0x4D954 调用
2. 0x48480-0x484D0: IsDeviceUnlocked → AVB state 设置
3. 0x4D818 函数分析: FastbootPublishVar
"""
import struct

PE32 = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
TEXT_SIZE = 0x6A000

with open(PE32, "rb") as f:
    pe = f.read()

code = pe[:TEXT_SIZE]

def resolve_adrp_add(code, addr, pe_data):
    """Try to resolve ADRP at addr + ADD at addr+4"""
    if addr + 8 > len(code):
        return None, None
    insn1 = struct.unpack_from('<I', code, addr)[0]
    insn2 = struct.unpack_from('<I', code, addr + 4)[0]
    if (insn1 & 0x9F000000) != 0x90000000:
        return None, None
    rd1 = insn1 & 0x1f
    immlo = (insn1 >> 29) & 3; immhi = (insn1 >> 5) & 0x7ffff
    imm = (immhi << 2) | immlo
    if imm & (1 << 20): imm -= (1 << 21)
    page = (addr & ~0xFFF) + (imm << 12)
    if (insn2 & 0xFFC00000) == 0x91000000:
        add_rn = (insn2 >> 5) & 0x1f
        add_rd = insn2 & 0x1f
        if add_rn == rd1:
            add_imm = (insn2 >> 10) & 0xFFF
            target = page + add_imm
            s = None
            if 0 <= target < len(pe_data):
                try:
                    end = pe_data.index(0, target, min(target+80, len(pe_data)))
                    s = pe_data[target:end].decode('ascii', errors='replace')
                    if not s.isprintable(): s = None
                except: pass
            return target, s
    return None, None

def full_decode(code, i, pe_data):
    """Full decode of one instruction with context"""
    insn = struct.unpack_from('<I', code, i)[0]
    cond_names = {0:'EQ',1:'NE',2:'CS',3:'CC',4:'MI',5:'PL',6:'VS',7:'VC',
                  8:'HI',9:'LS',10:'GE',11:'LT',12:'GT',13:'LE',14:'AL'}

    # ADRP
    if (insn & 0x9F000000) == 0x90000000:
        rd = insn & 0x1f
        immlo = (insn >> 29) & 3; immhi = (insn >> 5) & 0x7ffff
        imm = (immhi << 2) | immlo
        if imm & (1 << 20): imm -= (1 << 21)
        page = (i & ~0xFFF) + (imm << 12)
        return f"adrp x{rd}, 0x{page:X}"
    # ADD imm
    if (insn & 0xFFC00000) == 0x91000000:
        rd = insn & 0x1f; rn = (insn >> 5) & 0x1f; imm12 = (insn >> 10) & 0xFFF
        tgt, s = resolve_adrp_add(code, i-4, pe_data)
        extra = f"  → '{s}'" if s else (f"  → 0x{tgt:06X}" if tgt else "")
        return f"add x{rd}, x{rn}, #0x{imm12:X}{extra}"
    # SUB imm
    if (insn & 0xFFC00000) == 0xD1000000:
        rd = insn & 0x1f; rn = (insn >> 5) & 0x1f; imm12 = (insn >> 10) & 0xFFF
        return f"sub x{rd}, x{rn}, #0x{imm12:X}"
    # BL
    if (insn & 0xFC000000) == 0x94000000:
        off26 = insn & 0x03FFFFFF
        if off26 & (1 << 25): off26 -= (1 << 26)
        return f"bl 0x{i + off26*4:05X}"
    # B
    if (insn & 0xFC000000) == 0x14000000:
        off26 = insn & 0x03FFFFFF
        if off26 & (1 << 25): off26 -= (1 << 26)
        return f"b 0x{i + off26*4:05X}"
    # B.cond
    if (insn & 0xFE000000) == 0x54000000:
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1 << 18): imm19 -= (1 << 19)
        cond = insn & 0xf
        return f"b.{cond_names.get(cond,'?')} 0x{i + imm19*4:05X}"
    # CBZ/CBNZ
    if (insn & 0xFF000000) in (0x34000000, 0x35000000):
        rt = insn & 0x1f; imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1 << 18): imm19 -= (1 << 19)
        op = "cbnz" if insn & 0x01000000 else "cbz"
        sf = "x" if insn & 0x80000000 else "w"
        return f"{op} {sf}{rt}, 0x{i + imm19*4:05X}"
    # LDRB
    if (insn & 0xFFC00000) == 0x39400000:
        rt = insn & 0x1f; rn = (insn >> 5) & 0x1f; imm12 = (insn >> 10) & 0xFFF
        return f"ldrb w{rt}, [x{rn}, #{imm12}]"
    # LDR (64-bit unsigned offset)
    if (insn & 0xFFC00000) == 0xF9400000:
        rt = insn & 0x1f; rn = (insn >> 5) & 0x1f; imm12 = (insn >> 10) & 0xFFF
        return f"ldr x{rt}, [x{rn}, #0x{imm12*8:X}]"
    # LDR (32-bit unsigned offset)
    if (insn & 0xFFC00000) == 0xB9400000:
        rt = insn & 0x1f; rn = (insn >> 5) & 0x1f; imm12 = (insn >> 10) & 0xFFF
        return f"ldr w{rt}, [x{rn}, #0x{imm12*4:X}]"
    # STR (64-bit)
    if (insn & 0xFFC00000) == 0xF9000000:
        rt = insn & 0x1f; rn = (insn >> 5) & 0x1f; imm12 = (insn >> 10) & 0xFFF
        return f"str x{rt}, [x{rn}, #0x{imm12*8:X}]"
    # STRB
    if (insn & 0xFFC00000) == 0x39000000:
        rt = insn & 0x1f; rn = (insn >> 5) & 0x1f; imm12 = (insn >> 10) & 0xFFF
        return f"strb w{rt}, [x{rn}, #{imm12}]"
    # STP (pre-index)
    if (insn & 0x7FC00000) == 0x29800000 or (insn & 0x7FC00000) == 0xA9800000:
        return "stp ..."
    # LDP
    if (insn & 0x7FC00000) == 0x28C00000 or (insn & 0x7FC00000) == 0xA8C00000:
        return "ldp ..."
    # MOV (ORR)
    if (insn & 0xFF200000) == 0xAA000000:
        rd = insn & 0x1f; rn = (insn >> 5) & 0x1f; rm = (insn >> 16) & 0x1f
        if rn == 31: return f"mov x{rd}, x{rm}"
        return f"orr x{rd}, x{rn}, x{rm}"
    # MOVZ
    if (insn & 0xFF800000) == 0xD2800000:
        rd = insn & 0x1f; imm16 = (insn >> 5) & 0xFFFF; hw = (insn >> 21) & 3
        return f"mov x{rd}, #0x{imm16 << (hw*16):X}"
    if (insn & 0xFF800000) == 0x52800000:
        rd = insn & 0x1f; imm16 = (insn >> 5) & 0xFFFF; hw = (insn >> 21) & 3
        return f"mov w{rd}, #0x{imm16 << (hw*16):X}"
    # CSEL family
    if (insn & 0xFE000000) == 0x9A000000 or (insn & 0xFE000000) == 0x1A000000:
        sf = "x" if (insn >> 31) else "w"
        rd = insn & 0x1f; rn = (insn >> 5) & 0x1f; rm = (insn >> 16) & 0x1f
        cond = (insn >> 12) & 0xf; op2 = (insn >> 10) & 3
        ops = {0:'csel',1:'csinc',2:'csinv',3:'csneg'}
        return f"{ops[op2]} {sf}{rd}, {sf}{rn}, {sf}{rm}, {cond_names.get(cond,'?')}"
    # TST (ANDS with Rd=xzr)
    if (insn & 0x7F80001F) == 0x7200001F or (insn & 0xFF80001F) == 0xF200001F:
        rn = (insn >> 5) & 0x1f
        sf = "x" if (insn >> 31) else "w"
        return f"tst {sf}{rn}, #imm"
    # CMP (SUBS with Rd=xzr)
    if (insn & 0x7F800000) == 0x71000000 or (insn & 0xFF800000) == 0xF1000000:
        rn = (insn >> 5) & 0x1f; imm12 = (insn >> 10) & 0xFFF
        sf = "x" if (insn >> 31) else "w"
        return f"cmp {sf}{rn}, #0x{imm12:X}"
    # RET
    if insn == 0xD65F03C0:
        return "ret"
    # NOP
    if insn == 0xD503201F:
        return "nop"

    return f".word 0x{insn:08X}"

# 1. Full decode 0x4BF00-0x4C200 (unlock var registration area)
print("=== 0x4BF00-0x4C200 完整解码 ===")
for i in range(0x4BF00, 0x4C200, 4):
    d = full_decode(code, i, pe)
    print(f"  0x{i:05X}: {d}")

# 2. Full decode 0x48480-0x484E0 (the area after off-mode-charge registration,
#    where IsDeviceUnlocked is called and AVB state is set)
print(f"\n=== 0x48470-0x48520 完整解码 (off-mode-charge → IsDeviceUnlocked) ===")
for i in range(0x48470, 0x48520, 4):
    d = full_decode(code, i, pe)
    print(f"  0x{i:05X}: {d}")

# 3. Check what 0x4D818 (FastbootPublishVar) does
print(f"\n=== 0x4D818 (FastbootPublishVar) 函数体 ===")
for i in range(0x4D818, 0x4D860, 4):
    d = full_decode(code, i, pe)
    print(f"  0x{i:05X}: {d}")

# 4. Check 0x4D954 - what's this function?
print(f"\n=== 0x4D954 函数体 ===")
for i in range(0x4D954, 0x4D9E0, 4):
    d = full_decode(code, i, pe)
    print(f"  0x{i:05X}: {d}")

# 5. Broader context: look for ALL calls to publish functions (0x4D818, 0x4D954, 0x4D9DC)
# in the range 0x46000-0x4D000
print(f"\n=== 所有 publish 函数调用 (0x46000-0x4D000) ===")
for i in range(0x46000, 0x4D000, 4):
    insn = struct.unpack_from('<I', code, i)[0]
    if (insn & 0xFC000000) == 0x94000000:
        off26 = insn & 0x03FFFFFF
        if off26 & (1 << 25): off26 -= (1 << 26)
        target = i + off26 * 4
        if target in (0x4D818, 0x4D954, 0x4D9DC, 0x4C850):
            # Find most recent string arg
            strings = []
            for back in range(i - 4, max(i - 80, 0x46000), -4):
                tgt, s = resolve_adrp_add(code, back, pe)
                if s:
                    insn2 = struct.unpack_from('<I', code, back + 4)[0]
                    rd = insn2 & 0x1f
                    strings.append(f"x{rd}='{s[:30]}'")
            info = ", ".join(strings[::-1][:3]) if strings else "?"
            print(f"  0x{i:05X}: bl 0x{target:05X}  [{info}]")
