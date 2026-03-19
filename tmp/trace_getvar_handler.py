#!/usr/bin/env python3
"""
从 "GetVar Variable Not found" 错误消息反向追踪 getvar handler。
找到 fastboot "unlocked" 变量的查找机制。
"""
import struct

PE32 = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
TEXT_SIZE = 0x6A000

with open(PE32, "rb") as f:
    pe = f.read()

code = pe[:TEXT_SIZE]

def decode_adrp_add_at(code, addr):
    if addr + 8 > len(code):
        return None
    insn1 = struct.unpack_from('<I', code, addr)[0]
    insn2 = struct.unpack_from('<I', code, addr + 4)[0]
    if (insn1 & 0x9F000000) != 0x90000000:
        return None
    rd1 = insn1 & 0x1f
    immlo = (insn1 >> 29) & 3
    immhi = (insn1 >> 5) & 0x7ffff
    imm = (immhi << 2) | immlo
    if imm & (1 << 20): imm -= (1 << 21)
    page = (addr & ~0xFFF) + (imm << 12)
    if (insn2 & 0xFFC00000) == 0x91000000:
        add_rn = (insn2 >> 5) & 0x1f
        if add_rn == rd1:
            add_imm = (insn2 >> 10) & 0xFFF
            return page + add_imm
    return None

def get_string_at(pe, addr):
    if 0 <= addr < len(pe):
        try:
            end = pe.index(0, addr, min(addr + 100, len(pe)))
            s = pe[addr:end].decode('ascii', errors='replace')
            if s.isprintable(): return s
        except: pass
    return None

def decode_insn(code, i, pe_data=None):
    """Decode a single instruction for display"""
    if i + 4 > len(code): return ""
    insn = struct.unpack_from('<I', code, i)[0]

    if (insn & 0x9F000000) == 0x90000000:
        rd = insn & 0x1f
        immlo = (insn >> 29) & 3; immhi = (insn >> 5) & 0x7ffff
        imm = (immhi << 2) | immlo
        if imm & (1 << 20): imm -= (1 << 21)
        page = (i & ~0xFFF) + (imm << 12)
        return f"adrp x{rd}, 0x{page:X}"
    elif (insn & 0xFFC00000) == 0x91000000:
        rd = insn & 0x1f; rn = (insn >> 5) & 0x1f; imm12 = (insn >> 10) & 0xFFF
        s = ""
        if pe_data:
            resolved = decode_adrp_add_at(code, i - 4)
            if resolved:
                s_str = get_string_at(pe_data, resolved)
                if s_str: s = f"  → '{s_str[:40]}'"
        return f"add x{rd}, x{rn}, #0x{imm12:X}{s}"
    elif (insn & 0xFC000000) == 0x94000000:
        off26 = insn & 0x03FFFFFF
        if off26 & (1 << 25): off26 -= (1 << 26)
        return f"bl 0x{i + off26 * 4:05X}"
    elif (insn & 0xFC000000) == 0x14000000:
        off26 = insn & 0x03FFFFFF
        if off26 & (1 << 25): off26 -= (1 << 26)
        return f"b 0x{i + off26 * 4:05X}"
    elif insn == 0xD65F03C0:
        return "ret"
    elif (insn & 0xFFC00000) == 0x39400000:
        rt = insn & 0x1f; rn = (insn >> 5) & 0x1f; imm12 = (insn >> 10) & 0xFFF
        return f"ldrb w{rt}, [x{rn}, #{imm12}]"
    elif (insn & 0xFFC00000) == 0xF9400000:
        rt = insn & 0x1f; rn = (insn >> 5) & 0x1f; imm12 = (insn >> 10) & 0xFFF
        return f"ldr x{rt}, [x{rn}, #0x{imm12*8:X}]"
    elif (insn & 0xFFC00000) == 0xB9400000:
        rt = insn & 0x1f; rn = (insn >> 5) & 0x1f; imm12 = (insn >> 10) & 0xFFF
        return f"ldr w{rt}, [x{rn}, #0x{imm12*4:X}]"
    elif (insn & 0xFF000000) == 0x35000000:
        rt = insn & 0x1f; imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1 << 18): imm19 -= (1 << 19)
        return f"cbnz w{rt}, 0x{i + imm19*4:05X}"
    elif (insn & 0xFF000000) == 0x34000000:
        rt = insn & 0x1f; imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1 << 18): imm19 -= (1 << 19)
        return f"cbz w{rt}, 0x{i + imm19*4:05X}"
    elif (insn & 0x7FE0FC00) == 0x6B00001F:
        rn = (insn >> 5) & 0x1f; rm = (insn >> 16) & 0x1f
        return f"cmp w{rn}, w{rm}"
    elif (insn & 0x7F800000) == 0x71000000:
        rn = (insn >> 5) & 0x1f; imm12 = (insn >> 10) & 0xFFF
        return f"cmp w{rn}, #0x{imm12:X}"
    elif (insn & 0xFFE0001F) == 0x7200001F:
        rn = (insn >> 5) & 0x1f
        immr = (insn >> 16) & 0x3f; imms = (insn >> 10) & 0x3f
        return f"tst w{rn}, #<bitmask r={immr} s={imms}>"
    elif (insn & 0xFE000000) == 0x54000000:
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1 << 18): imm19 -= (1 << 19)
        cond = insn & 0xf
        cond_names = {0:'EQ',1:'NE',2:'CS',3:'CC',4:'MI',5:'PL',6:'VS',7:'VC',
                      8:'HI',9:'LS',10:'GE',11:'LT',12:'GT',13:'LE',14:'AL'}
        return f"b.{cond_names.get(cond,'?')} 0x{i + imm19*4:05X}"
    elif (insn & 0xFF200C00) == 0x9A800000:
        rd = insn & 0x1f; rn = (insn >> 5) & 0x1f; rm = (insn >> 16) & 0x1f
        cond = (insn >> 12) & 0xf; op2 = (insn >> 10) & 3
        cond_names = {0:'EQ',1:'NE',2:'CS',3:'CC',4:'MI',5:'PL',6:'VS',7:'VC',
                      8:'HI',9:'LS',10:'GE',11:'LT',12:'GT',13:'LE',14:'AL'}
        ops = {0:'csel',1:'csinc',2:'csinv',3:'csneg'}
        return f"{ops.get(op2,'csel?')} x{rd}, x{rn}, x{rm}, {cond_names.get(cond,'?')}"
    return f"0x{insn:08X}"

# 1. Find "GetVar Variable Not found" reference
print("=== 'GetVar Variable Not found' 字符串追踪 ===")
off = pe.find(b"GetVar Variable Not found")
if off is None:
    off = pe.find(b"Variable Not found")
print(f"  字符串在 0x{off:06X}")

# Find ADRP+ADD references
target_page = off & ~0xFFF
target_off = off & 0xFFF
refs = []
for i in range(0, TEXT_SIZE - 8, 4):
    res = decode_adrp_add_at(code, i)
    if res == off:
        refs.append(i)
        print(f"  引用在 0x{i:05X}")

# 2. For each ref, show broad function context
for ref in refs:
    print(f"\n=== GetVar handler context (ref at 0x{ref:05X}) ===")
    # Find function start: look back for STP x29,x30
    func_start = ref
    for back in range(ref - 4, max(ref - 400, 0), -4):
        insn = struct.unpack_from('<I', code, back)[0]
        if (insn & 0xFFFF8000) == 0xA9800000 or (insn & 0xFFC003E0) == 0xA98003E0:
            # STP with pre-index addressing (function prologue)
            func_start = back
            break
        # Also check for STP xN, xM, [sp, #imm]!
        if (insn & 0x7FC00000) == 0x29800000:
            func_start = back
            break

    # Find function end
    func_end = ref + 200
    for fwd in range(ref + 4, min(ref + 600, TEXT_SIZE), 4):
        insn = struct.unpack_from('<I', code, fwd)[0]
        if insn == 0xD65F03C0:
            func_end = fwd + 4
            break

    print(f"  Function: 0x{func_start:05X} - 0x{func_end:05X}")
    for addr in range(func_start, func_end, 4):
        d = decode_insn(code, addr, pe)
        marker = " <<<" if addr == ref else ""
        print(f"    0x{addr:05X}: {d}{marker}")

# 3. Search for where "unlocked" (0x051DB0) is loaded via LDR from pointer
# Maybe the string is accessed indirectly through a table
print(f"\n=== 搜索 'Unlocked'/'Locked' 的间接引用 ===")
# Check if 0x051DB0 or 0x051DB7 appear as pointers in the data section
for tgt_addr, name in [(0x051DB0, "Unlocked"), (0x051DB7, "Locked"), (0x051DAE, "Unlocked-2")]:
    # Search as 8-byte pointer
    needle = struct.pack('<Q', tgt_addr)
    for pos in range(0, len(pe) - 8, 8):
        if pe[pos:pos+8] == needle:
            print(f"  {name}: 64-bit ptr at 0x{pos:06X}")

# 4. Search for the "unlocked" fastboot var in a completely different way:
# Look for the function that compares against string "unlocked" using strncmp/strcmp
# In fastboot getvar handler, it would do:
#   if (strncmp(var_name, "unlocked", 8) == 0) ...
# The string comparison function would be called with "unlocked" as one arg
#
# Alternative: look for function at 0x4D818 (FastbootPublishVar) callers more carefully
# Maybe "unlocked" is published BEFORE 0x48334 or elsewhere

# 5. Dump the full initialization sequence 0x48200-0x48500
print(f"\n=== FastBoot 变量注册区域 0x48200-0x48550 ===")
for addr in range(0x48200, 0x48550, 4):
    d = decode_insn(code, addr, pe)
    if 'bl 0x4D818' in d or 'bl 0x4D954' in d or 'bl 0x4D9DC' in d or 'bl 0x22C18' in d:
        print(f"  * 0x{addr:05X}: {d}")
    elif "→ '" in d:
        print(f"    0x{addr:05X}: {d}")

# 6. Check the code BEFORE the variant registration (0x48334)
# The unlocked var might be registered even earlier
print(f"\n=== 0x48100-0x48350 (registration 之前) ===")
for addr in range(0x48100, 0x48350, 4):
    d = decode_insn(code, addr, pe)
    if 'bl 0x4D' in d or 'bl 0x22C' in d or "→ '" in d or 'ret' in d:
        print(f"    0x{addr:05X}: {d}")
