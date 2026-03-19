#!/usr/bin/env python3
"""
关键追踪：
1. 解码 0x38490（OemCheckResetDevInfo 的 0x365C4 路径调用的函数）
2. 找 0x3C328（第3个 init_defaults 调用者）的所有调用者
3. 解码 0x4FD10（ReadDeviceInfo 中的 magic 比较函数）
4. 追踪 ReadDeviceInfo 完整函数入口和调用链
5. 搜索所有 strb w*, [x*, #13] 并过滤写入 devinfo 缓冲区的
"""
import struct

PE32 = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
TEXT_SIZE = 0x6A000

with open(PE32, "rb") as f:
    pe = f.read()
code = pe[:TEXT_SIZE]

def decode(addr):
    if addr < 0 or addr + 4 > TEXT_SIZE:
        return f"OUT_OF_RANGE"
    insn = struct.unpack_from('<I', code, addr)[0]
    if insn == 0xD65F03C0: return "ret"
    if insn == 0xD503201F: return "nop"
    if insn == 0: return ".word 0"

    # BL / B / B.cond / CBZ / CBNZ / TBZ / TBNZ
    if (insn & 0xFC000000) == 0x94000000:
        off = insn & 0x03FFFFFF
        if off & (1<<25): off -= (1<<26)
        return f"bl 0x{addr+off*4:05X}"
    if (insn & 0xFC000000) == 0x14000000:
        off = insn & 0x03FFFFFF
        if off & (1<<25): off -= (1<<26)
        return f"b 0x{addr+off*4:05X}"
    if (insn & 0xFF000010) == 0x54000000:
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1<<18): imm19 -= (1<<19)
        cc = {0:'EQ',1:'NE',2:'CS',3:'CC',4:'MI',5:'PL',6:'VS',7:'VC',8:'HI',9:'LS',10:'GE',11:'LT',12:'GT',13:'LE'}.get(insn&0xf,'?')
        return f"b.{cc} 0x{addr+imm19*4:05X}"
    if (insn & 0x7E000000) == 0x34000000:
        sf="x" if (insn>>31) else "w"
        op="cbnz" if (insn>>24)&1 else "cbz"
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1<<18): imm19 -= (1<<19)
        return f"{op} {sf}{insn&0x1f}, 0x{addr+imm19*4:05X}"
    if (insn & 0x7E000000) == 0x36000000:
        op="tbnz" if (insn>>24)&1 else "tbz"
        bit = ((insn>>31)<<5)|((insn>>19)&0x1f)
        imm14 = (insn >> 5) & 0x3FFF
        if imm14 & (1<<13): imm14 -= (1<<14)
        return f"{op} x{insn&0x1f}, #{bit}, 0x{addr+imm14*4:05X}"

    # ADRP / ADR
    if (insn & 0x9F000000) == 0x90000000:
        rd = insn & 0x1f
        immlo = (insn>>29)&3; immhi = (insn>>5)&0x7ffff
        imm = (immhi<<2)|immlo
        if imm & (1<<20): imm -= (1<<21)
        pg = (addr & ~0xFFF) + (imm << 12)
        return f"adrp x{rd}, 0x{pg:X}"
    if (insn & 0x9F000000) == 0x10000000:
        rd = insn & 0x1f
        immlo = (insn>>29)&3; immhi = (insn>>5)&0x7ffff
        imm = (immhi<<2)|immlo
        if imm & (1<<20): imm -= (1<<21)
        return f"adr x{rd}, 0x{addr+imm:X}"

    # ADD/SUB imm (64-bit)
    if (insn & 0xFF000000) == 0x91000000:
        return f"add x{insn&0x1f}, x{(insn>>5)&0x1f}, #0x{(insn>>10)&0xFFF:X}"
    if (insn & 0xFF000000) == 0xD1000000:
        return f"sub x{insn&0x1f}, x{(insn>>5)&0x1f}, #0x{(insn>>10)&0xFFF:X}"
    # ADD/SUB imm (32-bit)
    if (insn & 0xFF000000) == 0x11000000:
        return f"add w{insn&0x1f}, w{(insn>>5)&0x1f}, #0x{(insn>>10)&0xFFF:X}"
    if (insn & 0xFF000000) == 0x51000000:
        return f"sub w{insn&0x1f}, w{(insn>>5)&0x1f}, #0x{(insn>>10)&0xFFF:X}"

    # MOV wide
    if (insn & 0xFF800000) == 0x52800000:
        rd = insn&0x1f; imm16 = (insn>>5)&0xFFFF
        return f"mov w{rd}, #0x{imm16:X} ({imm16})"
    if (insn & 0xFF800000) == 0xD2800000:
        rd = insn&0x1f; imm16 = (insn>>5)&0xFFFF
        return f"mov x{rd}, #0x{imm16:X}"

    # MOV register
    if (insn & 0xFFE0FFE0) == 0xAA0003E0:
        return f"mov x{insn&0x1f}, x{(insn>>16)&0x1f}"
    if (insn & 0xFFE0FFE0) == 0x2A0003E0:
        return f"mov w{insn&0x1f}, w{(insn>>16)&0x1f}"

    # ORR imm (mov bitmask)
    if (insn & 0xFF800000) == 0x32000000:
        rd = insn&0x1f; rn = (insn>>5)&0x1f
        N = (insn>>22)&1; immr = (insn>>16)&0x3f; imms = (insn>>10)&0x3f
        # Decode 32-bit bitmask
        val = decode_bitmask_imm(N, imms, immr, 32)
        if rn == 31:
            return f"mov w{rd}, #0x{val:X} ({val})"
        return f"orr w{rd}, w{rn}, #0x{val:X}"
    if (insn & 0xFF800000) == 0xB2000000:
        rd = insn&0x1f; rn = (insn>>5)&0x1f
        N = (insn>>22)&1; immr = (insn>>16)&0x3f; imms = (insn>>10)&0x3f
        val = decode_bitmask_imm(N, imms, immr, 64)
        if rn == 31:
            return f"mov x{rd}, #0x{val:X}"
        return f"orr x{rd}, x{rn}, #0x{val:X}"

    # AND imm
    if (insn & 0xFF800000) == 0x12000000:
        rd = insn&0x1f; rn = (insn>>5)&0x1f
        N = (insn>>22)&1; immr = (insn>>16)&0x3f; imms = (insn>>10)&0x3f
        val = decode_bitmask_imm(N, imms, immr, 32)
        return f"and w{rd}, w{rn}, #0x{val:X}"

    # TST (ANDS Xzr)
    if (insn & 0x7F80001F) == 0x7200001F:
        rn = (insn>>5)&0x1f
        N = (insn>>22)&1; immr = (insn>>16)&0x3f; imms = (insn>>10)&0x3f
        val = decode_bitmask_imm(N, imms, immr, 32)
        return f"tst w{rn}, #0x{val:X}"

    # CMP imm
    if (insn & 0xFF80001F) == 0x7100001F:
        return f"cmp w{(insn>>5)&0x1f}, #{(insn>>10)&0xFFF}"
    if (insn & 0xFF80001F) == 0xF100001F:
        return f"cmp x{(insn>>5)&0x1f}, #{(insn>>10)&0xFFF}"
    # CMP reg
    if (insn & 0xFFE0FC1F) == 0x6B00001F:
        return f"cmp w{(insn>>5)&0x1f}, w{(insn>>16)&0x1f}"

    # STRB/LDRB unsigned
    if (insn & 0xFFC00000) == 0x39000000:
        return f"strb w{insn&0x1f}, [x{(insn>>5)&0x1f}, #{(insn>>10)&0xFFF}]"
    if (insn & 0xFFC00000) == 0x39400000:
        return f"ldrb w{insn&0x1f}, [x{(insn>>5)&0x1f}, #{(insn>>10)&0xFFF}]"

    # STR/LDR 32/64 unsigned
    if (insn & 0xFFC00000) == 0xB9000000:
        return f"str w{insn&0x1f}, [x{(insn>>5)&0x1f}, #{((insn>>10)&0xFFF)*4}]"
    if (insn & 0xFFC00000) == 0xB9400000:
        return f"ldr w{insn&0x1f}, [x{(insn>>5)&0x1f}, #{((insn>>10)&0xFFF)*4}]"
    if (insn & 0xFFC00000) == 0xF9000000:
        return f"str x{insn&0x1f}, [x{(insn>>5)&0x1f}, #{((insn>>10)&0xFFF)*8}]"
    if (insn & 0xFFC00000) == 0xF9400000:
        return f"ldr x{insn&0x1f}, [x{(insn>>5)&0x1f}, #{((insn>>10)&0xFFF)*8}]"

    # STUR/LDUR
    if (insn & 0xFFE00C00) == 0xB8000000:
        imm9 = (insn>>12)&0x1FF
        if imm9 & 0x100: imm9 -= 0x200
        return f"stur w{insn&0x1f}, [x{(insn>>5)&0x1f}, #{imm9}]"
    if (insn & 0xFFE00C00) == 0xB8400000:
        imm9 = (insn>>12)&0x1FF
        if imm9 & 0x100: imm9 -= 0x200
        return f"ldur w{insn&0x1f}, [x{(insn>>5)&0x1f}, #{imm9}]"
    if (insn & 0xFFE00C00) == 0xF8000000:
        imm9 = (insn>>12)&0x1FF
        if imm9 & 0x100: imm9 -= 0x200
        return f"stur x{insn&0x1f}, [x{(insn>>5)&0x1f}, #{imm9}]"
    if (insn & 0xFFE00C00) == 0xF8400000:
        imm9 = (insn>>12)&0x1FF
        if imm9 & 0x100: imm9 -= 0x200
        return f"ldur x{insn&0x1f}, [x{(insn>>5)&0x1f}, #{imm9}]"

    # STP pre-index
    if (insn & 0xFFC00000) == 0xA9800000:
        rt=insn&0x1f; rt2=(insn>>10)&0x1f; rn=(insn>>5)&0x1f
        imm7 = (insn>>15)&0x7f
        if imm7 & 0x40: imm7 -= 128
        return f"stp x{rt}, x{rt2}, [x{rn}, #{imm7*8}]!"
    # STP signed offset
    if (insn & 0xFFC00000) == 0xA9000000:
        rt=insn&0x1f; rt2=(insn>>10)&0x1f; rn=(insn>>5)&0x1f
        imm7 = (insn>>15)&0x7f
        if imm7 & 0x40: imm7 -= 128
        return f"stp x{rt}, x{rt2}, [x{rn}, #{imm7*8}]"
    # LDP post-index
    if (insn & 0xFFC00000) == 0xA8C00000:
        rt=insn&0x1f; rt2=(insn>>10)&0x1f; rn=(insn>>5)&0x1f
        imm7 = (insn>>15)&0x7f
        if imm7 & 0x40: imm7 -= 128
        return f"ldp x{rt}, x{rt2}, [x{rn}], #{imm7*8}"

    # STR/LDR pre-index (with !)
    if (insn & 0xFFE00C00) == 0xF8000C00:
        imm9 = (insn>>12)&0x1FF
        if imm9 & 0x100: imm9 -= 0x200
        return f"str x{insn&0x1f}, [x{(insn>>5)&0x1f}, #{imm9}]!"
    if (insn & 0xFFE00C00) == 0xF8400C00:
        imm9 = (insn>>12)&0x1FF
        if imm9 & 0x100: imm9 -= 0x200
        return f"ldr x{insn&0x1f}, [x{(insn>>5)&0x1f}, #{imm9}]!"

    # BLR/BR
    if (insn & 0xFFFFFC1F) == 0xD63F0000:
        return f"blr x{(insn>>5)&0x1f}"
    if (insn & 0xFFFFFC1F) == 0xD61F0000:
        return f"br x{(insn>>5)&0x1f}"

    # CSEL/CSINC/CSINV/CSNEG
    if (insn & 0x7FE00000) in (0x1A800000, 0x5A800000):
        sf = "x" if (insn>>31) else "w"
        ops = {0:'csel',1:'csinc',2:'csinv',3:'csneg'}
        op2 = ((insn>>30)&1)<<1|((insn>>10)&1)
        rm=(insn>>16)&0x1f; cond=(insn>>12)&0xf; rn=(insn>>5)&0x1f; rd=insn&0x1f
        cc = {0:'EQ',1:'NE',2:'CS',3:'CC',4:'MI',5:'PL',8:'HI',9:'LS',10:'GE',11:'LT',12:'GT',13:'LE'}.get(cond,f'c{cond}')
        if op2 == 1 and rn == 31 and rm == 31:
            return f"cset {sf}{rd}, {cc}" if cond&1==0 else f"cset {sf}{rd}, {cc}"
        return f"{ops.get(op2,'?')} {sf}{rd}, {sf}{rn}, {sf}{rm}, {cc}"

    # STP variants (wider catch)
    if (insn & 0x7FC00000) in (0x29000000, 0x29800000, 0x28C00000):
        sf = 8 if (insn>>31) else 4
        rt=insn&0x1f; rt2=(insn>>10)&0x1f; rn=(insn>>5)&0x1f
        imm7=(insn>>15)&0x7f
        if imm7 & 0x40: imm7 -= 128
        r = "x" if sf == 8 else "w"
        opc = (insn>>22) & 0x7
        if opc in (6,7): # pre-index
            return f"stp {r}{rt}, {r}{rt2}, [x{rn}, #{imm7*sf}]!"
        elif opc in (2,3): # post-index
            return f"ldp {r}{rt}, {r}{rt2}, [x{rn}], #{imm7*sf}"
        else: # signed offset
            return f"stp {r}{rt}, {r}{rt2}, [x{rn}, #{imm7*sf}]"

    return f"0x{insn:08X}"

def decode_bitmask_imm(N, imms, immr, bitsize):
    """Decode AArch64 bitmask immediate"""
    if N == 1:
        esize = 64
    else:
        esize = 32
        while esize > 2:
            if (imms & (esize-1)) != imms:
                break
            esize >>= 1
        # Find the element size by looking at the highest clear bit in imms
        # Simplified: just handle common cases
        esize = 64 if N else 32

    # Simple cases for 32-bit
    if bitsize == 32 and N == 0:
        welem = (1 << (imms + 1)) - 1
        welem = ((welem >> immr) | (welem << (32 - immr))) & 0xFFFFFFFF
        return welem
    elif bitsize == 64 and N == 1:
        welem = (1 << (imms + 1)) - 1
        welem = ((welem >> immr) | (welem << (64 - immr))) & 0xFFFFFFFFFFFFFFFF
        return welem
    # Fallback
    return 0xDEAD

def find_bl_to(target):
    callers = []
    for i in range(0, TEXT_SIZE, 4):
        insn = struct.unpack_from('<I', code, i)[0]
        if (insn & 0xFC000000) == 0x94000000:
            off = insn & 0x03FFFFFF
            if off & (1<<25): off -= (1<<26)
            if i + off*4 == target:
                callers.append(i)
    return callers

def find_b_to(target):
    callers = []
    for i in range(0, TEXT_SIZE, 4):
        insn = struct.unpack_from('<I', code, i)[0]
        if (insn & 0xFC000000) == 0x14000000:
            off = insn & 0x03FFFFFF
            if off & (1<<25): off -= (1<<26)
            if i + off*4 == target:
                callers.append(i)
    return callers

# ==========================================
print("=" * 60)
print("=== 1. 解码 0x38490 函数 ===")
print("=" * 60)
for a in range(0x38490, 0x384D0, 4):
    d = decode(a)
    print(f"  0x{a:05X}: {d}")
    if d == "ret" or (d.startswith("b ") and "0x384" not in d):
        break

# ==========================================
print(f"\n{'='*60}")
print("=== 2. 找 0x3C328 的所有调用者 ===")
print("=" * 60)
callers_bl = find_bl_to(0x3C328)
callers_b = find_b_to(0x3C328)
print(f"  BL callers: {[f'0x{c:05X}' for c in callers_bl]}")
print(f"  B callers:  {[f'0x{c:05X}' for c in callers_b]}")
if not callers_bl and not callers_b:
    print("  NO direct callers! → called via function pointer")
    # Search in data section for pointer
    for off in range(TEXT_SIZE, len(pe)-8, 8):
        val = struct.unpack_from('<Q', pe, off)[0]
        if val == 0x3C328:
            print(f"  Found pointer at data offset 0x{off:05X}")
            for d in range(-24, 32, 8):
                if off+d >= 0 and off+d+8 <= len(pe):
                    v = struct.unpack_from('<Q', pe, off+d)[0]
                    if 0 < v < 0x200000:
                        mark = " <<<" if d == 0 else ""
                        print(f"    [0x{off+d:05X}] = 0x{v:05X}{mark}")

# ==========================================
print(f"\n{'='*60}")
print("=== 3. 解码 0x4FD10 函数 (magic compare) ===")
print("=" * 60)
for a in range(0x4FD10, min(0x4FD80, TEXT_SIZE), 4):
    d = decode(a)
    print(f"  0x{a:05X}: {d}")
    if d == "ret":
        break

# ==========================================
print(f"\n{'='*60}")
print("=== 4. ReadDeviceInfo 完整函数 (从入口到 return) ===")
print("=" * 60)
# Find the function entry - search backwards from 0x23300 for prologue/ret
func_start = None
for a in range(0x23300, 0x22C00, -4):
    d = decode(a)
    if d == "ret" or d == ".word 0":
        func_start = a + 4
        print(f"  Function entry (after {d}) at 0x{func_start:05X}")
        break

if func_start:
    for a in range(func_start, min(func_start + 0x200, TEXT_SIZE), 4):
        d = decode(a)
        mark = ""
        if a == 0x23358: mark = "  ← magic compare"
        elif a == 0x2335C: mark = "  ← cbz = skip init_defaults if match"
        elif a == 0x23390: mark = "  ← init_defaults(0) !!!"
        elif "0x4FD10" in d: mark = "  ← compare function"
        elif "0x384D0" in d: mark = "  ← init_defaults"
        elif "0x22C18" in d: mark = "  ← IsDeviceUnlocked"
        elif d == "ret": mark = "  ← RETURN"
        print(f"  0x{a:05X}: {d}{mark}")
        if d == "ret":
            break

# ==========================================
print(f"\n{'='*60}")
print("=== 5. 找 ReadDeviceInfo 的调用者 ===")
print("=" * 60)
if func_start:
    callers = find_bl_to(func_start)
    print(f"  ReadDeviceInfo at 0x{func_start:05X} callers: {[f'0x{c:05X}' for c in callers]}")
    for c in callers:
        print(f"\n  Caller context at 0x{c:05X}:")
        for ctx in range(max(c-24, 0), min(c+24, TEXT_SIZE), 4):
            print(f"    0x{ctx:05X}: {decode(ctx)}")

# ==========================================
print(f"\n{'='*60}")
print("=== 6. init_defaults 0x384D0 完整代码 ===")
print("=" * 60)
for a in range(0x384D0, 0x38600, 4):
    d = decode(a)
    mark = ""
    if "0x189E0" in d: mark = "  ← IsSecureBootEnabled()"
    elif "strb" in d and "#13" in d: mark = "  ← is_unlocked = w9"
    elif "strb" in d and "#14" in d: mark = "  ← is_unlock_critical = w9"
    elif "strb" in d and "#15" in d: mark = "  ← charger_screen = w8"
    elif "strb" in d and "#144" in d: mark = "  ← verity_mode = w8"
    elif d == "ret": mark = "  ← RETURN"
    print(f"  0x{a:05X}: {d}{mark}")
    if d == "ret":
        break

# ==========================================
print(f"\n{'='*60}")
print("=== 7. 搜索所有 OemCheckResetDevInfo/0x362D0 的调用者(包括间接) ===")
print("=" * 60)
callers_362d0 = find_bl_to(0x362D0)
callers_b_362d0 = find_b_to(0x362D0)
print(f"  BL callers: {[f'0x{c:05X}' for c in callers_362d0]}")
print(f"  B callers:  {[f'0x{c:05X}' for c in callers_b_362d0]}")
# search data section
for off in range(TEXT_SIZE, len(pe)-8, 8):
    val = struct.unpack_from('<Q', pe, off)[0]
    if val == 0x362D0:
        print(f"  Pointer at data 0x{off:05X}")
        for d in range(-24, 32, 8):
            if off+d >= 0 and off+d+8 <= len(pe):
                v = struct.unpack_from('<Q', pe, off+d)[0]
                if 0 < v < 0x200000:
                    mark = " <<<" if d == 0 else ""
                    print(f"    [0x{off+d:05X}] = 0x{v:05X}{mark}")

# ==========================================
print(f"\n{'='*60}")
print("=== 8. 关键字符串 ===")
print("=" * 60)
for saddr in [0x5BF06, 0x564EB, 0x5AA0F]:
    if saddr < len(pe):
        end = saddr
        while end < min(saddr + 80, len(pe)) and pe[end] != 0:
            end += 1
        s = pe[saddr:end]
        print(f"  0x{saddr:05X}: \"{s.decode('utf-8', errors='replace')}\"")

# ==========================================
print(f"\n{'='*60}")
print("=== 9. init_defaults 的 w20 参数使用情况 ===")
print("=" * 60)
# Check if w20 is used AFTER the strb sequence
print("  Checking if w20 (saved from parameter w0) affects execution...")
for a in range(0x38540, 0x38600, 4):
    insn = struct.unpack_from('<I', code, a)[0]
    d = decode(a)
    # Check if w20 appears
    if 'w20' in d or 'x20' in d:
        print(f"  0x{a:05X}: {d}  ← uses w20!")
    else:
        print(f"  0x{a:05X}: {d}")
    if d == "ret":
        break
