#!/usr/bin/env python3
"""
关键追踪:
1. 解码 0x634A0 处的函数指针表 — 找到调用 0x3C328 的 OEM 命令名
2. 解码 0x367F0（boot sequence 中 ReadDeviceInfo 后立即调用的函数）
3. 确定 0x362D0 是否被 0x367F0 包含或调用
4. 搜索 0x362D0 在整个二进制中的引用
"""
import struct

PE32 = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
TEXT_SIZE = 0x6A000

with open(PE32, "rb") as f:
    pe = f.read()
code = pe[:TEXT_SIZE]

def read_string(addr, maxlen=80):
    if addr >= len(pe): return "(out of range)"
    end = addr
    while end < min(addr + maxlen, len(pe)) and pe[end] != 0:
        end += 1
    return pe[addr:end].decode('utf-8', errors='replace')

def decode_simple(addr):
    if addr < 0 or addr + 4 > TEXT_SIZE:
        return "OUT"
    insn = struct.unpack_from('<I', code, addr)[0]
    if insn == 0xD65F03C0: return "ret"
    if insn == 0xD503201F: return "nop"
    if insn == 0: return ".word 0"
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
        conds = {0:'EQ',1:'NE',2:'CS',3:'CC',4:'MI',5:'PL',6:'VS',7:'VC',8:'HI',9:'LS',10:'GE',11:'LT',12:'GT',13:'LE',14:'AL'}
        cc = conds.get(insn&0xf, f'c{insn&0xf}')
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
    if (insn & 0x9F000000) == 0x90000000:
        rd = insn & 0x1f
        immlo = (insn>>29)&3; immhi = (insn>>5)&0x7ffff
        imm = (immhi<<2)|immlo
        if imm & (1<<20): imm -= (1<<21)
        pg = (addr & ~0xFFF) + (imm << 12)
        return f"adrp x{rd}, 0x{pg:X}"
    if (insn & 0xFF000000) == 0x91000000:
        return f"add x{insn&0x1f}, x{(insn>>5)&0x1f}, #0x{(insn>>10)&0xFFF:X}"
    if (insn & 0xFF000000) == 0xD1000000:
        return f"sub x{insn&0x1f}, x{(insn>>5)&0x1f}, #0x{(insn>>10)&0xFFF:X}"
    if (insn & 0xFF800000) == 0x52800000:
        return f"mov w{insn&0x1f}, #0x{((insn>>5)&0xFFFF):X}"
    if (insn & 0xFF800000) == 0xD2800000:
        return f"mov x{insn&0x1f}, #0x{((insn>>5)&0xFFFF):X}"
    if (insn & 0xFFE0FFE0) == 0xAA0003E0:
        return f"mov x{insn&0x1f}, x{(insn>>16)&0x1f}"
    if (insn & 0xFFE0FFE0) == 0x2A0003E0:
        return f"mov w{insn&0x1f}, w{(insn>>16)&0x1f}"
    if (insn & 0xFFC00000) == 0x39000000:
        return f"strb w{insn&0x1f}, [x{(insn>>5)&0x1f}, #{(insn>>10)&0xFFF}]"
    if (insn & 0xFFC00000) == 0x39400000:
        return f"ldrb w{insn&0x1f}, [x{(insn>>5)&0x1f}, #{(insn>>10)&0xFFF}]"
    if (insn & 0xFFC00000) == 0xF9400000:
        return f"ldr x{insn&0x1f}, [x{(insn>>5)&0x1f}, #{((insn>>10)&0xFFF)*8}]"
    if (insn & 0xFFC00000) == 0xF9000000:
        return f"str x{insn&0x1f}, [x{(insn>>5)&0x1f}, #{((insn>>10)&0xFFF)*8}]"
    if (insn & 0xFFC00000) == 0xB9400000:
        return f"ldr w{insn&0x1f}, [x{(insn>>5)&0x1f}, #{((insn>>10)&0xFFF)*4}]"
    if (insn & 0xFFC00000) == 0xB9000000:
        return f"str w{insn&0x1f}, [x{(insn>>5)&0x1f}, #{((insn>>10)&0xFFF)*4}]"
    if (insn & 0xFF80001F) == 0x7100001F:
        return f"cmp w{(insn>>5)&0x1f}, #{(insn>>10)&0xFFF}"
    if (insn & 0xFF80001F) == 0xF100001F:
        return f"cmp x{(insn>>5)&0x1f}, #{(insn>>10)&0xFFF}"
    if (insn & 0xFFFFFC1F) == 0xD63F0000:
        return f"blr x{(insn>>5)&0x1f}"
    if (insn & 0xFFFFFC1F) == 0xD61F0000:
        return f"br x{(insn>>5)&0x1f}"
    return f"0x{insn:08X}"

# ==========================================
print("=" * 60)
print("=== 1. 函数指针/命令表 around 0x634A0 ===")
print("=" * 60)
print("  Pattern: {func_ptr, string_ptr} pairs")
# Dump wider range around the table
for off in range(0x63400, min(0x63600, len(pe)), 8):
    val = struct.unpack_from('<Q', pe, off)[0]
    info = ""
    if 0 < val < TEXT_SIZE:
        info = f" → CODE func at 0x{val:05X}"
    elif TEXT_SIZE <= val < len(pe):
        s = read_string(val)
        if s and len(s) > 1:
            info = f" → STRING \"{s}\""
    mark = " <<<" if off == 0x634A0 else ""
    if info:
        print(f"  0x{off:05X}: 0x{val:016X}{info}{mark}")

# ==========================================
print(f"\n{'='*60}")
print("=== 2. 解码 0x367F0 函数 (boot后立即调用) ===")
print("=" * 60)
# Find function start — search backward for ret
func_start = 0x367F0
for a in range(0x367F0, 0x36700, -4):
    d = decode_simple(a)
    if d == "ret" or d == ".word 0":
        func_start = a + 4
        break

print(f"  Function start: 0x{func_start:05X}")
bl_targets = set()
for a in range(func_start, min(func_start + 0x300, TEXT_SIZE), 4):
    d = decode_simple(a)
    mark = ""
    if "0x362D0" in d: mark = " ← OemCheckResetDevInfo!!!"
    elif "0x384D0" in d: mark = " ← init_defaults"
    elif "0x22C18" in d: mark = " ← IsDeviceUnlocked"
    elif "0x232D8" in d: mark = " ← ReadDeviceInfo"
    elif "0x3C328" in d: mark = " ← ResetDevInfo3"
    elif "0x18248" in d: mark = " ← ReadWriteDevInfo"
    elif "0x384B0" in d: mark = " ← SetIsUnlocked"
    elif "0x22CA8" in d: mark = " ← WriteDeviceInfo"
    if d.startswith("bl "):
        target = int(d.split("0x")[1], 16)
        bl_targets.add(target)
    print(f"  0x{a:05X}: {d}{mark}")
    if d == "ret":
        break

# ==========================================
print(f"\n{'='*60}")
print("=== 3. 搜索所有对 0x362D0 的引用 ===")
print("=" * 60)
# Search as BL
for i in range(0, TEXT_SIZE, 4):
    insn = struct.unpack_from('<I', code, i)[0]
    if (insn & 0xFC000000) == 0x94000000:
        off = insn & 0x03FFFFFF
        if off & (1<<25): off -= (1<<26)
        if i + off*4 == 0x362D0:
            print(f"  BL at 0x{i:05X}")
    if (insn & 0xFC000000) == 0x14000000:
        off = insn & 0x03FFFFFF
        if off & (1<<25): off -= (1<<26)
        if i + off*4 == 0x362D0:
            print(f"  B at 0x{i:05X}")

# Search as pointer in data
needle = struct.pack('<Q', 0x362D0)
pos = 0
while True:
    idx = pe.find(needle, pos)
    if idx == -1: break
    print(f"  Pointer at 0x{idx:05X}")
    pos = idx + 1

# Also search for address in ADRP computations
print("\n  Checking ADRP+ADD to 0x362D0:")
for i in range(0, TEXT_SIZE-4, 4):
    insn = struct.unpack_from('<I', code, i)[0]
    if (insn & 0x9F000000) == 0x90000000:  # ADRP
        rd = insn & 0x1f
        immlo = (insn>>29)&3; immhi = (insn>>5)&0x7ffff
        im = (immhi<<2)|immlo
        if im & (1<<20): im -= (1<<21)
        pg = (i & ~0xFFF) + (im << 12)
        if pg == (0x362D0 & ~0xFFF):  # same page
            # Check next instruction for ADD to complete address
            next_insn = struct.unpack_from('<I', code, i+4)[0]
            if (next_insn & 0xFF000000) == 0x91000000:
                nrd = next_insn & 0x1f
                nrn = (next_insn >> 5) & 0x1f
                nimm = (next_insn >> 10) & 0xFFF
                if nrn == rd and pg + nimm == 0x362D0:
                    print(f"  ADRP+ADD at 0x{i:05X}: x{rd} = 0x{pg+nimm:X}")

# ==========================================
print(f"\n{'='*60}")
print("=== 4. 0x367F0 调用的子函数 ===")
print("=" * 60)
for t in sorted(bl_targets):
    # Show first few instructions
    print(f"\n  Sub-function 0x{t:05X}:")
    for a in range(t, min(t+32, TEXT_SIZE), 4):
        d = decode_simple(a)
        mark = ""
        if "0x362D0" in d: mark = " ← calls OemCheckResetDevInfo!"
        elif "0x384D0" in d: mark = " ← calls init_defaults!"
        elif "0x22C18" in d: mark = " ← calls IsDeviceUnlocked!"
        elif "0x384B0" in d: mark = " ← calls SetIsUnlocked!"
        print(f"    0x{a:05X}: {d}{mark}")
        if d == "ret":
            break

# ==========================================
print(f"\n{'='*60}")
print("=== 5. 搜索0x367F0周边函数中对devinfo buffer的写入 ===")
print("=" * 60)
# Check if any function between 0x36000 and 0x38000 writes to devinfo[13]
devinfo_page = 0x1BD000
for i in range(0x36000, 0x38000, 4):
    insn = struct.unpack_from('<I', code, i)[0]
    # STRB
    if (insn & 0xFFC00000) == 0x39000000:
        imm = (insn >> 10) & 0xFFF
        rn = (insn >> 5) & 0x1f
        rt = insn & 0x1f
        if imm == 13:
            print(f"  0x{i:05X}: strb w{rt}, [x{rn}, #13]")

# ==========================================
print(f"\n{'='*60}")
print("=== 6. 完整的 0x3C328 函数 ===")
print("=" * 60)
for a in range(0x3C328, min(0x3C400, TEXT_SIZE), 4):
    d = decode_simple(a)
    mark = ""
    if "0x384D0" in d: mark = " ← init_defaults(1)!"
    print(f"  0x{a:05X}: {d}{mark}")
    if d == "ret":
        break

# ==========================================
print(f"\n{'='*60}")
print("=== 7. 0x3C328 周围函数 (0x3C310, 0x3C348 from dispatch table) ===")
print("=" * 60)
for func in [0x3C310, 0x3C348]:
    print(f"\n  --- 0x{func:05X} ---")
    for a in range(func, min(func + 0x60, TEXT_SIZE), 4):
        d = decode_simple(a)
        mark = ""
        if "0x384D0" in d: mark = " ← init_defaults!"
        elif "0x22C18" in d: mark = " ← IsDeviceUnlocked!"
        print(f"  0x{a:05X}: {d}{mark}")
        if d == "ret" or (d.startswith("b 0x") and int(d.split("0x")[1],16) > 0x40000):
            break
