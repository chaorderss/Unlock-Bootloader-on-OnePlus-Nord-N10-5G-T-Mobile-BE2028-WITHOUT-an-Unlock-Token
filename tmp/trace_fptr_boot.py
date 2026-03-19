#!/usr/bin/env python3
"""
深入搜索:
1. 搜索 0x3C328 和 0x362D0 的函数指针（32/64位，含偏移）
2. 验证 IsDeviceUnlocked 读取的确切地址
3. 追踪 0x01558 之后的 boot sequence
4. 搜索 ReadDeviceInfo (0x232D8) 被调用后是否还有其他代码重新读取devinfo
5. 搜索所有写入 devinfo buffer 区域 0x1BD978+13 = 0x1BD985 的代码
"""
import struct

PE32 = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
TEXT_SIZE = 0x6A000

with open(PE32, "rb") as f:
    pe = f.read()
code = pe[:TEXT_SIZE]

print("=" * 60)
print("=== 1. 验证 IsDeviceUnlocked (0x22C18) 的实际字节 ===")
print("=" * 60)
for addr in [0x22C18, 0x22C1C, 0x22C20]:
    insn = struct.unpack_from('<I', code, addr)[0]
    print(f"  0x{addr:05X}: 0x{insn:08X}")

# Decode 0x22C18 instruction
insn = struct.unpack_from('<I', code, 0x22C18)[0]
# ADRP: 1 immlo[1:0] 10000 immhi[18:0] Rd[4:0]
rd = insn & 0x1f
immlo = (insn >> 29) & 3
immhi = (insn >> 5) & 0x7ffff
imm = (immhi << 2) | immlo
if imm & (1 << 20): imm -= (1 << 21)
pc = 0x22C18
page = (pc & ~0xFFF) + (imm << 12)
print(f"  0x22C18: adrp x{rd}, 0x{page:X}")

# Decode 0x22C1C
insn2 = struct.unpack_from('<I', code, 0x22C1C)[0]
print(f"  0x22C1C raw: 0x{insn2:08X}")
# Check if LDRB unsigned offset: 0011 1001 01 imm12 Rn Rt
if (insn2 & 0xFFC00000) == 0x39400000:
    imm12 = (insn2 >> 10) & 0xFFF
    rn = (insn2 >> 5) & 0x1f
    rt = insn2 & 0x1f
    print(f"  0x22C1C: ldrb w{rt}, [x{rn}, #{imm12}]")
    eff_addr = page + imm12
    print(f"  Effective address: 0x{page:X} + {imm12} = 0x{eff_addr:X}")
    print(f"  devinfo buffer start: 0x1BD978")
    print(f"  Offset from buffer start: 0x{eff_addr:X} - 0x1BD978 = {eff_addr - 0x1BD978}")
else:
    # try ADD
    if (insn2 & 0xFF000000) == 0x91000000:
        imm12 = (insn2 >> 10) & 0xFFF
        rn = (insn2 >> 5) & 0x1f
        rdd = insn2 & 0x1f
        print(f"  0x22C1C: add x{rdd}, x{rn}, #0x{imm12:X}")
    else:
        print(f"  0x22C1C: unknown encoding")

print(f"\n{'='*60}")
print("=== 2. 搜索 0x3C328 和 0x362D0 的函数指针 ===")
print("=" * 60)
targets = [0x3C328, 0x362D0, 0x232D8, 0x384D0, 0x384B0]
target_names = {0x3C328: "ResetDevInfo(0x3C328)", 0x362D0: "OemCheckResetDevInfo(0x362D0)",
                0x232D8: "ReadDeviceInfo(0x232D8)", 0x384D0: "init_defaults(0x384D0)",
                0x384B0: "SetIsUnlocked(0x384B0)"}

for target in targets:
    print(f"\n  --- Searching for {target_names.get(target, '')} = 0x{target:X} ---")
    # Search as 64-bit LE
    needle64 = struct.pack('<Q', target)
    pos = 0
    while True:
        idx = pe.find(needle64, pos)
        if idx == -1: break
        print(f"  [64bit] Found at PE offset 0x{idx:05X}")
        # Show context
        for d in range(-16, 24, 8):
            if idx+d >= 0 and idx+d+8 <= len(pe):
                v = struct.unpack_from('<Q', pe, idx+d)[0]
                mark = " <<<" if d == 0 else ""
                if 0 < v < 0x200000:
                    print(f"    [{d:+3d}] 0x{idx+d:05X}: 0x{v:016X} (={v:#X}){mark}")
                else:
                    print(f"    [{d:+3d}] 0x{idx+d:05X}: 0x{v:016X}{mark}")
        pos = idx + 1

    # Search as 32-bit LE
    needle32 = struct.pack('<I', target)
    pos = 0
    found_32 = []
    while True:
        idx = pe.find(needle32, pos)
        if idx == -1: break
        # Skip if it's in code section (likely part of an instruction)
        if idx < TEXT_SIZE:
            pos = idx + 1
            continue
        found_32.append(idx)
        pos = idx + 1
    if found_32:
        for idx in found_32[:5]:
            print(f"  [32bit] Found at PE offset 0x{idx:05X}")

print(f"\n{'='*60}")
print("=== 3. 追踪 boot sequence: 0x01558 前后 ===")
print("=" * 60)

def decode_simple(addr):
    if addr < 0 or addr + 4 > TEXT_SIZE:
        return "OUT"
    insn = struct.unpack_from('<I', code, addr)[0]
    if insn == 0xD65F03C0: return "ret"
    if insn == 0xD503201F: return "nop"
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
        cc = {0:'EQ',1:'NE',2:'CS',3:'CC',4:'MI',5:'PL',10:'GE',11:'LT',12:'GT',13:'LE'}.get(insn&0xf,'?')
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
    if (insn & 0xFF800000) == 0x52800000:
        return f"mov w{insn&0x1f}, #0x{((insn>>5)&0xFFFF):X}"
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
    if (insn & 0xFF80001F) == 0x7100001F:
        return f"cmp w{(insn>>5)&0x1f}, #{(insn>>10)&0xFFF}"
    if (insn & 0xFF80001F) == 0xF100001F:
        return f"cmp x{(insn>>5)&0x1f}, #{(insn>>10)&0xFFF}"
    if (insn & 0xFFFFFC1F) == 0xD63F0000:
        return f"blr x{(insn>>5)&0x1f}"
    if (insn & 0xFFFFFC1F) == 0xD61F0000:
        return f"br x{(insn>>5)&0x1f}"
    return f"0x{insn:08X}"

# Find function entry containing 0x01558
for a in range(0x01558, 0x00000, -4):
    d = decode_simple(a)
    if d == "ret" or d == ".word 0":
        start = a + 4
        break
else:
    start = 0x01500

print(f"  Function containing 0x01558 starts around 0x{start:05X}")
print(f"  Boot sequence from 0x01500:")
for a in range(0x01500, min(0x01700, TEXT_SIZE), 4):
    d = decode_simple(a)
    mark = ""
    if "0x232D8" in d: mark = " ← ReadDeviceInfo"
    elif "0x362D0" in d: mark = " ← OemCheckResetDevInfo"
    elif "0x3C328" in d: mark = " ← ResetDevInfo3"
    elif "0x384D0" in d: mark = " ← init_defaults"
    elif "0x22C18" in d: mark = " ← IsDeviceUnlocked"
    elif "0x18248" in d: mark = " ← ReadWriteDevInfo"
    elif "0x477F4" in d: mark = " ← FastbootInit?"
    print(f"  0x{a:05X}: {d}{mark}")
    if d == "ret" and a > 0x01600:
        break

print(f"\n{'='*60}")
print("=== 4. 追踪 0x01614 之后的代码 ===")
print("=" * 60)
for a in range(0x01614, min(0x018A0, TEXT_SIZE), 4):
    d = decode_simple(a)
    mark = ""
    if "0x232D8" in d: mark = " ← ReadDeviceInfo"
    elif "0x362D0" in d: mark = " ← OemCheckResetDevInfo"
    elif "0x3C328" in d: mark = " ← ResetDevInfo3"
    elif "0x384D0" in d: mark = " ← init_defaults"
    elif "0x22C18" in d: mark = " ← IsDeviceUnlocked"
    elif "0x18248" in d: mark = " ← ReadWriteDevInfo"
    elif "0x477F4" in d: mark = " ← FastbootInit?"
    print(f"  0x{a:05X}: {d}{mark}")
    if d == "ret" and a > 0x01700:
        break

print(f"\n{'='*60}")
print("=== 5. 找 ReadDeviceInfo 被调用时的上下文 ===")
print("=" * 60)
# 0x01558: bl 0x232D8 → ReadDeviceInfo
# What does 0x1B990 do (called right before)?
print("  前一个调用: 0x01554: bl 0x1B990 — 解码此函数:")
for a in range(0x1B990, min(0x1B990 + 0xC0, TEXT_SIZE), 4):
    d = decode_simple(a)
    mark = ""
    if "0x232D8" in d: mark = " ← ReadDeviceInfo"
    elif "0x362D0" in d: mark = " ← OemCheckResetDevInfo"
    elif "0x3C328" in d: mark = " ← ResetDevInfo3"
    elif "0x384D0" in d: mark = " ← init_defaults"
    elif "0x22C18" in d: mark = " ← IsDeviceUnlocked"
    elif "0x18248" in d: mark = " ← ReadWriteDevInfo"
    print(f"  0x{a:05X}: {d}{mark}")
    if d == "ret":
        break

print(f"\n{'='*60}")
print("=== 6. 0x18248 函数开头+调用者 ===")
print("=" * 60)
for a in range(0x18248, min(0x18248 + 0x60, TEXT_SIZE), 4):
    d = decode_simple(a)
    print(f"  0x{a:05X}: {d}")
    if d == "ret":
        break

# Find all callers of 0x18248
callers_18248 = []
for i in range(0, TEXT_SIZE, 4):
    insn = struct.unpack_from('<I', code, i)[0]
    if (insn & 0xFC000000) == 0x94000000:
        off = insn & 0x03FFFFFF
        if off & (1<<25): off -= (1<<26)
        if i + off*4 == 0x18248:
            callers_18248.append(i)
print(f"\n  All callers of 0x18248: {[f'0x{c:05X}' for c in callers_18248]}")
for c in callers_18248:
    # Show the w0 value before the call (look for mov w0)
    for back in range(c-16, c, 4):
        d = decode_simple(back)
        if 'mov w0' in d or 'mov x0' in d:
            print(f"    At 0x{c:05X}: preceded by 0x{back:05X}: {d}")

print(f"\n{'='*60}")
print("=== 7. 搜索 PE relocation table ===")
print("=" * 60)
# Check PE header for relocation info
if pe[0:2] == b'MZ':
    print("  Has MZ header")
    pe_offset = struct.unpack_from('<I', pe, 0x3C)[0]
    print(f"  PE header at 0x{pe_offset:X}")
    if pe[pe_offset:pe_offset+4] == b'PE\0\0':
        print("  PE signature found")
        opt_hdr_offset = pe_offset + 24
        magic = struct.unpack_from('<H', pe, opt_hdr_offset)[0]
        print(f"  Optional header magic: 0x{magic:X} ({'PE32+' if magic == 0x20B else 'PE32'})")
        if magic == 0x20B:
            image_base = struct.unpack_from('<Q', pe, opt_hdr_offset + 24)[0]
            print(f"  ImageBase: 0x{image_base:X}")
            num_dirs = struct.unpack_from('<I', pe, opt_hdr_offset + 108)[0]
            print(f"  Number of data directories: {num_dirs}")
            if num_dirs > 5:
                reloc_rva = struct.unpack_from('<I', pe, opt_hdr_offset + 136)[0]
                reloc_size = struct.unpack_from('<I', pe, opt_hdr_offset + 140)[0]
                print(f"  Relocation table: RVA=0x{reloc_rva:X}, Size=0x{reloc_size:X}")
else:
    print("  No MZ header")

print(f"\n{'='*60}")
print("=== 8. 搜索所有 BL 到 IsDeviceUnlocked 并检查后续代码 ===")
print("=" * 60)
# Find all callers and check what they do with the result
callers = []
for i in range(0, TEXT_SIZE, 4):
    insn = struct.unpack_from('<I', code, i)[0]
    if (insn & 0xFC000000) == 0x94000000:
        off = insn & 0x03FFFFFF
        if off & (1<<25): off -= (1<<26)
        if i + off*4 == 0x22C18:
            callers.append(i)

for c in callers:
    # Show 4 instructions after BL
    print(f"\n  0x{c:05X}: bl 0x22C18 (IsDeviceUnlocked)")
    for a in range(c+4, min(c+20, TEXT_SIZE), 4):
        d = decode_simple(a)
        print(f"    0x{a:05X}: {d}")
