#!/usr/bin/env python3
"""
深入分析:
1. 0x4C850 publish 函数的实际行为
2. getvar 命令处理流程
3. 是否存在动态 getvar handler
4. 0x22DB4 函数的间接调用者（通过函数指针表）
5. 检查 0x384B0 (set_is_unlocked_1) 的完整代码
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
    if insn == 0xD503201F: return "nop"

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
                 8:'HI',9:'LS',10:'GE',11:'LT',12:'GT',13:'LE'}
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
    # ADD imm
    if (insn & 0xFF000000) == 0x91000000:
        rd = insn & 0x1f; rn = (insn >> 5) & 0x1f; imm12 = (insn >> 10) & 0xFFF
        return f"add x{rd}, x{rn}, #0x{imm12:X}"
    # SUB imm
    if (insn & 0xFF000000) == 0xD1000000:
        rd = insn & 0x1f; rn = (insn >> 5) & 0x1f; imm12 = (insn >> 10) & 0xFFF
        return f"sub x{rd}, x{rn}, #0x{imm12:X}"
    # MOV wide
    if (insn & 0xFF800000) == 0x52800000:
        return f"mov w{insn & 0x1f}, #{(insn >> 5) & 0xFFFF}"
    if (insn & 0xFF800000) == 0xD2800000:
        return f"mov x{insn & 0x1f}, #{(insn >> 5) & 0xFFFF}"
    # MOV reg
    if (insn & 0xFFE0FFE0) == 0xAA0003E0:
        return f"mov x{insn & 0x1f}, x{(insn >> 16) & 0x1f}"
    if (insn & 0xFFE0FFE0) == 0x2A0003E0:
        return f"mov w{insn & 0x1f}, w{(insn >> 16) & 0x1f}"
    # STRB/LDRB
    if (insn & 0xFFC00000) == 0x39000000:
        return f"strb w{insn & 0x1f}, [x{(insn >> 5) & 0x1f}, #{(insn >> 10) & 0xFFF}]"
    if (insn & 0xFFC00000) == 0x39400000:
        return f"ldrb w{insn & 0x1f}, [x{(insn >> 5) & 0x1f}, #{(insn >> 10) & 0xFFF}]"
    # STR/LDR 64
    if (insn & 0xFFC00000) == 0xF9000000:
        return f"str x{insn & 0x1f}, [x{(insn >> 5) & 0x1f}, #{((insn >> 10) & 0xFFF)*8}]"
    if (insn & 0xFFC00000) == 0xF9400000:
        return f"ldr x{insn & 0x1f}, [x{(insn >> 5) & 0x1f}, #{((insn >> 10) & 0xFFF)*8}]"
    # STR/LDR 32
    if (insn & 0xFFC00000) == 0xB9000000:
        return f"str w{insn & 0x1f}, [x{(insn >> 5) & 0x1f}, #{((insn >> 10) & 0xFFF)*4}]"
    if (insn & 0xFFC00000) == 0xB9400000:
        return f"ldr w{insn & 0x1f}, [x{(insn >> 5) & 0x1f}, #{((insn >> 10) & 0xFFF)*4}]"
    # CMP imm
    if (insn & 0xFF80001F) == 0x7100001F:
        return f"cmp w{(insn >> 5) & 0x1f}, #{(insn >> 10) & 0xFFF}"
    # CMP reg
    if (insn & 0xFFE0FC1F) == 0x6B00001F:
        return f"cmp w{(insn >> 5) & 0x1f}, w{(insn >> 16) & 0x1f}"
    # TST
    if (insn & 0x7F80001F) == 0x7200001F:
        return f"tst w{(insn >> 5) & 0x1f}, #bitmask"
    # BLR
    if (insn & 0xFFFFFC1F) == 0xD63F0000:
        rn = (insn >> 5) & 0x1f
        return f"blr x{rn}"
    # BR
    if (insn & 0xFFFFFC1F) == 0xD61F0000:
        rn = (insn >> 5) & 0x1f
        return f"br x{rn}"
    # STP/LDP
    if (insn & 0x7FC00000) == 0x29800000:
        sf = 8 if (insn >> 31) else 4
        rt = insn & 0x1f; rt2 = (insn >> 10) & 0x1f; rn = (insn >> 5) & 0x1f
        imm7 = (insn >> 15) & 0x7f
        if imm7 & 0x40: imm7 -= 128
        r = "x" if sf == 8 else "w"
        return f"stp {r}{rt}, {r}{rt2}, [x{rn}, #{imm7*sf}]!"
    # CSEL variants
    if (insn & 0x7FE00000) in (0x1A800000, 0x5A800000):
        sf = "x" if (insn >> 31) else "w"
        ops = {0: 'csel', 1: 'csinc', 2: 'csinv', 3: 'csneg'}
        op2 = ((insn >> 30) & 1) << 1 | ((insn >> 10) & 1)
        rm = (insn >> 16) & 0x1f; cond = (insn >> 12) & 0xf
        rn = (insn >> 5) & 0x1f; rd = insn & 0x1f
        conds = {0:'EQ',1:'NE',2:'CS',3:'CC',4:'MI',5:'PL',8:'HI',9:'LS',10:'GE',11:'LT',12:'GT',13:'LE'}
        if op2 == 1 and rn == 31 and rm == 31:
            return f"cset {sf}{rd}, {conds.get(cond^1, f'c{cond^1}')}"
        return f"{ops.get(op2,'?')} {sf}{rd}, {sf}{rn}, {sf}{rm}, {conds.get(cond, f'c{cond}')}"
    # ORR imm
    if (insn & 0xFF800000) == 0x32000000:
        rd = insn & 0x1f; rn = (insn >> 5) & 0x1f
        if rn == 31: return f"mov w{rd}, #bitmask_imm"
        return f"orr w{rd}, w{rn}, #bitmask_imm"
    if (insn & 0xFF800000) == 0xB2000000:
        rd = insn & 0x1f; rn = (insn >> 5) & 0x1f
        if rn == 31: return f"mov x{rd}, #bitmask_imm64"
        return f"orr x{rd}, x{rn}, #bitmask_imm64"
    # AND immediate
    if (insn & 0xFF800000) == 0x12000000:
        rd = insn & 0x1f; rn = (insn >> 5) & 0x1f
        imms = (insn >> 10) & 0x3f
        if imms == 7: return f"and w{rd}, w{rn}, #0xFF"
        return f"and w{rd}, w{rn}, #bitmask"

    return f"0x{insn:08X}"

# === 1. Decode 0x4C850 (publish function) ===
print("=== 0x4C850 (FastbootPublish) 函数 ===")
for addr in range(0x4C850, 0x4C950, 4):
    d = decode_insn(addr)
    print(f"  0x{addr:05X}: {d}")
    if d == "ret":
        break

# === 2. Decode the getvar handler (0x4BF00-0x4C000) ===
print(f"\n=== getvar 命令处理器 (0x4BF00-0x4C700) ===")
# Find the getvar handler - it should reference "GetVar Variable Not found" at 0x067EA1
# and reference the variable list
for addr in range(0x4BF00, 0x4C700, 4):
    d = decode_insn(addr)
    # Only print interesting lines
    if any(x in d for x in ['bl ', 'blr ', 'ret', 'b.', 'cbz', 'cbnz', 'tbz', 'tbnz',
                              'adrp', 'add x', 'cmp', 'tst', 'csel', 'cset',
                              'ldr x', 'str x', 'ldrb', 'strb', 'mov x', 'b 0x']):
        print(f"  0x{addr:05X}: {d}")

# === 3. Decode 0x384B0 (SetIsUnlocked) ===
print(f"\n=== 0x384B0 (SetIsUnlocked/1) 函数 ===")
for addr in range(0x384B0, 0x384D0, 4):
    d = decode_insn(addr)
    print(f"  0x{addr:05X}: {d}")

# === 4. Search for function pointer tables containing devinfo getters ===
print(f"\n=== 搜索包含 0x22C18 (IsDeviceUnlocked) 的函数指针表 ===")
# Search for 64-bit pointers in data section
target_addr = 0x22C18
count = 0
for off in range(TEXT_SIZE, len(pe) - 8, 8):
    val = struct.unpack_from('<Q', pe, off)[0]
    if val == target_addr:
        print(f"  Found at offset 0x{off:05X}: ptr to 0x{val:X}")
        # Show surrounding pointers
        for delta in range(-32, 40, 8):
            if off + delta >= 0 and off + delta + 8 <= len(pe):
                v = struct.unpack_from('<Q', pe, off + delta)[0]
                if 0 < v < 0x100000:
                    mark = " <<<" if delta == 0 else ""
                    print(f"    [0x{off+delta:05X}] = 0x{v:X}{mark}")
        count += 1
if count == 0:
    print("  Not found as 64-bit pointer")
    # Try 32-bit
    for off in range(TEXT_SIZE, len(pe) - 4, 4):
        val = struct.unpack_from('<I', pe, off)[0]
        if val == target_addr:
            print(f"  Found as 32-bit at offset 0x{off:05X}")

# === 5. Search for function pointer tables containing 0x22DB4 ===
print(f"\n=== 搜索包含 0x22DB4 (SetDeviceUnlocked?) 的函数指针表 ===")
target_addr = 0x22DB4
count = 0
for off in range(TEXT_SIZE, len(pe) - 8, 8):
    val = struct.unpack_from('<Q', pe, off)[0]
    if val == target_addr:
        print(f"  Found at offset 0x{off:05X}: ptr to 0x{val:X}")
        for delta in range(-32, 40, 8):
            if off + delta >= 0 and off + delta + 8 <= len(pe):
                v = struct.unpack_from('<Q', pe, off + delta)[0]
                if 0 < v < 0x100000:
                    mark = " <<<" if delta == 0 else ""
                    print(f"    [0x{off+delta:05X}] = 0x{v:X}{mark}")
        count += 1
if count == 0:
    print("  Not found as 64-bit pointer")

# === 6. Search for 0x22E4C function - maybe it's at a different entry ===
# Look for the function prologue before 0x22E34
print(f"\n=== 0x22DB0-0x22E60 完整反汇编 ===")
for addr in range(0x22DB0, 0x22E60, 4):
    d = decode_insn(addr)
    mark = ""
    if addr == 0x22DB4: mark = " ← func entry?"
    elif addr == 0x22E4C: mark = " ← WRITE devinfo[0x0D]"
    elif addr == 0x22E3C: mark = " ← READ devinfo[0x0D]"
    print(f"  0x{addr:05X}: {d}{mark}")

# === 7. Check what's at 0x5BF06 and 0x5BF14 (magic string) ===
print(f"\n=== 关键字符串 ===")
for saddr in [0x5BF06, 0x5BF14, 0x5BF00, 0x60037B, 0x6003B2, 0x600BD4, 0x600B92, 0x60044B]:
    if saddr < len(pe):
        end = saddr
        while end < min(saddr + 80, len(pe)) and pe[end] != 0:
            end += 1
        s = pe[saddr:end]
        try:
            print(f"  0x{saddr:05X}: \"{s.decode('utf-8', errors='replace')}\"")
        except:
            print(f"  0x{saddr:05X}: {s}")

# === 8. Also check callers of 0x22CA8 (WriteDeviceInfo?) ===
print(f"\n=== 0x22CA8 的调用者 ===")
for i in range(0, TEXT_SIZE, 4):
    insn = struct.unpack_from('<I', code, i)[0]
    if (insn & 0xFC000000) == 0x94000000:
        off26 = insn & 0x03FFFFFF
        if off26 & (1<<25): off26 -= (1<<26)
        if i + off26*4 == 0x22CA8:
            print(f"  0x{i:05X}: bl 0x22CA8")

# === 9. Check all BLR calls in the fastboot init area ===
print(f"\n=== BLR (indirect calls) in 0x46000-0x4D000 ===")
for addr in range(0x46000, 0x4D000, 4):
    insn = struct.unpack_from('<I', code, addr)[0]
    if (insn & 0xFFFFFC1F) == 0xD63F0000:
        rn = (insn >> 5) & 0x1f
        print(f"  0x{addr:05X}: blr x{rn}")

# === 10. Check SPECIFICALLY the flow from OemCheckResetDevInfo return to fastboot ===
# Find all callers of 0x362D0 (OemCheckResetDevInfo)
print(f"\n=== OemCheckResetDevInfo (0x362D0) 的调用者 ===")
for i in range(0, TEXT_SIZE, 4):
    insn = struct.unpack_from('<I', code, i)[0]
    if (insn & 0xFC000000) == 0x94000000:
        off26 = insn & 0x03FFFFFF
        if off26 & (1<<25): off26 -= (1<<26)
        if i + off26*4 == 0x362D0:
            print(f"  0x{i:05X}: bl 0x362D0 (OemCheckResetDevInfo)")
            for ctx in range(max(i-8, 0), min(i+20, TEXT_SIZE), 4):
                print(f"    0x{ctx:05X}: {decode_insn(ctx)}")
