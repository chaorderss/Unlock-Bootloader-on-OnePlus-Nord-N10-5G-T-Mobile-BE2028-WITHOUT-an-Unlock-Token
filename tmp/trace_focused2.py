#!/usr/bin/env python3
"""Focused investigation of suspicious devinfo access points:
1. Function at 0x2310C area (calls 0x29464 with devinfo buffer)
2. Function at 0x37C18 area (devinfo + ReadWritePartition)
3. Function 0x29464 (could be memset/zeromem!)
4. "Device unlocked: %a" string reference finder
5. 0x4E9E0 function
"""

import struct

PE = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
pe = open(PE, "rb").read()

CODE_START = 0x1000
CODE_END = 0x6A000

def u32(off):
    return struct.unpack_from("<I", pe, off)[0]

def decode_adrp(w, addr):
    if (w & 0x9F000000) != 0x90000000:
        return None
    rd = w & 0x1F
    immlo = (w >> 29) & 0x3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & 0x100000:
        imm |= ~0x1FFFFF
    page = ((addr & ~0xFFF) + (imm << 12)) & 0xFFFFFFFF
    return (rd, page)

def decode_add_imm(w):
    if (w & 0xFF800000) == 0x91000000:
        rd = w & 0x1F
        rn = (w >> 5) & 0x1F
        imm12 = (w >> 10) & 0xFFF
        sh = (w >> 22) & 1
        if sh:
            imm12 <<= 12
        return (rd, rn, imm12)
    return None

def decode_bl(w, addr):
    if (w >> 26) == 0x25:
        imm = w & 0x3FFFFFF
        if imm & 0x2000000:
            imm |= ~0x3FFFFFF
        return (addr + imm * 4) & 0xFFFFFFFF
    return None

def find_func_start(addr):
    """Search backwards for function prologue (STP with negative offset or similar)."""
    for off in range(addr, max(CODE_START, addr - 0x200), -4):
        w = u32(off)
        # STP x29, x30, [sp, #-N]! or similar prologue
        if (w & 0xFFC003E0) == 0xA9800000:  # STP with pre-index
            return off
        # SUB sp, sp, #N followed by STP
        if (w & 0xFF800000) == 0xD1000000:
            rn = (w >> 5) & 0x1F
            rd = w & 0x1F
            if rd == 31 and rn == 31:  # SUB sp, sp, #imm
                return off
        # STR with pre-index push pattern
        if (w & 0xFFE00400) == 0xF8000C00:
            rt = w & 0x1F
            rn = (w >> 5) & 0x1F
            if rn == 31:  # push to sp
                return off
    return addr

def hexdump(addr, size=64):
    """Show raw hex dump of PE at given offset."""
    for off in range(addr, min(len(pe), addr + size), 16):
        chunk = pe[off:off+16]
        hexstr = ' '.join(f'{b:02X}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"  0x{off:06X}: {hexstr}  {ascii_str}")

def disasm_range(start, end):
    """Disassemble with annotations."""
    for addr in range(start, min(end, len(pe)), 4):
        w = u32(addr)
        anno = ""

        # ADRP
        adrp = decode_adrp(w, addr)
        if adrp:
            rd, page = adrp
            anno = f"ADRP x{rd}, 0x{page:X}"

        # ADD imm
        add = decode_add_imm(w)
        if add:
            rd, rn, imm12 = add
            anno = f"ADD x{rd}, x{rn}, #0x{imm12:X}"

        # BL
        bl = decode_bl(w, addr)
        if bl is not None:
            label = ""
            known = {0x18248: "ReadWritePartition", 0x28574: "DebugCheck", 0x285A0: "DebugCheck2",
                     0x280FC: "DebugPrint", 0x01370: "LocateProtocol", 0x22C18: "IsDeviceUnlocked",
                     0x22CA8: "SetChargerScreen", 0x22D40: "SetVerityMode", 0x22DB8: "SetDeviceUnlocked",
                     0x232D8: "ReadDeviceInfo", 0x384D0: "init_defaults", 0x384B0: "SetIsUnlocked",
                     0x189E0: "IsSecureBoot_trampoline", 0x189E8: "func_189E8",
                     0x38490: "GetCalRebootCount", 0x38430: "SetCalRebootCount",
                     0x4E9E0: "func_4E9E0", 0x29464: "func_29464",
                     0x4FD10: "CompareMem"}
            label = known.get(bl, "")
            anno = f"BL 0x{bl:05X} {label}"

        # B
        if (w >> 26) == 0x05:
            imm = w & 0x3FFFFFF
            if imm & 0x2000000:
                imm |= ~0x3FFFFFF
            target = (addr + imm * 4) & 0xFFFFFFFF
            anno = f"B 0x{target:05X}"

        # STRB
        if (w & 0xFFC00000) == 0x39000000:
            rt = w & 0x1F
            rn = (w >> 5) & 0x1F
            imm12 = (w >> 10) & 0xFFF
            anno = f"STRB w{rt}, [x{rn}, #{imm12}]"

        # LDRB
        if (w & 0xFFC00000) == 0x39400000:
            rt = w & 0x1F
            rn = (w >> 5) & 0x1F
            imm12 = (w >> 10) & 0xFFF
            anno = f"LDRB w{rt}, [x{rn}, #{imm12}]"

        # STR 64-bit imm
        if (w & 0xFFC00000) == 0xF9000000:
            rt = w & 0x1F
            rn = (w >> 5) & 0x1F
            imm12 = ((w >> 10) & 0xFFF) * 8
            anno = f"STR x{rt}, [x{rn}, #{imm12}]"

        # LDR 64-bit imm
        if (w & 0xFFC00000) == 0xF9400000:
            rt = w & 0x1F
            rn = (w >> 5) & 0x1F
            imm12 = ((w >> 10) & 0xFFF) * 8
            anno = f"LDR x{rt}, [x{rn}, #{imm12}]"

        # STR 32-bit imm
        if (w & 0xFFC00000) == 0xB9000000:
            rt = w & 0x1F
            rn = (w >> 5) & 0x1F
            imm12 = ((w >> 10) & 0xFFF) * 4
            anno = f"STR w{rt}, [x{rn}, #{imm12}]"

        # LDR 32-bit imm
        if (w & 0xFFC00000) == 0xB9400000:
            rt = w & 0x1F
            rn = (w >> 5) & 0x1F
            imm12 = ((w >> 10) & 0xFFF) * 4
            anno = f"LDR w{rt}, [x{rn}, #{imm12}]"

        # MOV wide 32
        if (w & 0xFF800000) == 0x52800000:
            rd = w & 0x1F
            imm16 = (w >> 5) & 0xFFFF
            anno = f"MOV w{rd}, #{imm16}"

        # MOV wide 64
        if (w & 0xFF800000) == 0xD2800000:
            rd = w & 0x1F
            imm16 = (w >> 5) & 0xFFFF
            anno = f"MOV x{rd}, #0x{imm16:X}"

        # MOV register (64-bit)
        if (w & 0xFFE0FFE0) == 0xAA0003E0:
            rd = w & 0x1F
            rm = (w >> 16) & 0x1F
            anno = f"MOV x{rd}, x{rm}"

        # MOV register (32-bit)
        if (w & 0xFFE0FFE0) == 0x2A0003E0:
            rd = w & 0x1F
            rm = (w >> 16) & 0x1F
            anno = f"MOV w{rd}, w{rm}"

        # RET
        if w == 0xD65F03C0:
            anno = "RET"

        # CBZ/CBNZ
        for op, name in [(0xB4000000, "CBZ x"), (0x34000000, "CBZ w"),
                         (0xB5000000, "CBNZ x"), (0x35000000, "CBNZ w")]:
            if (w & 0xFF000000) == op:
                rt = w & 0x1F
                imm19 = (w >> 5) & 0x7FFFF
                if imm19 & 0x40000:
                    imm19 |= ~0x7FFFF
                target = (addr + imm19 * 4) & 0xFFFFFFFF
                anno = f"{name}{rt}, 0x{target:05X}"

        # B.cond
        if (w & 0xFF000010) == 0x54000000:
            cond = w & 0xF
            imm19 = (w >> 5) & 0x7FFFF
            if imm19 & 0x40000:
                imm19 |= ~0x3FFFF
            target = (addr + imm19 * 4) & 0xFFFFFFFF
            conds = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
            anno = f"B.{conds[cond]} 0x{target:05X}"

        # TBNZ/TBZ
        if (w & 0x7F000000) == 0x37000000:
            rt = w & 0x1F
            bit = ((w >> 31) << 5) | ((w >> 19) & 0x1F)
            imm14 = (w >> 5) & 0x3FFF
            if imm14 & 0x2000:
                imm14 |= ~0x3FFF
            target = (addr + imm14 * 4) & 0xFFFFFFFF
            op = "TBNZ" if (w >> 24) & 1 else "TBZ"
            anno = f"{op} w{rt}, #{bit}, 0x{target:05X}"

        # STP (64-bit pre-index)
        if (w & 0xFFC00000) == 0xA9000000 or (w & 0xFE000000) == 0xA9000000:
            anno = f"STP (0x{w:08X})"

        # CMP imm
        if (w & 0xFF800000) == 0x71000000:
            rn = (w >> 5) & 0x1F
            imm12 = (w >> 10) & 0xFFF
            anno = f"CMP w{rn}, #{imm12}"

        # BLR
        if (w & 0xFFFFFC1F) == 0xD63F0000:
            rn = (w >> 5) & 0x1F
            anno = f"BLR x{rn}"

        if not anno:
            anno = f"0x{w:08X}"

        print(f"  0x{addr:05X}: {anno}")

# ============================================================
# 1. Function at 0x29464 — what is it?
# ============================================================
print("=" * 70)
print("=== 1. Function at 0x29464 ===")
print("=" * 70)
disasm_range(0x29464, 0x294E0)

# Check callers count
callers_29464 = []
for addr in range(CODE_START, CODE_END, 4):
    bl = decode_bl(u32(addr), addr)
    if bl == 0x29464:
        callers_29464.append(addr)
print(f"\nCallers of 0x29464: {len(callers_29464)} → {[f'0x{a:05X}' for a in callers_29464]}")

# ============================================================
# 2. Function context at 0x23100 area (devinfo + 0x29464 calls)
# ============================================================
print("\n" + "=" * 70)
print("=== 2. Function at ~0x230F0 area (devinfo + 0x29464) ===")
print("=" * 70)
# Find function start
func_start = find_func_start(0x23100)
print(f"Function start estimate: 0x{func_start:05X}")
disasm_range(func_start, min(CODE_END, func_start + 0x200))

# Find callers of this function
func_callers = []
for addr in range(CODE_START, CODE_END, 4):
    bl = decode_bl(u32(addr), addr)
    if bl is not None and func_start <= bl < func_start + 0x10:
        func_callers.append(addr)
print(f"\nCallers of function at 0x{func_start:05X}: {len(func_callers)} → {[f'0x{a:05X}' for a in func_callers]}")

# ============================================================
# 3. Function context at 0x37C00 area (devinfo + ReadWritePartition)
# ============================================================
print("\n" + "=" * 70)
print("=== 3. Function at ~0x37C00 area (devinfo + ReadWritePartition) ===")
print("=" * 70)
func_start_37c = find_func_start(0x37C18)
print(f"Function start estimate: 0x{func_start_37c:05X}")
disasm_range(func_start_37c, min(CODE_END, func_start_37c + 0x180))

# Find callers
func_callers_37c = []
for addr in range(CODE_START, CODE_END, 4):
    bl = decode_bl(u32(addr), addr)
    if bl is not None and func_start_37c <= bl < func_start_37c + 0x10:
        func_callers_37c.append(addr)
print(f"\nCallers of function at 0x{func_start_37c:05X}: {len(func_callers_37c)} → {[f'0x{a:05X}' for a in func_callers_37c]}")

# ============================================================
# 4. Search for code referencing "Device unlocked: %a" at 0x067D2F
# ============================================================
print("\n" + "=" * 70)
print("=== 4. Finding code that references 'Device unlocked: %a' at 0x067D2F ===")
print("=" * 70)

# First, verify the string
print("Raw string data at 0x067D20:")
hexdump(0x067D20, 64)

target_addr = 0x067D2F
target_page = target_addr & ~0xFFF  # 0x067000
target_offset = target_addr & 0xFFF  # 0xD2F

print(f"\nSearching for ADRP to page 0x{target_page:X} + ADD offset 0x{target_offset:X}")

# Also search for nearby strings
for str_addr in [0x067D2F, 0x067D43]:
    page = str_addr & ~0xFFF
    offset = str_addr & 0xFFF
    for addr in range(CODE_START, CODE_END, 4):
        w = u32(addr)
        adrp = decode_adrp(w, addr)
        if adrp is None:
            continue
        rd, ap = adrp
        if ap != page:
            continue
        # Check next few instructions for ADD with matching offset
        for delta in range(4, 20, 4):
            if addr + delta >= CODE_END:
                break
            w2 = u32(addr + delta)
            add = decode_add_imm(w2)
            if add and add[1] == rd and add[2] == offset:
                print(f"\n  Found reference to 0x{str_addr:06X} at 0x{addr:05X} + 0x{addr+delta:05X}")
                # Show surrounding context
                disasm_range(max(CODE_START, addr - 40), min(CODE_END, addr + 80))
                break

# Also try page 0x068000 with adjusted offset
print("\n  Also searching ADRP to 0x068000...")
for addr in range(CODE_START, CODE_END, 4):
    w = u32(addr)
    adrp = decode_adrp(w, addr)
    if adrp is None:
        continue
    rd, ap = adrp
    if ap != 0x068000:
        continue
    # Check next instruction for ADD
    w2 = u32(addr + 4)
    add = decode_add_imm(w2)
    if add and add[1] == rd:
        effective = ap + add[2]
        # Check if this points near our strings
        if 0x067D00 <= effective <= 0x067D70:
            print(f"  Found: 0x{addr:05X} → 0x{effective:06X}")
            disasm_range(max(CODE_START, addr - 20), min(CODE_END, addr + 40))

# ============================================================
# 5. Search ALL ADRP to 0x067000 in code
# ============================================================
print("\n" + "=" * 70)
print("=== 5. All ADRP to 0x067000 page ===")
print("=" * 70)
for addr in range(CODE_START, CODE_END, 4):
    w = u32(addr)
    adrp = decode_adrp(w, addr)
    if adrp and adrp[1] == 0x067000:
        print(f"  0x{addr:05X}: ADRP x{adrp[0]}, 0x067000")
        # Check next instruction
        w2 = u32(addr + 4)
        add = decode_add_imm(w2)
        if add:
            print(f"  0x{addr+4:05X}: ADD x{add[0]}, x{add[1]}, #0x{add[2]:X} → effective=0x{0x067000+add[2]:06X}")

# ============================================================
# 6. Function 0x4E9E0 first instructions
# ============================================================
print("\n" + "=" * 70)
print("=== 6. Function at 0x4E9E0 ===")
print("=" * 70)
disasm_range(0x4E9E0, min(CODE_END, 0x4EA40))

# ============================================================
# 7. Look at 0x3C000 area — uses 0x1BF528 buffer (NOT devinfo!)
# ============================================================
print("\n" + "=" * 70)
print("=== 7. Buffer at 0x1BF528 — what is it? ===")
print("=" * 70)
print("Raw data at 0x1BF528:")
hexdump(0x1BF528, 32)
# Find function at 0x3C000 area
func_3c = find_func_start(0x3C1B8)
print(f"\nFunction start at ~0x3C area: 0x{func_3c:05X}")

# Check who calls this area
callers_3c = []
for addr in range(CODE_START, CODE_END, 4):
    bl = decode_bl(u32(addr), addr)
    if bl is not None and 0x3C000 <= bl <= 0x3CA00:
        callers_3c.append((addr, bl))
if callers_3c:
    print(f"Callers into 0x3C000-0x3CA00: {len(callers_3c)}")
    for a, t in callers_3c[:20]:
        print(f"  0x{a:05X} → 0x{t:05X}")

# ============================================================
# 8. Check if 0x3755C or 0x370DC areas modify devinfo
# ============================================================
print("\n" + "=" * 70)
print("=== 8. ADRP refs without ★: 0x370DC and 0x37CD0 ===")
print("=" * 70)

# 0x370DC: ADRP x1, 0x1BD000 (no ADD offset match)
print("0x370DC area:")
disasm_range(0x370C0, 0x37110)

# 0x37CD0: ADRP x8, 0x1BD000 (no ADD offset match)
print("\n0x37CD0 area:")
disasm_range(0x37CB0, 0x37D20)

# ============================================================
# 9. Check 0x22EE8 ADRP reference (no DEVINFO BUFFER mark)
# ============================================================
print("\n" + "=" * 70)
print("=== 9. ADRP at 0x22EE8 (in SetDeviceUnlocked second write path) ===")
print("=" * 70)
disasm_range(0x22ED0, 0x23010)

print("\nDone.")
