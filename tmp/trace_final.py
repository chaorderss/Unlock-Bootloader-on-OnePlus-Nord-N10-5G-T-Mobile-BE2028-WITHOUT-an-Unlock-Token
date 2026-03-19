#!/usr/bin/env python3
"""Final investigation:
1. Non-devinfo ADRP refs to 0x1BD000 page
2. ReadWritePartition function analysis
3. Functions 0x30890 and 0x30AE0 (called in boot function after devinfo read)
4. ALL possible indirect callers of init_defaults through call chains
5. Check if there's a memcpy/memset to the devinfo buffer area (0x1BD985 specifically)
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
    return (rd, ((addr & ~0xFFF) + (imm << 12)) & 0xFFFFFFFF)

def decode_add(w):
    if (w & 0xFF800000) == 0x91000000:
        rd = w & 0x1F
        rn = (w >> 5) & 0x1F
        imm12 = (w >> 10) & 0xFFF
        sh = (w >> 22) & 1
        if sh: imm12 <<= 12
        return (rd, rn, imm12)
    return None

def decode_bl(w, addr):
    if (w >> 26) == 0x25:
        imm = w & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        return (addr + imm * 4) & 0xFFFFFFFF
    return None

def disasm_line(addr):
    if addr < 0 or addr + 4 > len(pe): return "OOB"
    w = u32(addr)

    adrp = decode_adrp(w, addr)
    if adrp: return f"ADRP x{adrp[0]}, 0x{adrp[1]:X}"

    add = decode_add(w)
    if add: return f"ADD x{add[0]}, x{add[1]}, #0x{add[2]:X}"

    bl = decode_bl(w, addr)
    if bl is not None:
        known = {0x18248: "ReadWritePartition", 0x28574: "DebugCheck", 0x280FC: "DebugPrint",
                 0x01370: "LocateProtocol", 0x22C18: "IsDeviceUnlocked", 0x232D8: "ReadDeviceInfo",
                 0x384D0: "init_defaults", 0x22DB8: "SetDeviceUnlocked", 0x384B0: "SetIsUnlocked",
                 0x22CA8: "SetChargerScreen", 0x189E0: "IsSecureBoot_tramp", 0x189E8: "func_189E8",
                 0x4FD10: "CompareMem", 0x29464: "func_29464", 0x4E9E0: "func_4E9E0",
                 0x38800: "IsSecureBootEnabled (real)", 0x38680: "ReadFuses"}
        return f"BL 0x{bl:05X} {known.get(bl, '')}"

    if (w >> 26) == 0x05:
        imm = w & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        return f"B 0x{(addr + imm * 4) & 0xFFFFFFFF:05X}"

    if (w & 0xFFC00000) == 0x39000000:
        rt = w & 0x1F; rn = (w >> 5) & 0x1F; imm12 = (w >> 10) & 0xFFF
        return f"STRB w{rt}, [x{rn}, #{imm12}]"
    if (w & 0xFFC00000) == 0x39400000:
        rt = w & 0x1F; rn = (w >> 5) & 0x1F; imm12 = (w >> 10) & 0xFFF
        return f"LDRB w{rt}, [x{rn}, #{imm12}]"
    if (w & 0xFFC00000) == 0xF9000000:
        rt = w & 0x1F; rn = (w >> 5) & 0x1F; imm = ((w >> 10) & 0xFFF) * 8
        return f"STR x{rt}, [x{rn}, #{imm}]"
    if (w & 0xFFC00000) == 0xF9400000:
        rt = w & 0x1F; rn = (w >> 5) & 0x1F; imm = ((w >> 10) & 0xFFF) * 8
        return f"LDR x{rt}, [x{rn}, #{imm}]"
    if (w & 0xFFC00000) == 0xB9000000:
        rt = w & 0x1F; rn = (w >> 5) & 0x1F; imm = ((w >> 10) & 0xFFF) * 4
        return f"STR w{rt}, [x{rn}, #{imm}]"
    if (w & 0xFFC00000) == 0xB9400000:
        rt = w & 0x1F; rn = (w >> 5) & 0x1F; imm = ((w >> 10) & 0xFFF) * 4
        return f"LDR w{rt}, [x{rn}, #{imm}]"
    if (w & 0xFF800000) == 0x52800000:
        return f"MOV w{w & 0x1F}, #{(w >> 5) & 0xFFFF}"
    if (w & 0xFF800000) == 0xD2800000:
        return f"MOV x{w & 0x1F}, #0x{(w >> 5) & 0xFFFF:X}"
    if w == 0xD65F03C0:
        return "RET"
    if (w & 0xFFE0FFE0) == 0xAA0003E0:
        return f"MOV x{w & 0x1F}, x{(w >> 16) & 0x1F}"
    if (w & 0xFFE0FFE0) == 0x2A0003E0:
        return f"MOV w{w & 0x1F}, w{(w >> 16) & 0x1F}"
    if (w & 0xFF000000) == 0xB4000000:
        rt = w & 0x1F; imm19 = (w >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x7FFFF
        return f"CBZ x{rt}, 0x{(addr + imm19*4)&0xFFFFFFFF:05X}"
    if (w & 0xFF000000) == 0x34000000:
        rt = w & 0x1F; imm19 = (w >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x7FFFF
        return f"CBZ w{rt}, 0x{(addr + imm19*4)&0xFFFFFFFF:05X}"
    if (w & 0xFFFFFC1F) == 0xD63F0000:
        return f"BLR x{(w >> 5) & 0x1F}"
    if (w & 0xFF000010) == 0x54000000:
        cond = w & 0xF; imm19 = (w >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x3FFFF
        conds = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
        return f"B.{conds[cond]} 0x{(addr + imm19*4)&0xFFFFFFFF:05X}"
    if (w & 0x7F000000) == 0x37000000:
        rt = w & 0x1F; bit = ((w >> 31) << 5) | ((w >> 19) & 0x1F)
        imm14 = (w >> 5) & 0x3FFF
        if imm14 & 0x2000: imm14 |= ~0x3FFF
        op = "TBNZ" if (w >> 24) & 1 else "TBZ"
        return f"{op} w{rt}, #{bit}, 0x{(addr + imm14*4)&0xFFFFFFFF:05X}"
    if (w & 0xFF800000) == 0x71000000:
        return f"CMP w{(w >> 5) & 0x1F}, #{(w >> 10) & 0xFFF}"
    return f"0x{w:08X}"

def disasm_range(start, end):
    for a in range(start, min(end, len(pe)), 4):
        print(f"  0x{a:05X}: {disasm_line(a)}")

# ===============================================================
# 1. Non-devinfo ADRP refs to 0x1BD000 page
# ===============================================================
print("=" * 70)
print("=== 1. Non-devinfo ADRP refs to page 0x1BD000 ===")
print("   (These ADRP to 0x1BD000 but ADD offset != 0x978)")
print("=" * 70)

non_devinfo_adrps = [0x1E8E4, 0x1FF24, 0x20E74, 0x21678, 0x22AB0]
for addr in non_devinfo_adrps:
    print(f"\n--- 0x{addr:05X} ---")
    # Show 3 instructions before and 10 after
    for a in range(max(CODE_START, addr - 12), min(CODE_END, addr + 44), 4):
        line = disasm_line(a)
        marker = " <<<" if a == addr else ""
        print(f"  0x{a:05X}: {line}{marker}")
    # If ADD follows, compute effective address
    w2 = u32(addr + 4)
    add = decode_add(w2)
    adrp = decode_adrp(u32(addr), addr)
    if adrp and add and add[1] == adrp[0]:
        eff = adrp[1] + add[2]
        print(f"  → Effective address: 0x{eff:06X} (page 0x{adrp[1]:X} + 0x{add[2]:X})")

# ===============================================================
# 2. ReadWritePartition (0x18248) function analysis
# ===============================================================
print("\n" + "=" * 70)
print("=== 2. ReadWritePartition function at 0x18248 ===")
print("=" * 70)
disasm_range(0x18248, 0x18350)

# ===============================================================
# 3. Functions 0x30890 and 0x30AE0 — check for devinfo access
# ===============================================================
print("\n" + "=" * 70)
print("=== 3a. Function 0x30890 — first 48 instructions ===")
print("=" * 70)
disasm_range(0x30890, 0x30950)

# Search for ADRP 0x1BD000 within reasonable range
print("\n  Searching 0x30890-0x30AE0 for ADRP 0x1BD000:")
for a in range(0x30890, 0x30AE0, 4):
    adrp = decode_adrp(u32(a), a)
    if adrp and adrp[1] == 0x1BD000:
        print(f"  FOUND at 0x{a:05X}")
for a in range(0x30890, 0x30AE0, 4):
    bl = decode_bl(u32(a), a)
    if bl is not None:
        # Check if target is a known devinfo function
        devinfo_funcs = [0x22C18, 0x22C28, 0x22C38, 0x22C48, 0x22C58, 0x22CA8, 0x22D40, 0x22DB8, 0x232D8, 0x384D0, 0x384B0, 0x18248]
        if bl in devinfo_funcs:
            print(f"  BL to devinfo function at 0x{a:05X} → 0x{bl:05X}")

print("\n" + "=" * 70)
print("=== 3b. Function 0x30AE0 — first 48 instructions ===")
print("=" * 70)
disasm_range(0x30AE0, 0x30BA0)

print("\n  Searching 0x30AE0-0x30C00 for ADRP 0x1BD000:")
for a in range(0x30AE0, 0x30C00, 4):
    adrp = decode_adrp(u32(a), a)
    if adrp and adrp[1] == 0x1BD000:
        print(f"  FOUND at 0x{a:05X}")
for a in range(0x30AE0, 0x30C00, 4):
    bl = decode_bl(u32(a), a)
    if bl is not None:
        devinfo_funcs = [0x22C18, 0x22C28, 0x22C38, 0x22C48, 0x22C58, 0x22CA8, 0x22D40, 0x22DB8, 0x232D8, 0x384D0, 0x384B0, 0x18248]
        if bl in devinfo_funcs:
            print(f"  BL to devinfo function at 0x{a:05X} → 0x{bl:05X}")

# ===============================================================
# 4. Check 0x46AA0 fastboot init for devinfo access
# ===============================================================
print("\n" + "=" * 70)
print("=== 4. Fastboot init 0x46AA0-0x46D00 for devinfo access ===")
print("=" * 70)
print("  Searching 0x46AA0-0x46D00 for ADRP 0x1BD000:")
for a in range(0x46AA0, 0x46D00, 4):
    adrp = decode_adrp(u32(a), a)
    if adrp and adrp[1] == 0x1BD000:
        print(f"  FOUND at 0x{a:05X}")
for a in range(0x46AA0, 0x46D00, 4):
    bl = decode_bl(u32(a), a)
    if bl is not None:
        devinfo_funcs = {0x22C18: "IsDeviceUnlocked", 0x22C28: "IsUnlockCritical",
                        0x22C38: "GetVerityMode", 0x22C48: "GetChargerScreen",
                        0x22CA8: "SetChargerScreen", 0x22D40: "SetVerityMode",
                        0x22DB8: "SetDeviceUnlocked", 0x232D8: "ReadDeviceInfo",
                        0x384D0: "init_defaults", 0x384B0: "SetIsUnlocked",
                        0x18248: "ReadWritePartition"}
        if bl in devinfo_funcs:
            print(f"  BL {devinfo_funcs[bl]} at 0x{a:05X}")

# ===============================================================
# 5. Exhaustive search: ALL BL targets from 0x367F0 boot function
# ===============================================================
print("\n" + "=" * 70)
print("=== 5. Boot function 0x367F0 — all BL targets ===")
print("=" * 70)
for a in range(0x367F0, 0x36920, 4):
    bl = decode_bl(u32(a), a)
    if bl is not None:
        print(f"  0x{a:05X}: BL 0x{bl:05X}", end="")
        # Check if any of these call devinfo functions internally
        # Just list the BL targets
        known = {0x34E50: "ProcessParams", 0x362D8: "OemCheckResetDevInfo",
                0x30890: "ProtocolInit", 0x30AE0: "ReadConfig",
                0x46AA0: "FastbootInit", 0x01370: "LocateProtocol",
                0x28574: "DebugCheck", 0x280FC: "DebugPrint",
                0x0D4A4: "FreePoolCleanup"}
        if bl in known:
            print(f" ({known[bl]})", end="")
        print()

# ===============================================================
# 6. Look at the BLR (indirect call) sites near devinfo code
# ===============================================================
print("\n" + "=" * 70)
print("=== 6. BLR (indirect calls) in devinfo functions area ===")
print("=" * 70)
print("  Searching 0x22C00-0x23400 for BLR:")
for a in range(0x22C00, 0x23400, 4):
    w = u32(a)
    if (w & 0xFFFFFC1F) == 0xD63F0000:
        rn = (w >> 5) & 0x1F
        print(f"  0x{a:05X}: BLR x{rn}")
        # Show context
        for ctx in range(max(CODE_START, a-20), min(CODE_END, a+8), 4):
            print(f"    0x{ctx:05X}: {disasm_line(ctx)}")

# ===============================================================
# 7. Check init_defaults more carefully for CopyMem call
# ===============================================================
print("\n" + "=" * 70)
print("=== 7. init_defaults CopyMem/SetMem indirect calls ===")
print("=" * 70)
print("  Searching 0x384D0-0x385D0 for BLR:")
for a in range(0x384D0, 0x385D0, 4):
    w = u32(a)
    if (w & 0xFFFFFC1F) == 0xD63F0000:
        rn = (w >> 5) & 0x1F
        print(f"  0x{a:05X}: BLR x{rn}")

# ===============================================================
# 8. Key question: trace ReadWritePartition to see if it's
#    devinfo-specific or takes a partition name
# ===============================================================
print("\n" + "=" * 70)
print("=== 8. ReadWritePartition detailed (0x18248) ===")
print("=" * 70)
# Show more of the function
disasm_range(0x18248, 0x18450)

# ===============================================================
# 9. Check the ENTIRE boot flow from 0x01500 for any deviation
# ===============================================================
print("\n" + "=" * 70)
print("=== 9. Full boot flow 0x01500-0x01700 ===")
print("=" * 70)
disasm_range(0x01500, 0x01700)

# ===============================================================
# 10. The REAL test: what if ReadDeviceInfo's CompareMem returns
#     non-zero for some reason?
# ===============================================================
print("\n" + "=" * 70)
print("=== 10. CompareMem at 0x4FD10 — first 20 instructions ===")
print("=" * 70)
disasm_range(0x4FD10, 0x4FD70)

print("\nDone.")
