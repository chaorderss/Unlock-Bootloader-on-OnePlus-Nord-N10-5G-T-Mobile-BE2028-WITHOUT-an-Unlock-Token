#!/usr/bin/env python3
"""Quick checks:
1. Function 0x384A0 (called from ProtocolInit error path)
2. Context around 0x30A94 (ReadWritePartition call in ProtocolInit)
3. String at 0x5BF06 (ANDROID-BOOT! verification)
4. Also check ALL stores via DevInfoPtr (0x22C58 stores pointer)
5. Check if CSEL instruction at 0x4C11C is correct
"""
import struct

PE = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
pe = open(PE, "rb").read()

def u32(off): return struct.unpack_from("<I", pe, off)[0]

print("=== 1. Function at 0x384A0 (raw bytes) ===")
for off in range(0x38490, 0x384D0, 4):
    w = u32(off)
    print(f"  0x{off:05X}: 0x{w:08X}")

print(f"\n=== 2. Raw bytes 0x384A0-0x384AF ===")
for off in range(0x384A0, 0x384B0, 4):
    w = u32(off)
    # Try to decode
    # LDRB imm
    if (w & 0xFFC00000) == 0x39400000:
        rt = w & 0x1F; rn = (w >> 5) & 0x1F; imm = (w >> 10) & 0xFFF
        print(f"  0x{off:05X}: LDRB w{rt}, [x{rn}, #{imm}]")
    elif w == 0xD65F03C0:
        print(f"  0x{off:05X}: RET")
    elif (w & 0x9F000000) == 0x90000000:
        rd = w & 0x1F
        immlo = (w >> 29) & 0x3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000: imm |= ~0x1FFFFF
        page = ((off & ~0xFFF) + (imm << 12)) & 0xFFFFFFFF
        print(f"  0x{off:05X}: ADRP x{rd}, 0x{page:X}")
    elif (w & 0xFF800000) == 0x91000000:
        rd = w & 0x1F; rn = (w >> 5) & 0x1F
        imm12 = (w >> 10) & 0xFFF; sh = (w >> 22) & 1
        if sh: imm12 <<= 12
        print(f"  0x{off:05X}: ADD x{rd}, x{rn}, #0x{imm12:X}")
    elif (w & 0xFFC00000) == 0xB9400000:
        rt = w & 0x1F; rn = (w >> 5) & 0x1F; imm = ((w >> 10) & 0xFFF) * 4
        print(f"  0x{off:05X}: LDR w{rt}, [x{rn}, #{imm}]")
    else:
        print(f"  0x{off:05X}: 0x{w:08X} (unknown)")

print(f"\n=== 3. String at 0x5BF06 ===")
s = pe[0x5BF06:0x5BF06+20]
print(f"  Raw: {' '.join(f'{b:02X}' for b in s)}")
print(f"  ASCII: {s[:13].decode('ascii', errors='replace')}")

print(f"\n=== 4. Context around 0x30A94 (ReadWritePartition) ===")
for off in range(0x30A70, 0x30AE0, 4):
    w = u32(off)
    # Decode common instructions
    if (w >> 26) == 0x25:
        imm = w & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        target = (off + imm * 4) & 0xFFFFFFFF
        known = {0x18248: "ReadWritePartition", 0x28574: "DebugCheck", 0x280FC: "DebugPrint",
                 0x384A0: "func_384A0", 0x384D0: "init_defaults", 0x285A0: "DebugCheck2",
                 0x01370: "LocateProtocol", 0x0D4A4: "FreePool"}
        print(f"  0x{off:05X}: BL 0x{target:05X} {known.get(target, '')}")
    elif w == 0xD65F03C0:
        print(f"  0x{off:05X}: RET")
    elif (w & 0x9F000000) == 0x90000000:
        rd = w & 0x1F
        immlo = (w >> 29) & 0x3; immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000: imm |= ~0x1FFFFF
        page = ((off & ~0xFFF) + (imm << 12)) & 0xFFFFFFFF
        print(f"  0x{off:05X}: ADRP x{rd}, 0x{page:X}")
    elif (w & 0xFF800000) == 0x91000000:
        rd = w & 0x1F; rn = (w >> 5) & 0x1F
        imm12 = (w >> 10) & 0xFFF; sh = (w >> 22) & 1
        if sh: imm12 <<= 12
        print(f"  0x{off:05X}: ADD x{rd}, x{rn}, #0x{imm12:X}")
    elif (w & 0xFF800000) == 0x52800000:
        rd = w & 0x1F; imm = (w >> 5) & 0xFFFF
        print(f"  0x{off:05X}: MOV w{rd}, #{imm}")
    elif (w & 0xFFE0FFE0) == 0xAA0003E0:
        rd = w & 0x1F; rm = (w >> 16) & 0x1F
        print(f"  0x{off:05X}: MOV x{rd}, x{rm}")
    elif (w & 0xFFE0FFE0) == 0x2A0003E0:
        rd = w & 0x1F; rm = (w >> 16) & 0x1F
        print(f"  0x{off:05X}: MOV w{rd}, w{rm}")
    else:
        print(f"  0x{off:05X}: 0x{w:08X}")

print(f"\n=== 5. DevInfoPtr getter at 0x22C58 ===")
for off in range(0x22C58, 0x22C70, 4):
    w = u32(off)
    if (w & 0x9F000000) == 0x90000000:
        rd = w & 0x1F
        immlo = (w >> 29) & 0x3; immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000: imm |= ~0x1FFFFF
        page = ((off & ~0xFFF) + (imm << 12)) & 0xFFFFFFFF
        print(f"  0x{off:05X}: ADRP x{rd}, 0x{page:X}")
    elif (w & 0xFF800000) == 0x91000000:
        rd = w & 0x1F; rn = (w >> 5) & 0x1F
        imm12 = (w >> 10) & 0xFFF
        print(f"  0x{off:05X}: ADD x{rd}, x{rn}, #0x{imm12:X}")
    elif (w & 0xFFC00000) == 0xF9000000:
        rt = w & 0x1F; rn = (w >> 5) & 0x1F; imm = ((w >> 10) & 0xFFF) * 8
        print(f"  0x{off:05X}: STR x{rt}, [x{rn}, #{imm}]")
    elif w == 0xD65F03C0:
        print(f"  0x{off:05X}: RET")
    else:
        print(f"  0x{off:05X}: 0x{w:08X}")

# Find callers of GetDevInfoPtr (0x22C58)
callers = []
for addr in range(0x1000, 0x6A000, 4):
    w = u32(addr)
    if (w >> 26) == 0x25:
        imm = w & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        target = (addr + imm * 4) & 0xFFFFFFFF
        if target == 0x22C58:
            callers.append(addr)
print(f"\n  GetDevInfoPtr callers: {len(callers)} → {[f'0x{a:05X}' for a in callers]}")

print(f"\n=== 6. Check CSEL at 0x4C11C (device-info handler) ===")
w = u32(0x4C11C)
print(f"  0x4C11C: 0x{w:08X}")
sf = (w >> 31) & 1
op = (w >> 30) & 1
S = (w >> 29) & 1
rm = (w >> 16) & 0x1F
cond = (w >> 12) & 0xF
o2 = (w >> 10) & 0x3
rn = (w >> 5) & 0x1F
rd = w & 0x1F
conds = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
print(f"  sf={sf}, op={op}, S={S}")
print(f"  Rm=x{rm}, cond={conds[cond]}, Rn=x{rn}, Rd=x{rd}")
if op == 0 and o2 == 0:
    print(f"  CSEL x{rd}, x{rn}, x{rm}, {conds[cond]}")
    print(f"  → if {conds[cond]} is true: x{rd} = x{rn}")
    print(f"  → if {conds[cond]} is false: x{rd} = x{rm}")

# After TST w0, #0xFF (IsDeviceUnlocked returns 0 or 1):
# Z=1 when w0=0 (locked), Z=0 when w0!=0 (unlocked)
# EQ is true when Z=1
# So: EQ true (locked) → x3 = x25 (should be "false")
#     EQ false (unlocked) → x3 = x24 (should be "true")
print(f"\n  After TST w0, #0xFF:")
print(f"  - If w0=0 (locked): Z=1, EQ true → x{rd} = x{rn} (x25)")
print(f"  - If w0=1 (unlocked): Z=0, EQ false → x{rd} = x{rm} (x24)")

print(f"\n=== 7. Check x24/x25 setup (search backwards from 0x4C0F0) ===")
for off in range(0x4C080, 0x4C100, 4):
    w = u32(off)
    if (w & 0x9F000000) == 0x90000000:
        rd = w & 0x1F
        immlo = (w >> 29) & 0x3; immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000: imm |= ~0x1FFFFF
        page = ((off & ~0xFFF) + (imm << 12)) & 0xFFFFFFFF
        print(f"  0x{off:05X}: ADRP x{rd}, 0x{page:X}")
    elif (w & 0xFF800000) == 0x91000000:
        rd = w & 0x1F; rn = (w >> 5) & 0x1F
        imm12 = (w >> 10) & 0xFFF
        print(f"  0x{off:05X}: ADD x{rd}, x{rn}, #0x{imm12:X}")
    else:
        print(f"  0x{off:05X}: 0x{w:08X}")

# Check what strings x24 and x25 point to
# From 0x4C0F0: ADD x24, x24, #0xDC8
# From 0x4C0F4: ADD x25, x25, #0xB65
# We need the ADRP that set up x24 and x25
# Let's check strings at approximate addresses

print(f"\n=== 8. Partition name at 0x69BE0 ===")
s = pe[0x69BE0:0x69BF0]
print(f"  Raw: {' '.join(f'{b:02X}' for b in s)}")
# Try as UTF-16
parts = []
for i in range(0, min(32, len(s)), 2):
    ch = struct.unpack_from('<H', s, i)[0]
    if ch == 0: break
    if 32 <= ch < 127:
        parts.append(chr(ch))
    else:
        parts.append(f'<{ch:04X}>')
print(f"  UTF-16: {''.join(parts)}")

# Also check 0x69C10 (the other partition)
print(f"\n  Partition name at 0x69C10:")
s2 = pe[0x69C10:0x69C30]
print(f"  Raw: {' '.join(f'{b:02X}' for b in s2)}")
parts2 = []
for i in range(0, min(32, len(s2)), 2):
    ch = struct.unpack_from('<H', s2, i)[0]
    if ch == 0: break
    if 32 <= ch < 127:
        parts2.append(chr(ch))
    else:
        parts2.append(f'<{ch:04X}>')
print(f"  UTF-16: {''.join(parts2)}")

print(f"\n=== 9. Check what 0x1B990 does (called before ReadDeviceInfo) ===")
for off in range(0x1B990, 0x1BA10, 4):
    w = u32(off)
    if (w >> 26) == 0x25:
        imm = w & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        target = (off + imm * 4) & 0xFFFFFFFF
        print(f"  0x{off:05X}: BL 0x{target:05X}")
    elif (w & 0x9F000000) == 0x90000000:
        rd = w & 0x1F
        immlo = (w >> 29) & 0x3; immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000: imm |= ~0x1FFFFF
        page = ((off & ~0xFFF) + (imm << 12)) & 0xFFFFFFFF
        print(f"  0x{off:05X}: ADRP x{rd}, 0x{page:X}")
    elif (w & 0xFF800000) == 0x91000000:
        rd = w & 0x1F; rn = (w >> 5) & 0x1F; imm12 = (w >> 10) & 0xFFF
        print(f"  0x{off:05X}: ADD x{rd}, x{rn}, #0x{imm12:X}")
    elif w == 0xD65F03C0:
        print(f"  0x{off:05X}: RET")
    elif (w & 0xFFC00000) == 0xF9400000:
        rt = w & 0x1F; rn = (w >> 5) & 0x1F; imm = ((w >> 10) & 0xFFF) * 8
        print(f"  0x{off:05X}: LDR x{rt}, [x{rn}, #{imm}]")
    elif (w & 0xFFC00000) == 0xF9000000:
        rt = w & 0x1F; rn = (w >> 5) & 0x1F; imm = ((w >> 10) & 0xFFF) * 8
        print(f"  0x{off:05X}: STR x{rt}, [x{rn}, #{imm}]")
    else:
        print(f"  0x{off:05X}: 0x{w:08X}")

# Check if 0x1B990 accesses devinfo
print(f"\n  Searching 0x1B990-0x1BA80 for ADRP 0x1BD000:")
for a in range(0x1B990, 0x1BA80, 4):
    w = u32(a)
    if (w & 0x9F000000) == 0x90000000:
        rd = w & 0x1F
        immlo = (w >> 29) & 0x3; immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000: imm |= ~0x1FFFFF
        page = ((a & ~0xFFF) + (imm << 12)) & 0xFFFFFFFF
        if page == 0x1BD000:
            print(f"  FOUND at 0x{a:05X}")

print("\n=== 10. Larger context: 0x30940-0x30AA0 (ProtocolInit error path) ===")
for off in range(0x30940, 0x30AA0, 4):
    w = u32(off)
    if (w >> 26) == 0x25:
        imm = w & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        target = (off + imm * 4) & 0xFFFFFFFF
        known = {0x18248: "ReadWritePartition", 0x28574: "DebugCheck", 0x280FC: "DebugPrint",
                 0x384A0: "func_384A0", 0x384D0: "init_defaults", 0x285A0: "DebugCheck2",
                 0x0D4A4: "FreePool", 0x22C18: "IsDeviceUnlocked"}
        print(f"  0x{off:05X}: BL 0x{target:05X} {known.get(target, '')}")
    elif (w >> 26) == 0x05:
        imm = w & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        target = (off + imm * 4) & 0xFFFFFFFF
        print(f"  0x{off:05X}: B 0x{target:05X}")
    elif w == 0xD65F03C0:
        print(f"  0x{off:05X}: RET")
    elif (w & 0x9F000000) == 0x90000000:
        rd = w & 0x1F
        immlo = (w >> 29) & 0x3; immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000: imm |= ~0x1FFFFF
        page = ((off & ~0xFFF) + (imm << 12)) & 0xFFFFFFFF
        print(f"  0x{off:05X}: ADRP x{rd}, 0x{page:X}")
    elif (w & 0xFF800000) == 0x91000000:
        rd = w & 0x1F; rn = (w >> 5) & 0x1F; imm12 = (w >> 10) & 0xFFF
        print(f"  0x{off:05X}: ADD x{rd}, x{rn}, #0x{imm12:X}")
    elif (w & 0xFF800000) == 0x52800000:
        rd = w & 0x1F; imm = (w >> 5) & 0xFFFF
        print(f"  0x{off:05X}: MOV w{rd}, #{imm}")
    elif (w & 0xFF000000) == 0xB4000000:
        rt = w & 0x1F; imm19 = (w >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x7FFFF
        target = (off + imm19*4) & 0xFFFFFFFF
        print(f"  0x{off:05X}: CBZ x{rt}, 0x{target:05X}")
    elif (w & 0xFF000010) == 0x54000000:
        cond = w & 0xF; imm19 = (w >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x3FFFF
        target = (off + imm19*4) & 0xFFFFFFFF
        conds = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
        print(f"  0x{off:05X}: B.{conds[cond]} 0x{target:05X}")
    elif (w & 0xFFE0FFE0) == 0xAA0003E0:
        rd = w & 0x1F; rm = (w >> 16) & 0x1F
        print(f"  0x{off:05X}: MOV x{rd}, x{rm}")
    elif (w & 0xFFE0FFE0) == 0x2A0003E0:
        rd = w & 0x1F; rm = (w >> 16) & 0x1F
        print(f"  0x{off:05X}: MOV w{rd}, w{rm}")
    elif (w & 0xFFC00000) == 0x39400000:
        rt = w & 0x1F; rn = (w >> 5) & 0x1F; imm = (w >> 10) & 0xFFF
        print(f"  0x{off:05X}: LDRB w{rt}, [x{rn}, #{imm}]")
    elif (w & 0xFFC00000) == 0x39000000:
        rt = w & 0x1F; rn = (w >> 5) & 0x1F; imm = (w >> 10) & 0xFFF
        print(f"  0x{off:05X}: STRB w{rt}, [x{rn}, #{imm}]")
    elif (w & 0xFFC00000) == 0xB9400000:
        rt = w & 0x1F; rn = (w >> 5) & 0x1F; imm = ((w >> 10) & 0xFFF) * 4
        print(f"  0x{off:05X}: LDR w{rt}, [x{rn}, #{imm}]")
    elif (w & 0xFFC00000) == 0xB9000000:
        rt = w & 0x1F; rn = (w >> 5) & 0x1F; imm = ((w >> 10) & 0xFFF) * 4
        print(f"  0x{off:05X}: STR w{rt}, [x{rn}, #{imm}]")
    elif (w & 0xFFC00000) == 0xF9400000:
        rt = w & 0x1F; rn = (w >> 5) & 0x1F; imm = ((w >> 10) & 0xFFF) * 8
        print(f"  0x{off:05X}: LDR x{rt}, [x{rn}, #{imm}]")
    elif (w & 0xFFC00000) == 0xF9000000:
        rt = w & 0x1F; rn = (w >> 5) & 0x1F; imm = ((w >> 10) & 0xFFF) * 8
        print(f"  0x{off:05X}: STR x{rt}, [x{rn}, #{imm}]")
    elif (w & 0x7F000000) == 0x37000000:
        rt = w & 0x1F; bit = ((w >> 31) << 5) | ((w >> 19) & 0x1F)
        imm14 = (w >> 5) & 0x3FFF
        if imm14 & 0x2000: imm14 |= ~0x3FFF
        target = (off + imm14*4) & 0xFFFFFFFF
        op = "TBNZ" if (w >> 24) & 1 else "TBZ"
        print(f"  0x{off:05X}: {op} w{rt}, #{bit}, 0x{target:05X}")
    elif (w & 0xFF800000) == 0x71000000:
        rn = (w >> 5) & 0x1F; imm12 = (w >> 10) & 0xFFF
        print(f"  0x{off:05X}: CMP w{rn}, #{imm12}")
    elif (w & 0xFFFFFC1F) == 0xD63F0000:
        rn = (w >> 5) & 0x1F
        print(f"  0x{off:05X}: BLR x{rn}")
    else:
        print(f"  0x{off:05X}: 0x{w:08X}")

print("\nDone.")
