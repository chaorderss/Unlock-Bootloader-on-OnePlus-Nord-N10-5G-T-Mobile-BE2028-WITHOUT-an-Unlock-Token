#!/usr/bin/env python3
"""
Check BLR indirect calls at 0x36878 and 0x3688C in boot function.
Trace where x8 comes from for each call.
Also check the OemCheckResetDevInfo parameter (what value does boot function pass?).
"""
import struct

PE = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
with open(PE, "rb") as f:
    pe = f.read()

def r32(off):
    return struct.unpack_from('<I', pe, off)[0]

def decode(off, inst):
    s = f"  0x{off:05X}: 0x{inst:08X}"
    if inst == 0xD65F03C0: return s + "  RET"
    if (inst >> 26) == 0x25:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        t = off + (imm << 2)
        return s + f"  BL 0x{t & 0xFFFFFFFF:05X}"
    if (inst >> 26) == 0x05:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        t = off + (imm << 2)
        return s + f"  B 0x{t & 0xFFFFFFFF:05X}"
    if (inst & 0xFF000010) == 0x54000000:
        imm19 = (inst >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x7FFFF
        t = off + (imm19 << 2)
        cond = inst & 0xF
        conds = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
        return s + f"  B.{conds[cond]} 0x{t & 0xFFFFFFFF:05X}"
    if (inst & 0x7E000000) == 0x34000000:
        sf = (inst >> 31) & 1; op = (inst >> 24) & 1; rt = inst & 0x1F
        imm19 = (inst >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x7FFFF
        t = off + (imm19 << 2)
        rn = f"x{rt}" if sf else f"w{rt}"
        mn = "CBNZ" if op else "CBZ"
        return s + f"  {mn} {rn}, 0x{t & 0xFFFFFFFF:05X}"
    if (inst & 0x7E000000) == 0x36000000:
        op = (inst >> 24) & 1
        b5 = (inst >> 31) & 1; b40 = (inst >> 19) & 0x1F
        bit = (b5 << 5) | b40
        rt = inst & 0x1F
        imm14 = (inst >> 5) & 0x3FFF
        if imm14 & 0x2000: imm14 |= ~0x3FFF
        t = off + (imm14 << 2)
        mn = "TBNZ" if op else "TBZ"
        return s + f"  {mn} x{rt}, #{bit}, 0x{t & 0xFFFFFFFF:05X}"
    if (inst & 0x9F000000) == 0x90000000:
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF; immlo = (inst >> 29) & 0x3
        iv = (immhi << 2) | immlo
        if iv & 0x100000: iv |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
        return s + f"  ADRP x{rd}, 0x{pg:X}"
    if (inst & 0xFF800000) == 0x91000000:
        rd = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm12 = (inst >> 10) & 0xFFF
        sh = (inst >> 22) & 1
        if sh: imm12 <<= 12
        return s + f"  ADD x{rd}, x{rn}, #0x{imm12:X}"
    if (inst & 0xFFFFFC1F) == 0xD63F0000:
        rn = (inst >> 5) & 0x1F
        return s + f"  BLR x{rn}"
    if (inst & 0xFFFFFC1F) == 0xD61F0000:
        rn = (inst >> 5) & 0x1F
        return s + f"  BR x{rn}"
    if (inst & 0xFFC00000) == 0xF9400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 8
        return s + f"  LDR x{rt}, [x{rn}, #{imm}]"
    if (inst & 0xFFC00000) == 0xF9000000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 8
        return s + f"  STR x{rt}, [x{rn}, #{imm}]"
    if (inst & 0xFFC00000) == 0xB9400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 4
        return s + f"  LDR w{rt}, [x{rn}, #{imm}]"
    if (inst & 0xFFC00000) == 0xB9000000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 4
        return s + f"  STR w{rt}, [x{rn}, #{imm}]"
    if (inst & 0xFFC00000) == 0x39000000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = (inst >> 10) & 0xFFF
        return s + f"  STRB w{rt}, [x{rn}, #{imm}]"
    if (inst & 0xFFC00000) == 0x39400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = (inst >> 10) & 0xFFF
        return s + f"  LDRB w{rt}, [x{rn}, #{imm}]"
    if (inst & 0xFF800000) == 0x52800000:
        rd = inst & 0x1F; imm16 = (inst >> 5) & 0xFFFF; hw = (inst >> 21) & 0x3
        return s + f"  MOV w{rd}, #0x{imm16 << (hw*16):X}"
    if (inst & 0xFF800000) == 0xD2800000:
        rd = inst & 0x1F; imm16 = (inst >> 5) & 0xFFFF; hw = (inst >> 21) & 0x3
        return s + f"  MOV x{rd}, #0x{imm16 << (hw*16):X}"
    if (inst & 0xFF3FFC00) == 0xAA1F0000:
        rd = inst & 0x1F; rm = (inst >> 16) & 0x1F
        return s + f"  MOV x{rd}, x{rm}"
    if (inst & 0xFF3FFC00) == 0x2A1F0000:
        rd = inst & 0x1F; rm = (inst >> 16) & 0x1F
        return s + f"  MOV w{rd}, w{rm}"
    return s

# Full boot function disassembly around the BLR calls
print("=" * 70)
print("Boot function 0x367F0 — full disassembly 0x367F0-0x36A00")
print("=" * 70)
for off in range(0x367F0, 0x36A00, 4):
    print(decode(off, r32(off)))

# Now specifically trace x8 before BLR x8 at 0x36878
print("\n" + "=" * 70)
print("Trace x8 source before BLR x8 at 0x36878")
print("=" * 70)
# Disassemble from function entry to BLR
for off in range(0x36850, 0x36880, 4):
    print(decode(off, r32(off)))

# Trace x8 source before BLR x8 at 0x3688C
print("\n" + "=" * 70)
print("Trace x8 source before BLR x8 at 0x3688C")
print("=" * 70)
for off in range(0x36878, 0x36898, 4):
    print(decode(off, r32(off)))

# Check the OemCheckResetDevInfo call — what parameter?
# The caller is at 0x368A4, check what w0 is before the call
print("\n" + "=" * 70)
print("Before OemCheckResetDevInfo call at 0x368A4 — trace w0")
print("=" * 70)
for off in range(0x36890, 0x368B0, 4):
    print(decode(off, r32(off)))

# Check ProcessParams at 0x34E50 — does it modify devinfo?
print("\n" + "=" * 70)
print("ProcessParams 0x34E50 — first 60 instructions")
print("=" * 70)
has_devinfo = False
for off in range(0x34E50, 0x34F80, 4):
    inst = r32(off)
    d = decode(off, inst)
    # Check for ADRP 0x1BD000
    if (inst & 0x9F000000) == 0x90000000:
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF; immlo = (inst >> 29) & 0x3
        iv = (immhi << 2) | immlo
        if iv & 0x100000: iv |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
        if pg == 0x1BD000:
            d += " ★ DEVINFO PAGE!"
            has_devinfo = True
    print(d)
    if inst == 0xD65F03C0:
        break
if not has_devinfo:
    print("  → No ADRP to 0x1BD000 in ProcessParams first 0x130 bytes")

# Wider ProcessParams check — scan entire function for ADRP 0x1BD000
print("\n  Scanning 0x34E50-0x362D0 for ADRP 0x1BD000...")
for off in range(0x34E50, 0x362D0, 4):
    inst = r32(off)
    if (inst & 0x9F000000) == 0x90000000:
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF; immlo = (inst >> 29) & 0x3
        iv = (immhi << 2) | immlo
        if iv & 0x100000: iv |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
        if pg == 0x1BD000:
            print(f"  ★ ADRP x{rd}, 0x1BD000 at 0x{off:05X}")
            for off2 in range(off, min(off+20, 0x362D0), 4):
                print(f"    {decode(off2, r32(off2))}")

# Check BLR callers — find ALL BLR instructions in boot function range
# and trace where the pointer comes from
print("\n" + "=" * 70)
print("ALL BLR instructions in 0x367F0-0x36A00")
print("=" * 70)
for off in range(0x367F0, 0x36A00, 4):
    inst = r32(off)
    if (inst & 0xFFFFFC1F) == 0xD63F0000:
        rn = (inst >> 5) & 0x1F
        print(f"\n  BLR x{rn} at 0x{off:05X}")
        # Search backwards for where x{rn} was loaded
        for back in range(off - 4, max(off - 60, 0x367F0), -4):
            bi = r32(back)
            # Check LDR xN, [xM, #imm] where N == rn
            if (bi & 0xFFC00000) == 0xF9400000:
                rt = bi & 0x1F
                if rt == rn:
                    rn2 = (bi >> 5) & 0x1F
                    imm = ((bi >> 10) & 0xFFF) * 8
                    print(f"    Loaded from: LDR x{rn}, [x{rn2}, #{imm}] at 0x{back:05X}")
                    # If loading from a known data address, check what's there
                    break
            # Check ADRP + ADD setting xN
            if (bi & 0x9F000000) == 0x90000000:
                rd = bi & 0x1F
                if rd == rn:
                    immhi = (bi >> 5) & 0x7FFFF; immlo = (bi >> 29) & 0x3
                    iv = (immhi << 2) | immlo
                    if iv & 0x100000: iv |= ~0x1FFFFF
                    pg = ((back & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
                    print(f"    Set via ADRP x{rn}, 0x{pg:X} at 0x{back:05X}")
                    break

# Check init_defaults (0x384D0) — confirm it sets devinfo[13]
print("\n" + "=" * 70)
print("init_defaults 0x384D0 — full disassembly")
print("=" * 70)
for off in range(0x384D0, 0x38600, 4):
    d = decode(off, r32(off))
    inst = r32(off)
    # Highlight stores to devinfo
    if (inst & 0xFFC00000) == 0x39000000:
        rn = (inst >> 5) & 0x1F; imm = (inst >> 10) & 0xFFF
        if imm in [13, 14, 15, 144, 148]:
            d += f"  ★★★ devinfo[{imm}]"
    print(d)
    if inst == 0xD65F03C0:
        break

# Check OemCheckResetDevInfo — does it receive param from boot function?
# At 0x362D8 entry, w0/x0 contains the parameter
# The boot function call is at 0x368A4: BL 0x362D8
# What is w0 at that point?
print("\n" + "=" * 70)
print("OemCheckResetDevInfo parameter trace")
print("=" * 70)
print("Checking what OemCheckResetDevInfo does with its parameter...")
# OemCheckResetDevInfo entry at 0x362D8
# Previously analyzed: at 0x363C4, checks CMP w0, #1
# If == 1: calls init_defaults. If != 1: skips.
# Let's find the CMP instruction
for off in range(0x362D8, 0x36400, 4):
    inst = r32(off)
    d = decode(off, inst)
    if (inst & 0xFF800000) == 0x71000000:  # CMP Wn, #imm
        rn = (inst >> 5) & 0x1F; imm12 = (inst >> 10) & 0xFFF
        d += f"  ← CMP w{rn}, #{imm12}"
    print(d)

print("\nDone.")
