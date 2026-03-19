#!/usr/bin/env python3
"""Targeted deep trace:
1. Disasm 0x22C00-0x23500 (IsDeviceUnlocked + SetDeviceUnlocked + ReadDeviceInfo region)
2. Disasm 0x38400-0x38600 (SetIsUnlocked + init_defaults region)
3. Find enclosing function for 0x22E10 more carefully
4. Find ALL callers of IsDeviceUnlocked (at 0x22C18 if it's just 3 instructions)
5. Check 0x384B0 ADRP+ADD
"""
import struct

PE = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
pe = open(PE, "rb").read()
CODE_START = 0x1000
CODE_END = 0x6A000

def u32(off):
    return struct.unpack_from("<I", pe, off)[0] if off + 4 <= len(pe) else 0

def decode_bl(w, pc):
    if (w >> 26) == 0x25:
        imm26 = w & 0x3FFFFFF
        if imm26 & 0x2000000: imm26 -= 0x4000000
        return pc + imm26 * 4
    return None

def decode_adrp(w, pc):
    if (w & 0x9F000000) == 0x90000000:
        immhi = (w >> 5) & 0x7FFFF
        immlo = (w >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm & 0x100000: imm -= 0x200000
        return (pc & ~0xFFF) + (imm << 12)
    return None

def decode_add_imm(w):
    if (w & 0x7F800000) == 0x11000000:
        shift = (w >> 22) & 1
        imm12 = (w >> 10) & 0xFFF
        if shift: imm12 <<= 12
        rd = w & 0x1F
        rn = (w >> 5) & 0x1F
        return rd, rn, imm12
    return None

known = {0x18248: "ReadWritePartition", 0x28574: "DebugCheck", 0x285A0: "DebugCheck2",
         0x280FC: "DebugPrint", 0x4FE50: "SetMem", 0x4FD10: "CompareMem",
         0x01370: "LocateProtocol", 0x0D290: "AllocatePool", 0x189E0: "?",
         0x4C850: "?", 0x46700: "?"}

def annotate(off):
    w = u32(off)
    s = f"0x{off:05X}: 0x{w:08X}"
    bl = decode_bl(w, off)
    if bl is not None:
        s += f"  bl 0x{bl:05X}"
        if bl in known: s += f" ← {known[bl]}"
    if w == 0xD65F03C0: s += "  ret"
    adrp = decode_adrp(w, off)
    if adrp is not None: s += f"  adrp x{w&0x1F}, 0x{adrp:X}"
    add = decode_add_imm(w)
    if add: s += f"  add x{add[0]}, x{add[1]}, #0x{add[2]:X}"
    # STRB
    if (w & 0xFFC00000) == 0x39000000:
        imm=(w>>10)&0xFFF; rn=(w>>5)&0x1F; rt=w&0x1F
        s += f"  strb w{rt}, [x{rn}, #{imm}]"
    # LDRB
    if (w & 0xFFC00000) == 0x39400000:
        imm=(w>>10)&0xFFF; rn=(w>>5)&0x1F; rt=w&0x1F
        s += f"  ldrb w{rt}, [x{rn}, #{imm}]"
    # STR Wt
    if (w & 0xFFC00000) == 0xB9000000:
        imm=((w>>10)&0xFFF)*4; rn=(w>>5)&0x1F; rt=w&0x1F
        s += f"  str w{rt}, [x{rn}, #{imm}]"
    # LDR Wt
    if (w & 0xFFC00000) == 0xB9400000:
        imm=((w>>10)&0xFFF)*4; rn=(w>>5)&0x1F; rt=w&0x1F
        s += f"  ldr w{rt}, [x{rn}, #{imm}]"
    # STR Xt
    if (w & 0xFFC00000) == 0xF9000000:
        imm=((w>>10)&0xFFF)*8; rn=(w>>5)&0x1F; rt=w&0x1F
        s += f"  str x{rt}, [x{rn}, #{imm}]"
    # LDR Xt
    if (w & 0xFFC00000) == 0xF9400000:
        imm=((w>>10)&0xFFF)*8; rn=(w>>5)&0x1F; rt=w&0x1F
        s += f"  ldr x{rt}, [x{rn}, #{imm}]"
    # MOV Xd, Xn
    if (w & 0xFFE0FFE0) == 0xAA0003E0:
        rd=w&0x1F; rm=(w>>16)&0x1F; s += f"  mov x{rd}, x{rm}"
    # MOV Wd, Wn
    if (w & 0xFFE0FFE0) == 0x2A0003E0:
        rd=w&0x1F; rm=(w>>16)&0x1F; s += f"  mov w{rd}, w{rm}"
    # MOV Wd, #imm
    if (w & 0xFF800000) == 0x52800000:
        rd=w&0x1F; imm16=(w>>5)&0xFFFF; s += f"  mov w{rd}, #{imm16}"
    # BLR
    if (w & 0xFFFFFC1F) == 0xD63F0000:
        rn=(w>>5)&0x1F; s += f"  blr x{rn}"
    # B.cond
    if (w & 0xFF000010) == 0x54000000:
        imm19=(w>>5)&0x7FFFF
        if imm19&0x40000: imm19-=0x80000
        target=off+imm19*4; cond=w&0xF
        conds={0:"EQ",1:"NE",2:"CS",3:"CC",4:"MI",5:"PL",6:"VS",7:"VC",8:"HI",9:"LS",10:"GE",11:"LT",12:"GT",13:"LE"}
        s += f"  b.{conds.get(cond,'?')} 0x{target:05X}"
    # B uncond
    if (w & 0xFC000000) == 0x14000000:
        imm26=w&0x3FFFFFF
        if imm26&0x2000000: imm26-=0x4000000
        s += f"  b 0x{off+imm26*4:05X}"
    # CBZ/CBNZ
    if (w & 0x7E000000) == 0x34000000:
        imm19=(w>>5)&0x7FFFF
        if imm19&0x40000: imm19-=0x80000
        rt=w&0x1F; op="cbz" if not((w>>24)&1) else "cbnz"
        s += f"  {op} w{rt}, 0x{off+imm19*4:05X}"
    # TBNZ/TBZ
    if (w & 0x7E000000) == 0x36000000:
        bit=((w>>31)&1)<<5|((w>>19)&0x1F)
        imm14=(w>>5)&0x3FFF
        if imm14&0x2000: imm14-=0x4000
        rt=w&0x1F; op="tbnz" if(w>>24)&1 else "tbz"
        s += f"  {op} w{rt}, #{bit}, 0x{off+imm14*4:05X}"
    # CSINC
    if (w & 0xFFE00C00) == 0x1A800400:
        rd=w&0x1F;rn=(w>>5)&0x1F;rm=(w>>16)&0x1F;cond=(w>>12)&0xF
        s += f"  csinc w{rd}, w{rn}, w{rm}, cond={cond}"
    # AND imm
    if (w & 0xFF800000) == 0x12000000:
        rd=w&0x1F; rn=(w>>5)&0x1F; s += f"  and w{rd}, w{rn}, #imm"
    if (w & 0xFF800000) == 0x72000000:
        rd=w&0x1F; rn=(w>>5)&0x1F; s += f"  tst/ands w{rd}, w{rn}, #imm"
    # CMP
    if (w & 0xFFE00000) == 0x6B000000:
        rn=(w>>5)&0x1F; rm=(w>>16)&0x1F; s += f"  cmp w{rn}, w{rm}"
    if (w & 0xFFC00000) == 0x71000000:
        rn=(w>>5)&0x1F; imm12=(w>>10)&0xFFF; s += f"  cmp w{rn}, #{imm12}"
    return s

# Section 1: Disassemble 0x22C00-0x23500
print("=" * 70)
print("=== Region 0x22C00-0x23500 (IsDeviceUnlocked, SetDeviceUnlocked, ReadDeviceInfo) ===")
print("=" * 70)
for off in range(0x22C00, 0x23500, 4):
    print(annotate(off))

# Section 2: Disassemble 0x38400-0x38600
print("\n" + "=" * 70)
print("=== Region 0x38400-0x38600 (SetIsUnlocked, init_defaults) ===")
print("=" * 70)
for off in range(0x38400, 0x38600, 4):
    print(annotate(off))

# Section 3: Find ALL callers of candidate IsDeviceUnlocked
print("\n" + "=" * 70)
print("=== ALL callers of candidate functions ===")
print("=" * 70)
# If IsDeviceUnlocked starts at 0x22C18, find callers
# But also check if maybe 0x22C00 or another nearby address is the real entry
for target in [0x22C18, 0x22C00, 0x22C10, 0x22C14, 0x22C1C]:
    callers = []
    for off in range(CODE_START, CODE_END, 4):
        w = u32(off)
        bl = decode_bl(w, off)
        if bl == target:
            callers.append(off)
    if callers:
        print(f"BL 0x{target:05X}: {len(callers)} callers → {', '.join(f'0x{c:05X}' for c in callers[:20])}")

# Also check for key nearby functions
for target in [0x22CA8, 0x22DB8, 0x232D8, 0x384D0, 0x384B0, 0x189E0, 0x38490]:
    callers = []
    for off in range(CODE_START, CODE_END, 4):
        w = u32(off)
        bl = decode_bl(w, off)
        if bl == target:
            callers.append(off)
    if callers:
        print(f"BL 0x{target:05X}: {len(callers)} callers → {', '.join(f'0x{c:05X}' for c in callers[:20])}")
    else:
        # Try nearby addresses
        for delta in range(-8, 12, 4):
            t2 = target + delta
            c2 = []
            for off in range(CODE_START, CODE_END, 4):
                w = u32(off)
                bl = decode_bl(w, off)
                if bl == t2:
                    c2.append(off)
            if c2:
                print(f"  (near 0x{target:05X}) BL 0x{t2:05X}: {len(c2)} callers → {', '.join(f'0x{c:05X}' for c in c2[:10])}")

print("\nDone.")
