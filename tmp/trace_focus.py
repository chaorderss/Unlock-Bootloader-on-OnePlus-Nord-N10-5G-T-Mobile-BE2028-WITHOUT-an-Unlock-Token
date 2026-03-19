#!/usr/bin/env python3
"""
Focus analysis:
1. What's at 0x189E0 vs 0x189E8?
2. Full SetDeviceUnlocked flow with the SECOND write
3. What does callers 0x02720 and 0x031A0 do (early boot calls to IsDeviceUnlocked)?
4. Boot sequence around 0x01500-0x01600 and 0x02700-0x03200
5. Trace the function 0x1D2E8 (calls SetDeviceUnlocked) — where is it called from?
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
         0x280FC: "DebugPrint", 0x01370: "LocateProtocol", 0x0D290: "AllocatePool",
         0x22C18: "IsDeviceUnlocked", 0x22C28: "IsUnlockCritical", 0x22C38: "GetVerityMode",
         0x22C48: "GetChargerScreen", 0x22CA8: "SetChargerScreen", 0x22D40: "SetVerityMode",
         0x22DB8: "SetDeviceUnlocked", 0x384D0: "init_defaults", 0x384B0: "SetIsUnlocked",
         0x38490: "GetCalRebootCount", 0x38430: "SetCalRebootCount",
         0x189E0: "func_189E0", 0x189E8: "func_189E8",
         0x232D8: "ReadDeviceInfo", 0x2A108: "GetVariable?", 0x2A888: "Assert?",
         0x29464: "SetVariable?", 0x2907C: "ReadFromFV?"}

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
    if (w & 0xFFC00000) == 0x39000000:
        imm=(w>>10)&0xFFF; rn=(w>>5)&0x1F; rt=w&0x1F
        s += f"  strb w{rt}, [x{rn}, #{imm}]"
    if (w & 0xFFC00000) == 0x39400000:
        imm=(w>>10)&0xFFF; rn=(w>>5)&0x1F; rt=w&0x1F
        s += f"  ldrb w{rt}, [x{rn}, #{imm}]"
    if (w & 0xFFC00000) == 0xB9000000:
        imm=((w>>10)&0xFFF)*4; rn=(w>>5)&0x1F; rt=w&0x1F
        s += f"  str w{rt}, [x{rn}, #{imm}]"
    if (w & 0xFFC00000) == 0xB9400000:
        imm=((w>>10)&0xFFF)*4; rn=(w>>5)&0x1F; rt=w&0x1F
        s += f"  ldr w{rt}, [x{rn}, #{imm}]"
    if (w & 0xFFC00000) == 0xF9000000:
        imm=((w>>10)&0xFFF)*8; rn=(w>>5)&0x1F; rt=w&0x1F
        s += f"  str x{rt}, [x{rn}, #{imm}]"
    if (w & 0xFFC00000) == 0xF9400000:
        imm=((w>>10)&0xFFF)*8; rn=(w>>5)&0x1F; rt=w&0x1F
        s += f"  ldr x{rt}, [x{rn}, #{imm}]"
    if (w & 0xFFE0FFE0) == 0xAA0003E0:
        rd=w&0x1F; rm=(w>>16)&0x1F; s += f"  mov x{rd}, x{rm}"
    if (w & 0xFFE0FFE0) == 0x2A0003E0:
        rd=w&0x1F; rm=(w>>16)&0x1F; s += f"  mov w{rd}, w{rm}"
    if (w & 0xFF800000) == 0x52800000:
        rd=w&0x1F; imm16=(w>>5)&0xFFFF; s += f"  mov w{rd}, #{imm16}"
    if (w & 0xFFFFFC1F) == 0xD63F0000:
        rn=(w>>5)&0x1F; s += f"  blr x{rn}"
    if (w & 0xFF000010) == 0x54000000:
        imm19=(w>>5)&0x7FFFF
        if imm19&0x40000: imm19-=0x80000
        target=off+imm19*4; cond=w&0xF
        conds={0:"EQ",1:"NE",2:"CS",3:"CC",4:"MI",5:"PL",6:"VS",7:"VC",8:"HI",9:"LS",10:"GE",11:"LT",12:"GT",13:"LE"}
        s += f"  b.{conds.get(cond,'?')} 0x{target:05X}"
    if (w & 0xFC000000) == 0x14000000:
        imm26=w&0x3FFFFFF
        if imm26&0x2000000: imm26-=0x4000000
        s += f"  b 0x{off+imm26*4:05X}"
    if (w & 0x7E000000) == 0x34000000:
        imm19=(w>>5)&0x7FFFF
        if imm19&0x40000: imm19-=0x80000
        rt=w&0x1F; op="cbz" if not((w>>24)&1) else "cbnz"
        is64=(w>>31)&1
        s += f"  {op} {'x' if is64 else 'w'}{rt}, 0x{off+imm19*4:05X}"
    if (w & 0x7E000000) == 0x36000000:
        bit=((w>>31)&1)<<5|((w>>19)&0x1F)
        imm14=(w>>5)&0x3FFF
        if imm14&0x2000: imm14-=0x4000
        rt=w&0x1F; op="tbnz" if(w>>24)&1 else "tbz"
        s += f"  {op} w{rt}, #{bit}, 0x{off+imm14*4:05X}"
    if (w & 0xFFE00C00) == 0x1A800400:
        rd=w&0x1F;rn=(w>>5)&0x1F;rm=(w>>16)&0x1F;cond=(w>>12)&0xF
        s += f"  csinc w{rd}, w{rn}, w{rm}, cond={cond}"
    if (w & 0xFFE00C00) == 0x1A800000:
        rd=w&0x1F;rn=(w>>5)&0x1F;rm=(w>>16)&0x1F;cond=(w>>12)&0xF
        s += f"  csel w{rd}, w{rn}, w{rm}, cond={cond}"
    if (w & 0xFF800000) == 0x72000000 or (w & 0xFF800000) == 0x12000000:
        rd=w&0x1F; rn=(w>>5)&0x1F; s += f"  ands/and w{rd}, w{rn}, #imm"
    if (w & 0xFFE00000) == 0x6B000000:
        rn=(w>>5)&0x1F; rm=(w>>16)&0x1F; s += f"  cmp w{rn}, w{rm}"
    if (w & 0xFFC00000) == 0x71000000:
        rn=(w>>5)&0x1F; imm12=(w>>10)&0xFFF; s += f"  cmp w{rn}, #{imm12}"
    return s

# 1. Functions at 0x189E0 and 0x189E8
print("=" * 70)
print("=== 0x189E0 and 0x189E8 — IsSecureBootEnabled area ===")
print("=" * 70)
for off in range(0x189C0, 0x18A40, 4):
    print(annotate(off))

# 2. Early boot callers of IsDeviceUnlocked
print("\n" + "=" * 70)
print("=== 0x02700-0x02780 — Early boot caller of IsDeviceUnlocked ===")
print("=" * 70)
for off in range(0x02700, 0x02780, 4):
    print(annotate(off))

print("\n" + "=" * 70)
print("=== 0x03180-0x03200 — Early boot caller of IsDeviceUnlocked ===")
print("=" * 70)
for off in range(0x03180, 0x03200, 4):
    print(annotate(off))

# 3. Boot sequence 0x01500-0x016A0 (around ReadDeviceInfo call at 0x01558)
print("\n" + "=" * 70)
print("=== 0x01500-0x016A0 — Boot init (ReadDeviceInfo caller) ===")
print("=" * 70)
for off in range(0x01500, 0x016A0, 4):
    print(annotate(off))

# 4. Function at 0x1D2E8 (caller of SetDeviceUnlocked), trace context
print("\n" + "=" * 70)
print("=== 0x1D2E8-0x1D400 — SetDeviceUnlocked caller ===")
print("=" * 70)
for off in range(0x1D2E8, 0x1D400, 4):
    print(annotate(off))

# 5. Search for function pointer to 0x1D2E8 in both code and data sections
print("\n" + "=" * 70)
print("=== Search: 0x1D2E8 as function pointer ===")
print("=" * 70)
needle64 = struct.pack("<Q", 0x1D2E8)
needle32 = struct.pack("<I", 0x1D2E8)
for n, name in [(needle64, "64-bit"), (needle32, "32-bit")]:
    pos = 0
    while True:
        idx = pe.find(n, pos)
        if idx < 0: break
        # Skip BL instructions
        if len(n) == 4 and idx < CODE_END and idx % 4 == 0:
            w = struct.unpack_from("<I", pe, idx)[0]
            if (w >> 26) in (0x25, 0x05):
                pos = idx + 1
                continue
        print(f"  {name}: found at PE offset 0x{idx:X}")
        pos = idx + 1

# Also search for nearby addresses (0x1D2E0-0x1D310)
for addr in range(0x1D2E0, 0x1D320, 8):
    needle = struct.pack("<Q", addr)
    idx = pe.find(needle, 0x6A000)  # search only in data section
    if idx >= 0:
        print(f"  64-bit 0x{addr:05X} found in data at 0x{idx:X}")

# 6. 0x46DE0 caller of IsDeviceUnlocked (in fastboot init area)
print("\n" + "=" * 70)
print("=== 0x46DC0-0x46E40 — Fastboot IsDeviceUnlocked caller ===")
print("=" * 70)
for off in range(0x46DC0, 0x46E40, 4):
    print(annotate(off))

# 7. ReadDeviceInfo full (0x232D8-0x233A8)
print("\n" + "=" * 70)
print("=== ReadDeviceInfo (0x232D8) — FULL ===")
print("=" * 70)
for off in range(0x232D8, 0x233B0, 4):
    print(annotate(off))

# 8. Callers of 0x189E8
print("\n" + "=" * 70)
print("=== Callers of 0x189E8 ===")
print("=" * 70)
callers = []
for off in range(CODE_START, CODE_END, 4):
    w = u32(off)
    bl = decode_bl(w, off)
    if bl == 0x189E8:
        callers.append(off)
print(f"BL 0x189E8: {len(callers)} callers → {', '.join(f'0x{c:05X}' for c in callers)}")

# 9. OemCheckResetDevInfo region (0x362D8-0x366A0)
print("\n" + "=" * 70)
print("=== OemCheckResetDevInfo (0x362D8-0x366A0) — FULL ===")
print("=" * 70)
for off in range(0x362D8, 0x366A0, 4):
    print(annotate(off))

print("\nDone.")
