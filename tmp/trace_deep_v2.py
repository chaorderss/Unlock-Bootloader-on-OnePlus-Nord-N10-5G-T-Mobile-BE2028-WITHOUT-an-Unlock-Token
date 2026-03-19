#!/usr/bin/env python3
"""
Deep trace v2: Read from PE binary (VA == PE offset), NOT text binary.
1. Full IsDeviceUnlocked (0x22C18) disassembly
2. Search for wider stores (STR/STP) to devinfo[13]
3. Function pointer search for init_defaults/SetDeviceUnlocked
4. Full 0x46920 (fastboot setup) disassembly
5. ALL callers of key functions
6. Full init_defaults disassembly
"""
import struct

PE = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
pe = open(PE, "rb").read()
CODE_START = 0x1000
CODE_END   = 0x6A000  # .text section: VA 0x1000 - 0x6A000

def u32(off):
    if off + 4 <= len(pe):
        return struct.unpack_from("<I", pe, off)[0]
    return 0

def decode_bl(w, pc):
    if (w >> 26) == 0x25:  # BL
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

known_funcs = {
    0x232D8: "ReadDeviceInfo", 0x22C18: "IsDeviceUnlocked?-OLD",
    0x22DB8: "SetDeviceUnlocked?-OLD", 0x384D0: "init_defaults?-OLD",
    0x189E0: "IsSecureBootEnabled?-OLD", 0x22CA8: "WriteDeviceInfo?-OLD",
    0x4C850: "FastbootPublish?-OLD", 0x384B0: "SetIsUnlocked?-OLD",
    0x18248: "ReadWritePartition?-OLD", 0x4FE50: "SetMem?",
    0x4FD10: "CompareMem?", 0x28574: "DebugCheck?",
}

def annotate(off, w):
    s = f"0x{off:05X}: 0x{w:08X}"
    bl = decode_bl(w, off)
    if bl is not None:
        s += f"  bl 0x{bl:05X}"
        if bl in known_funcs:
            s += f" ← {known_funcs[bl]}"
    if w == 0xD65F03C0:
        s += "  ret"
    adrp = decode_adrp(w, off)
    if adrp is not None:
        s += f"  adrp x{w&0x1F}, 0x{adrp:X}"
    add = decode_add_imm(w)
    if add:
        rd, rn, imm = add
        s += f"  add x{rd}, x{rn}, #0x{imm:X}"
    # STRB
    if (w & 0xFFC00000) == 0x39000000:
        imm = (w >> 10) & 0xFFF
        rn = (w >> 5) & 0x1F
        rt = w & 0x1F
        s += f"  strb w{rt}, [x{rn}, #{imm}]"
    # LDRB
    if (w & 0xFFC00000) == 0x39400000:
        imm = (w >> 10) & 0xFFF
        rn = (w >> 5) & 0x1F
        rt = w & 0x1F
        s += f"  ldrb w{rt}, [x{rn}, #{imm}]"
    # STR Wt
    if (w & 0xFFC00000) == 0xB9000000:
        imm = ((w >> 10) & 0xFFF) * 4
        rn = (w >> 5) & 0x1F
        rt = w & 0x1F
        s += f"  str w{rt}, [x{rn}, #{imm}]"
    # LDR Wt
    if (w & 0xFFC00000) == 0xB9400000:
        imm = ((w >> 10) & 0xFFF) * 4
        rn = (w >> 5) & 0x1F
        rt = w & 0x1F
        s += f"  ldr w{rt}, [x{rn}, #{imm}]"
    # STR Xt
    if (w & 0xFFC00000) == 0xF9000000:
        imm = ((w >> 10) & 0xFFF) * 8
        rn = (w >> 5) & 0x1F
        rt = w & 0x1F
        s += f"  str x{rt}, [x{rn}, #{imm}]"
    # LDR Xt
    if (w & 0xFFC00000) == 0xF9400000:
        imm = ((w >> 10) & 0xFFF) * 8
        rn = (w >> 5) & 0x1F
        rt = w & 0x1F
        s += f"  ldr x{rt}, [x{rn}, #{imm}]"
    # MOV Xd, Xn (ORR)
    if (w & 0xFFE0FFE0) == 0xAA0003E0:
        rd = w & 0x1F
        rm = (w >> 16) & 0x1F
        s += f"  mov x{rd}, x{rm}"
    # MOV Wd, #imm (MOVZ)
    if (w & 0xFF800000) == 0x52800000:
        rd = w & 0x1F
        imm16 = (w >> 5) & 0xFFFF
        s += f"  mov w{rd}, #{imm16}"
    # BLR
    if (w & 0xFFFFFC1F) == 0xD63F0000:
        rn = (w >> 5) & 0x1F
        s += f"  blr x{rn}"
    # B.cond
    if (w & 0xFF000010) == 0x54000000:
        imm19 = (w >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 -= 0x80000
        target = off + imm19 * 4
        cond = w & 0xF
        conds = {0:"EQ",1:"NE",2:"CS",3:"CC",4:"MI",5:"PL",6:"VS",7:"VC",
                 8:"HI",9:"LS",10:"GE",11:"LT",12:"GT",13:"LE",14:"AL"}
        s += f"  b.{conds.get(cond,'?')} 0x{target:05X}"
    # B unconditional
    if (w & 0xFC000000) == 0x14000000:
        imm26 = w & 0x3FFFFFF
        if imm26 & 0x2000000: imm26 -= 0x4000000
        target = off + imm26 * 4
        s += f"  b 0x{target:05X}"
    # CBZ/CBNZ
    if (w & 0x7E000000) == 0x34000000:
        imm19 = (w >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 -= 0x80000
        target = off + imm19 * 4
        rt = w & 0x1F
        is64 = (w >> 31) & 1
        op = "cbz" if not ((w >> 24) & 1) else "cbnz"
        s += f"  {op} {'x' if is64 else 'w'}{rt}, 0x{target:05X}"
    # TBNZ/TBZ
    if (w & 0x7E000000) == 0x36000000:
        bit = ((w >> 31) & 1) << 5 | ((w >> 19) & 0x1F)
        imm14 = (w >> 5) & 0x3FFF
        if imm14 & 0x2000: imm14 -= 0x4000
        target = off + imm14 * 4
        rt = w & 0x1F
        op = "tbnz" if (w >> 24) & 1 else "tbz"
        s += f"  {op} w{rt}, #{bit}, 0x{target:05X}"
    # CSINC/CSEL
    if (w & 0xFFE00C00) == 0x1A800400:
        rd = w & 0x1F
        rn = (w >> 5) & 0x1F
        rm = (w >> 16) & 0x1F
        cond = (w >> 12) & 0xF
        s += f"  csinc w{rd}, w{rn}, w{rm}, cond={cond}"
    if (w & 0xFFE00C00) == 0x1A800000:
        rd = w & 0x1F
        rn = (w >> 5) & 0x1F
        rm = (w >> 16) & 0x1F
        cond = (w >> 12) & 0xF
        s += f"  csel w{rd}, w{rn}, w{rm}, cond={cond}"
    # STP pre/post
    if (w & 0xFE000000) in (0xA9000000, 0xA8000000, 0x29000000, 0x28000000):
        imm7 = (w >> 15) & 0x7F
        if imm7 & 0x40: imm7 -= 0x80
        s += f"  stp/ldp ..."
    return s

# ============================================================
# Step 0: Find REAL function addresses by searching known BL patterns
# ============================================================
print("=" * 70)
print("=== Step 0: Verify known BL targets from PE ===")
print("=" * 70)

# Find ALL callers of popular targets
def find_bl_callers(target):
    callers = []
    for off in range(CODE_START, CODE_END, 4):
        w = u32(off)
        bl = decode_bl(w, off)
        if bl == target:
            callers.append(off)
    return callers

# First, scan all BL instructions to build a frequency table of targets
print("\nBuilding BL target frequency table...")
bl_targets = {}
for off in range(CODE_START, CODE_END, 4):
    w = u32(off)
    bl = decode_bl(w, off)
    if bl is not None and CODE_START <= bl < CODE_END:
        bl_targets.setdefault(bl, []).append(off)

# Find functions called most often (likely library functions)
top_targets = sorted(bl_targets.items(), key=lambda x: -len(x[1]))[:30]
print("Top 30 BL targets:")
for target, callers in top_targets:
    print(f"  0x{target:05X}: {len(callers)} callers")

# ============================================================
# Step 1: Find ALL STRB Wt, [Xn, #13]
# ============================================================
print("\n" + "=" * 70)
print("=== Step 1: All STRB Wt, [Xn, #13] instructions ===")
print("=" * 70)
strb13_sites = []
for off in range(CODE_START, CODE_END, 4):
    w = u32(off)
    if (w & 0xFFFFFC00) == 0x39003400:
        rt = w & 0x1F
        rn = (w >> 5) & 0x1F
        strb13_sites.append((off, rn, rt))
        print(f"  0x{off:05X}: STRB w{rt}, [x{rn}, #13]")

# ============================================================
# Step 2: For each STRB to [Xn, #13], trace back ADRP+ADD to find target
# ============================================================
print("\n" + "=" * 70)
print("=== Step 2: ADRP+ADD context for STRB [Xn, #13] ===")
print("=" * 70)
devinfo_page = None
devinfo_offset = None
for off, rn, rt in strb13_sites:
    # Look backward up to 64 instructions for ADRP loading to rn
    for back in range(4, 260, 4):
        if off - back < CODE_START:
            break
        w_back = u32(off - back)
        adrp = decode_adrp(w_back, off - back)
        if adrp is not None and (w_back & 0x1F) == rn:
            # Found ADRP to rn, check for ADD after it
            w_add = u32(off - back + 4)
            add_res = decode_add_imm(w_add)
            if add_res:
                rd, rn_add, imm = add_res
                if rn_add == rn:
                    print(f"  STRB at 0x{off:05X}: ADRP at 0x{off-back:05X} → 0x{adrp:X}, ADD #0x{imm:X}")
                    print(f"    Full addr: 0x{adrp+imm:X} (buffer pointer)")
                    if devinfo_page is None:
                        devinfo_page = adrp
                        devinfo_offset = imm
                        print(f"    *** Likely devinfo buffer: page=0x{adrp:X} offset=0x{imm:X} ***")
                    elif adrp == devinfo_page and imm == devinfo_offset:
                        print(f"    *** SAME devinfo buffer ***")
                    break
            break

# ============================================================
# Step 3: Find function that contains each devinfo STRB site, then find BL callers
# ============================================================
print("\n" + "=" * 70)
print("=== Step 3: Enclosing functions and callers ===")
print("=" * 70)
# For each STRB site, look backward for function prologue (STP x29,x30 or STP x19,x30)
for off, rn, rt in strb13_sites:
    # Check if this STRB writes to devinfo buffer
    # Look back for ADRP+ADD targeting devinfo
    is_devinfo = False
    for back in range(4, 260, 4):
        if off - back < CODE_START:
            break
        w_back = u32(off - back)
        adrp = decode_adrp(w_back, off - back)
        if adrp is not None and (w_back & 0x1F) == rn:
            w_add = u32(off - back + 4)
            add_res = decode_add_imm(w_add)
            if add_res:
                rd, rn_add, imm = add_res
                if rn_add == rn and adrp == devinfo_page and imm == devinfo_offset:
                    is_devinfo = True
            break

    if not is_devinfo:
        continue

    # Find function start (look for STP with SP)
    func_start = None
    for back in range(0, 512, 4):
        if off - back < CODE_START:
            break
        w = u32(off - back)
        # STP Xn, Xm, [SP, #imm]! (pre-index) = 0xA9800000 range
        # Or STR X30, [SP, #-imm]!
        # Common patterns: STP x29, x30, [sp, #-N]!
        if (w & 0xFFE00000) == 0xA9800000:  # STP pre-index
            func_start = off - back
            break
        if (w & 0xFFE00000) == 0xF8000000:  # STR pre-index
            func_start = off - back
            break

    if func_start:
        print(f"\n  STRB at 0x{off:05X} → function likely starts at 0x{func_start:05X}")
        callers = find_bl_callers(func_start)
        if callers:
            print(f"    BL callers: {', '.join(f'0x{c:05X}' for c in callers)}")
        else:
            print(f"    NO direct BL callers found (may be called via function pointer)")

# ============================================================
# Step 4: IsDeviceUnlocked — find by searching for LDRB w0, [Xn, #13]
#         with devinfo buffer, then find function boundary
# ============================================================
print("\n" + "=" * 70)
print("=== Step 4: Find IsDeviceUnlocked (LDRB devinfo[13] + RET) ===")
print("=" * 70)
# LDRB Wt, [Xn, #13]: encoding = 0x39403400 | (Rn << 5) | Rt, mask = 0xFFFFFC00
for off in range(CODE_START, CODE_END, 4):
    w = u32(off)
    if (w & 0xFFFFFC00) == 0x39403400:
        rt = w & 0x1F
        rn = (w >> 5) & 0x1F
        # Check if Xn was loaded from devinfo buffer ADRP+ADD
        for back in range(4, 128, 4):
            if off - back < CODE_START:
                break
            wb = u32(off - back)
            adrp = decode_adrp(wb, off - back)
            if adrp == devinfo_page and (wb & 0x1F) == rn:
                wa = u32(off - back + 4)
                add_res = decode_add_imm(wa)
                if add_res and add_res[1] == rn and add_res[2] == devinfo_offset:
                    # Found! Print context
                    print(f"\n  LDRB w{rt}, [x{rn}, #13] at 0x{off:05X}")
                    print(f"    ADRP+ADD at 0x{off-back:05X}")
                    # Find function boundary and callers
                    func_start = None
                    for fb in range(0, 512, 4):
                        if off - back - fb < CODE_START:
                            break
                        wf = u32(off - back - fb)
                        if (wf & 0xFFE00000) in (0xA9800000, 0xF8000000):
                            func_start = off - back - fb
                            break
                    if func_start:
                        print(f"    Enclosing function: 0x{func_start:05X}")
                        callers = find_bl_callers(func_start)
                        print(f"    Callers: {', '.join(f'0x{c:05X}' for c in callers)}")
                        # Disasm the function
                        print(f"    --- Disasm ---")
                        for di in range(func_start, min(func_start + 200, CODE_END), 4):
                            print(f"    {annotate(di, u32(di))}")
                            if u32(di) == 0xD65F03C0:  # RET
                                break
                break

# ============================================================
# Step 5: Search for function pointers in data sections
# ============================================================
print("\n" + "=" * 70)
print("=== Step 5: Function pointer search in .data section ===")
print("=" * 70)
DATA_START = 0x6A000
DATA_END = min(0x1C8000, len(pe))

# First, collect all function starts we care about (devinfo STRB functions)
func_targets = set()
for off, rn, rt in strb13_sites:
    # Find function start
    for back in range(0, 512, 4):
        if off - back < CODE_START:
            break
        w = u32(off - back)
        if (w & 0xFFE00000) in (0xA9800000, 0xF8000000):
            func_targets.add(off - back)
            break

print(f"Searching for function pointers to: {', '.join(f'0x{t:05X}' for t in sorted(func_targets))}")
for target in sorted(func_targets):
    # Search as 64-bit pointer
    needle = struct.pack("<Q", target)
    pos = DATA_START
    while pos < DATA_END:
        idx = pe.find(needle, pos, DATA_END)
        if idx < 0:
            break
        print(f"  0x{target:05X} found as 64-bit ptr at PE offset 0x{idx:X}")
        pos = idx + 1

# ============================================================
# Step 6: ALL callers of init_defaults (once we know its real address)
# ============================================================
print("\n" + "=" * 70)
print("=== Step 6: ALL callers of confirmed devinfo functions ===")
print("=" * 70)
for target in sorted(func_targets):
    callers = find_bl_callers(target)
    name = f"func_0x{target:05X}"
    print(f"\n  {name}: {len(callers)} callers")
    for c in callers:
        print(f"    BL at 0x{c:05X}")

# ============================================================
# Step 7: ReadDeviceInfo — find by string "ANDROID-BOOT!" reference
# ============================================================
print("\n" + "=" * 70)
print("=== Step 7: Find 'ANDROID-BOOT!' string and ReadDeviceInfo ===")
print("=" * 70)
magic = b"ANDROID-BOOT!"
idx = pe.find(magic)
while idx >= 0:
    print(f"  'ANDROID-BOOT!' found at PE offset 0x{idx:X}")
    # Search for ADRP+ADD referencing this address
    target_page = idx & ~0xFFF
    target_off = idx & 0xFFF
    print(f"    Page 0x{target_page:X}, offset 0x{target_off:X}")
    # Find ADRP references
    for off in range(CODE_START, CODE_END, 4):
        w = u32(off)
        adrp = decode_adrp(w, off)
        if adrp == target_page:
            w2 = u32(off + 4)
            add_res = decode_add_imm(w2)
            if add_res and add_res[2] == target_off:
                print(f"    Referenced by ADRP+ADD at 0x{off:05X}")
                # Disasm context
                for di in range(max(off - 40, CODE_START), min(off + 60, CODE_END), 4):
                    print(f"      {annotate(di, u32(di))}")
    idx = pe.find(magic, idx + 1)

# ============================================================
# Step 8: Wider stores overlapping devinfo[13]
# ============================================================
print("\n" + "=" * 70)
print("=== Step 8: Wider stores (STR/STP/STUR) overlapping devinfo byte 13 ===")
print("=" * 70)
if devinfo_page is not None:
    # Find all ADRP+ADD pointing to devinfo buffer
    for off in range(CODE_START, CODE_END, 4):
        w = u32(off)
        adrp = decode_adrp(w, off)
        if adrp != devinfo_page:
            continue
        rd = w & 0x1F
        w2 = u32(off + 4)
        add_res = decode_add_imm(w2)
        if not add_res or add_res[1] != rd or add_res[2] != devinfo_offset:
            continue
        dest_reg = add_res[0]
        # Scan forward for stores using dest_reg as base that overlap byte 13
        for off2 in range(off + 8, min(off + 512, CODE_END), 4):
            w3 = u32(off2)
            # STR Wt, [Xn, #imm] (4 bytes) - need offset 10,11,12,13 to overlap byte 13
            if (w3 & 0xFFC00000) == 0xB9000000:
                imm = ((w3 >> 10) & 0xFFF) * 4
                rn = (w3 >> 5) & 0x1F
                if rn == dest_reg and imm <= 13 and imm + 4 > 13:
                    rt = w3 & 0x1F
                    print(f"  STR w{rt}, [x{rn}, #{imm}] at 0x{off2:05X} (writes bytes {imm}-{imm+3})")
            # STR Xt, [Xn, #imm] (8 bytes)
            if (w3 & 0xFFC00000) == 0xF9000000:
                imm = ((w3 >> 10) & 0xFFF) * 8
                rn = (w3 >> 5) & 0x1F
                if rn == dest_reg and imm <= 13 and imm + 8 > 13:
                    rt = w3 & 0x1F
                    print(f"  STR x{rt}, [x{rn}, #{imm}] at 0x{off2:05X} (writes bytes {imm}-{imm+7})")
            # STP Wt, Wt2, [Xn, #imm] (8 bytes)
            if (w3 & 0xFFC00000) == 0x29000000:
                imm7 = (w3 >> 15) & 0x7F
                if imm7 & 0x40: imm7 -= 0x80
                imm = imm7 * 4
                rn = (w3 >> 5) & 0x1F
                if rn == dest_reg and imm <= 13 and imm + 8 > 13:
                    rt = w3 & 0x1F; rt2 = (w3 >> 10) & 0x1F
                    print(f"  STP w{rt},w{rt2}, [x{rn}, #{imm}] at 0x{off2:05X} (writes bytes {imm}-{imm+7})")
            # STP Xt, Xt2, [Xn, #imm] (16 bytes)
            if (w3 & 0xFFC00000) == 0xA9000000:
                imm7 = (w3 >> 15) & 0x7F
                if imm7 & 0x40: imm7 -= 0x80
                imm = imm7 * 8
                rn = (w3 >> 5) & 0x1F
                if rn == dest_reg and imm <= 13 and imm + 16 > 13:
                    rt = w3 & 0x1F; rt2 = (w3 >> 10) & 0x1F
                    print(f"  STP x{rt},x{rt2}, [x{rn}, #{imm}] at 0x{off2:05X} (writes bytes {imm}-{imm+15})")
            # STUR Wt, [Xn, #imm9] (4 bytes, unscaled)
            if (w3 & 0xFFE00C00) == 0xB8000000:
                imm9 = (w3 >> 12) & 0x1FF
                if imm9 & 0x100: imm9 -= 0x200
                rn = (w3 >> 5) & 0x1F
                if rn == dest_reg and imm9 <= 13 and imm9 + 4 > 13:
                    rt = w3 & 0x1F
                    print(f"  STUR w{rt}, [x{rn}, #{imm9}] at 0x{off2:05X} (writes bytes {imm9}-{imm9+3})")
            # STUR Xt, [Xn, #imm9] (8 bytes, unscaled)
            if (w3 & 0xFFE00C00) == 0xF8000000:
                imm9 = (w3 >> 12) & 0x1FF
                if imm9 & 0x100: imm9 -= 0x200
                rn = (w3 >> 5) & 0x1F
                if rn == dest_reg and imm9 <= 13 and imm9 + 8 > 13:
                    rt = w3 & 0x1F
                    print(f"  STUR x{rt}, [x{rn}, #{imm9}] at 0x{off2:05X} (writes bytes {imm9}-{imm9+7})")
            # Check for RET to stop
            if w3 == 0xD65F03C0:
                break

print("\nDone.")
