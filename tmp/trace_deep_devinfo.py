#!/usr/bin/env python3
"""
Deep trace:
1. Full IsDeviceUnlocked (0x22C18) disassembly
2. Search for wider stores (STR/STP) that could overwrite devinfo[13]
3. Search for init_defaults (0x384D0) and SetDeviceUnlocked (0x22DB8) function pointers in data
4. Full 0x46920 disassembly (called from fastboot init 0x46AA0)
5. 0x46BD8 error path (branch from 0x46AA0)
6. ALL callers of ReadWritePartition (0x18248)
7. Search for SetMem/CopyMem calls on devinfo buffer
"""

import struct, sys

PE = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
TEXT = "/tmp/linuxloader_text.bin"
DISASM = "/tmp/linuxloader_disasm.txt"
TEXT_SIZE = 0x89000
CODE_END = 0x6A000
DEVINFO_PAGE = 0x1BD  # ADRP page number for 0x1BD000
DEVINFO_OFF = 0x978   # ADD offset for devinfo buffer

pe = open(PE, "rb").read()
text = open(TEXT, "rb").read()

def u32(off): return struct.unpack_from("<I", text, off)[0] if off+4 <= len(text) else 0
def u64_pe(off): return struct.unpack_from("<Q", pe, off)[0] if off+8 <= len(pe) else 0

def disasm_range(start, end):
    lines = []
    for off in range(start, min(end, CODE_END), 4):
        w = u32(off)
        lines.append(f"0x{off:05X}: 0x{w:08X}")
    return lines

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
    if (w & 0x7F800000) == 0x11000000:  # ADD Xd, Xn, #imm12
        shift = (w >> 22) & 1
        imm12 = (w >> 10) & 0xFFF
        if shift: imm12 <<= 12
        rd = w & 0x1F
        rn = (w >> 5) & 0x1F
        return rd, rn, imm12
    return None

# --- Section 1: Full IsDeviceUnlocked 0x22C18 ---
print("=" * 70)
print("=== IsDeviceUnlocked (0x22C18) — FULL DISASSEMBLY ===")
print("=" * 70)
for off in range(0x22C18, 0x22CC0, 4):
    w = u32(off)
    s = f"0x{off:05X}: 0x{w:08X}"
    bl = decode_bl(w, off)
    if bl is not None:
        s += f"  bl 0x{bl:05X}"
        if bl == 0x232D8: s += " ← ReadDeviceInfo"
    if w == 0xD65F03C0:
        s += "  ret"
    # LDRB
    if (w & 0xFFC00000) == 0x39400000:
        imm12 = (w >> 10) & 0xFFF
        rn = (w >> 5) & 0x1F
        rt = w & 0x1F
        s += f"  ldrb w{rt}, [x{rn}, #{imm12}]"
    # LDR Xt
    if (w & 0xFFC00000) == 0xF9400000:
        imm12 = ((w >> 10) & 0xFFF) * 8
        rn = (w >> 5) & 0x1F
        rt = w & 0x1F
        s += f"  ldr x{rt}, [x{rn}, #{imm12}]"
    adrp = decode_adrp(w, off)
    if adrp is not None:
        s += f"  adrp x{w&0x1F}, 0x{adrp:X}"
    add = decode_add_imm(w)
    if add:
        rd, rn, imm = add
        s += f"  add x{rd}, x{rn}, #0x{imm:X}"
    # CBZ/CBNZ
    if (w & 0x7F000000) == 0x34000000:
        imm19 = (w >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 -= 0x80000
        target = off + imm19 * 4
        rt = w & 0x1F
        op = "cbz" if (w >> 24) & 1 == 0 else "cbnz"
        s += f"  {op} w{rt}, 0x{target:05X}"
    # TBNZ/TBZ
    if (w & 0x7E000000) == 0x36000000:
        bit = ((w >> 31) & 1) << 5 | ((w >> 19) & 0x1F)
        imm14 = (w >> 5) & 0x3FFF
        if imm14 & 0x2000: imm14 -= 0x4000
        target = off + imm14 * 4
        rt = w & 0x1F
        op = "tbnz" if (w >> 24) & 1 else "tbz"
        s += f"  {op} w{rt}, #{bit}, 0x{target:05X}"
    # AND
    if (w & 0xFF800000) == 0x12000000:
        rd = w & 0x1F
        rn = (w >> 5) & 0x1F
        s += f"  and w{rd}, w{rn}, #..."
    # MOV Xd, Xn
    if (w & 0xFFE0FFE0) == 0xAA0003E0:
        rd = w & 0x1F
        rm = (w >> 16) & 0x1F
        s += f"  mov x{rd}, x{rm}"
    print(s)

# --- Section 2: Search for WIDER stores (STR/STP) that could overwrite devinfo[13] ---
print("\n" + "=" * 70)
print("=== Search: STR/STP that could overwrite devinfo buffer byte 13 ===")
print("=" * 70)
# Strategy: Find all ADRP+ADD sequences pointing to devinfo buffer,
# then look for ANY subsequent store in the same function window that targets offsets 8-15
print("\nPhase 2a: All ADRP instructions referencing 0x1BD000:")
adrp_sites = []
for off in range(0, CODE_END, 4):
    w = u32(off)
    adrp = decode_adrp(w, off)
    if adrp == 0x1BD000:
        rd = w & 0x1F
        adrp_sites.append((off, rd))
        # Check next instruction for ADD with offset 0x978
        w2 = u32(off + 4)
        add_res = decode_add_imm(w2)
        if add_res:
            rd2, rn2, imm2 = add_res
            if rn2 == rd and imm2 == 0x978:
                print(f"  ADRP+ADD at 0x{off:05X}: x{rd2} = devinfo_buf (0x1BD978)")
                # Now scan forward for STR/STP/STUR targeting this register at offsets that include byte 13
                # Look within a reasonable window (128 instructions)
                for off2 in range(off + 8, min(off + 512, CODE_END), 4):
                    w3 = u32(off2)
                    # STRB Wt, [Xn, #imm] - already searched, but include for completeness at #13
                    if (w3 & 0xFFC00000) == 0x39000000:
                        imm = (w3 >> 10) & 0xFFF
                        rn = (w3 >> 5) & 0x1F
                        rt = w3 & 0x1F
                        if rn == rd2 and imm == 13:
                            print(f"    → STRB w{rt} at 0x{off2:05X}, [x{rn}, #13]")
                    # STR Wt, [Xn, #imm] (unsigned offset, scaled by 4)
                    if (w3 & 0xFFC00000) == 0xB9000000:
                        imm = ((w3 >> 10) & 0xFFF) * 4
                        rn = (w3 >> 5) & 0x1F
                        rt = w3 & 0x1F
                        if rn == rd2 and imm >= 8 and imm <= 15:
                            print(f"    → STR w{rt} at 0x{off2:05X}, [x{rn}, #{imm}] (4B overlaps byte 13!)")
                        if rn == rd2 and imm == 12:
                            print(f"    → STR w{rt} at 0x{off2:05X}, [x{rn}, #12] (4B write at 12-15, overlaps 13!)")
                    # STR Xt, [Xn, #imm] (unsigned offset, scaled by 8)
                    if (w3 & 0xFFC00000) == 0xF9000000:
                        imm = ((w3 >> 10) & 0xFFF) * 8
                        rn = (w3 >> 5) & 0x1F
                        rt = w3 & 0x1F
                        if rn == rd2 and imm >= 8 and imm <= 15:
                            print(f"    → STR x{rt} at 0x{off2:05X}, [x{rn}, #{imm}] (8B overlaps byte 13!)")
                        if rn == rd2 and imm == 8:
                            print(f"    → STR x{rt} at 0x{off2:05X}, [x{rn}, #8] (8B write at 8-15, overlaps 13!)")
                    # STP Wt, Wt2, [Xn, #imm] (signed offset, scaled by 4)
                    if (w3 & 0xFFC00000) == 0x29000000:
                        imm7 = (w3 >> 15) & 0x7F
                        if imm7 & 0x40: imm7 -= 0x80
                        imm = imm7 * 4
                        rn = (w3 >> 5) & 0x1F
                        if rn == rd2 and imm >= 6 and imm <= 13:
                            rt = w3 & 0x1F
                            rt2 = (w3 >> 10) & 0x1F
                            print(f"    → STP w{rt},w{rt2} at 0x{off2:05X}, [x{rn}, #{imm}] (8B may overlap byte 13!)")
                    # STP Xt, Xt2, [Xn, #imm] (signed offset, scaled by 8)
                    if (w3 & 0xFFC00000) == 0xA9000000:
                        imm7 = (w3 >> 15) & 0x7F
                        if imm7 & 0x40: imm7 -= 0x80
                        imm = imm7 * 8
                        rn = (w3 >> 5) & 0x1F
                        if rn == rd2 and imm >= 0 and imm <= 13:
                            rt = w3 & 0x1F
                            rt2 = (w3 >> 10) & 0x1F
                            print(f"    → STP x{rt},x{rt2} at 0x{off2:05X}, [x{rn}, #{imm}] (16B may overlap byte 13!)")
                    # STUR Wt, [Xn, #imm9] - unscaled
                    if (w3 & 0xFFE00C00) == 0xB8000000:
                        imm9 = (w3 >> 12) & 0x1FF
                        if imm9 & 0x100: imm9 -= 0x200
                        rn = (w3 >> 5) & 0x1F
                        rt = w3 & 0x1F
                        if rn == rd2 and imm9 >= 10 and imm9 <= 13:
                            print(f"    → STUR w{rt} at 0x{off2:05X}, [x{rn}, #{imm9}] (4B may overlap byte 13!)")
                    # STUR Xt, [Xn, #imm9] - unscaled
                    if (w3 & 0xFFE00C00) == 0xF8000000:
                        imm9 = (w3 >> 12) & 0x1FF
                        if imm9 & 0x100: imm9 -= 0x200
                        rn = (w3 >> 5) & 0x1F
                        rt = w3 & 0x1F
                        if rn == rd2 and imm9 >= 6 and imm9 <= 13:
                            print(f"    → STUR x{rt} at 0x{off2:05X}, [x{rn}, #{imm9}] (8B may overlap byte 13!)")
                    # STURB Wt, [Xn, #imm9] - unscaled byte store
                    if (w3 & 0xFFE00C00) == 0x38000000:
                        imm9 = (w3 >> 12) & 0x1FF
                        if imm9 & 0x100: imm9 -= 0x200
                        rn = (w3 >> 5) & 0x1F
                        rt = w3 & 0x1F
                        if rn == rd2 and imm9 == 13:
                            print(f"    → STURB w{rt} at 0x{off2:05X}, [x{rn}, #{imm9}] (byte write to offset 13!)")
                    # Check for BL to SetMem/CopyMem/memset/memcpy targets
                    bl_target = decode_bl(w3, off2)
                    if bl_target is not None and bl_target == 0x4FE50:
                        print(f"    → BL 0x4FE50 (SetMem?) at 0x{off2:05X}")
                    if bl_target is not None and bl_target == 0x4FD10:
                        print(f"    → BL 0x4FD10 (CompareMem) at 0x{off2:05X}")
                    # RET or another function (BL with save) resets scope
                    if w3 == 0xD65F03C0:
                        break

# --- Section 3: Search for function pointer references ---
print("\n" + "=" * 70)
print("=== Search: Function pointers to init_defaults/SetDeviceUnlocked ===")
print("=" * 70)
targets = {
    0x384D0: "init_defaults",
    0x22DB8: "SetDeviceUnlocked",
    0x22C18: "IsDeviceUnlocked",
    0x232D8: "ReadDeviceInfo",
    0x22CA8: "WriteDeviceInfo",
}
# Search the entire PE binary (including data sections) for 64-bit addresses
for target_addr, name in targets.items():
    print(f"\nSearching for 0x{target_addr:X} ({name}) as 64-bit LE pointer:")
    needle = struct.pack("<Q", target_addr)
    pos = 0
    found = False
    while True:
        idx = pe.find(needle, pos)
        if idx < 0:
            break
        found = True
        print(f"  Found at PE offset 0x{idx:X}")
        pos = idx + 1
    if not found:
        print(f"  (not found)")
    # Also search as 32-bit address (some tables might use 32-bit)
    needle32 = struct.pack("<I", target_addr)
    pos = 0
    found32 = False
    while True:
        idx = pe.find(needle32, pos)
        if idx < 0:
            break
        # Skip if it's a BL instruction encoding (in code section)
        if idx < CODE_END and idx % 4 == 0:
            w = struct.unpack_from("<I", pe, idx)[0]
            if (w >> 26) in (0x25, 0x05):  # BL or B
                pos = idx + 1
                continue
        if not found32:
            print(f"  As 32-bit pointer:")
            found32 = True
        # Show context
        if idx < CODE_END:
            print(f"    Found at PE offset 0x{idx:X} (CODE section)")
        else:
            print(f"    Found at PE offset 0x{idx:X} (DATA section)")
        pos = idx + 1

# --- Section 4: Full 0x46920 disassembly ---
print("\n" + "=" * 70)
print("=== 0x46920 — main fastboot setup (called from 0x46AA0) ===")
print("=" * 70)
# Disassemble a large window
for off in range(0x46920, min(0x46AA0, CODE_END), 4):
    w = u32(off)
    s = f"0x{off:05X}: 0x{w:08X}"
    bl = decode_bl(w, off)
    if bl is not None:
        s += f"  bl 0x{bl:05X}"
        known = {0x232D8: "ReadDeviceInfo", 0x22C18: "IsDeviceUnlocked",
                 0x22DB8: "SetDeviceUnlocked", 0x384D0: "init_defaults",
                 0x189E0: "IsSecureBootEnabled", 0x22CA8: "WriteDeviceInfo",
                 0x4C850: "FastbootPublish", 0x4FE50: "SetMem?", 0x18248: "ReadWritePartition",
                 0x4FD10: "CompareMem", 0x4DD78: "PrintStr?", 0x4DDCC: "FormatPrint?",
                 0x28574: "DebugCheck", 0x384B0: "SetIsUnlocked" }
        if bl in known:
            s += f" ← {known[bl]}"
    if w == 0xD65F03C0:
        s += "  ret"
    adrp = decode_adrp(w, off)
    if adrp is not None:
        s += f"  adrp x{w&0x1F}, 0x{adrp:X}"
    add = decode_add_imm(w)
    if add:
        rd, rn, imm = add
        s += f"  add x{rd}, x{rn}, #0x{imm:X}"
    # BLR
    if (w & 0xFFFFFC00) == 0xD63F0000:
        rn = (w >> 5) & 0x1F
        s += f"  blr x{rn}"
    # B conditional
    if (w & 0xFF000010) == 0x54000000:
        imm19 = (w >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 -= 0x80000
        target = off + imm19 * 4
        cond = w & 0xF
        cond_names = {0:"EQ",1:"NE",2:"CS",3:"CC",4:"MI",5:"PL",6:"VS",7:"VC",
                      8:"HI",9:"LS",10:"GE",11:"LT",12:"GT",13:"LE",14:"AL"}
        s += f"  b.{cond_names.get(cond,'?')} 0x{target:05X}"
    # B unconditional
    if (w & 0xFC000000) == 0x14000000:
        imm26 = w & 0x3FFFFFF
        if imm26 & 0x2000000: imm26 -= 0x4000000
        target = off + imm26 * 4
        s += f"  b 0x{target:05X}"
    # CBZ/CBNZ
    if (w & 0x7F000000) in (0x34000000, 0x35000000):
        imm19 = (w >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 -= 0x80000
        target = off + imm19 * 4
        rt = w & 0x1F
        op = "cbz" if (w & 0x7F000000) == 0x34000000 else "cbnz"
        is64 = (w >> 31) & 1
        s += f"  {op} {'x' if is64 else 'w'}{rt}, 0x{target:05X}"
    print(s)

# --- Section 5: 0x46BD8 error path (branch from 0x46AA0) ---
print("\n" + "=" * 70)
print("=== 0x46BD8 — error/alternate path from 0x46AA0 ===")
print("=" * 70)
for off in range(0x46BD8, min(0x46D00, CODE_END), 4):
    w = u32(off)
    s = f"0x{off:05X}: 0x{w:08X}"
    bl = decode_bl(w, off)
    if bl is not None:
        s += f"  bl 0x{bl:05X}"
        known = {0x232D8: "ReadDeviceInfo", 0x22C18: "IsDeviceUnlocked",
                 0x22DB8: "SetDeviceUnlocked", 0x384D0: "init_defaults",
                 0x189E0: "IsSecureBootEnabled", 0x22CA8: "WriteDeviceInfo",
                 0x4C850: "FastbootPublish", 0x4FE50: "SetMem?", 0x18248: "ReadWritePartition",
                 0x384B0: "SetIsUnlocked"}
        if bl in known:
            s += f" ← {known[bl]}"
    if w == 0xD65F03C0:
        s += "  ret"
    adrp = decode_adrp(w, off)
    if adrp is not None:
        s += f"  adrp x{w&0x1F}, 0x{adrp:X}"
    print(s)

# --- Section 6: ALL callers of ReadWritePartition (0x18248) ---
print("\n" + "=" * 70)
print("=== ALL callers of ReadWritePartition (0x18248) ===")
print("=" * 70)
for off in range(0, CODE_END, 4):
    w = u32(off)
    bl = decode_bl(w, off)
    if bl == 0x18248:
        # Check previous instructions for context
        prev1 = u32(off - 4)
        prev2 = u32(off - 8)
        # Check what mode (w0) is set to
        mode_str = ""
        for back in range(4, 20, 4):
            pw = u32(off - back)
            # MOV W0, #0 = 0x2A1F03E0
            if pw == 0x2A1F03E0:
                mode_str = " mode=0(READ)"
                break
            # MOV W0, #1 = 0x52800020
            if pw == 0x52800020:
                mode_str = " mode=1(WRITE)"
                break
        print(f"  BL 0x18248 at 0x{off:05X}{mode_str}")

# --- Section 7: ALL callers of IsDeviceUnlocked (0x22C18) ---
print("\n" + "=" * 70)
print("=== ALL callers of IsDeviceUnlocked (0x22C18) ===")
print("=" * 70)
for off in range(0, CODE_END, 4):
    w = u32(off)
    bl = decode_bl(w, off)
    if bl == 0x22C18:
        print(f"  BL 0x22C18 at 0x{off:05X}")

# --- Section 8: Full init_defaults (0x384D0) from start to end ---
print("\n" + "=" * 70)
print("=== Full init_defaults (0x384D0) disassembly ===")
print("=" * 70)
for off in range(0x384D0, 0x38590, 4):
    w = u32(off)
    s = f"0x{off:05X}: 0x{w:08X}"
    bl = decode_bl(w, off)
    if bl is not None:
        s += f"  bl 0x{bl:05X}"
        if bl == 0x189E0: s += " ← IsSecureBootEnabled"
        if bl == 0x4FE50: s += " ← SetMem?"
        if bl == 0x4FD10: s += " ← CompareMem"
    if w == 0xD65F03C0: s += "  ret"
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
    adrp = decode_adrp(w, off)
    if adrp is not None:
        s += f"  adrp x{w&0x1F}, 0x{adrp:X}"
    add = decode_add_imm(w)
    if add:
        rd, rn, imm = add
        s += f"  add x{rd}, x{rn}, #0x{imm:X}"
    # MOV immediate
    if (w & 0xFF800000) == 0x52800000:
        rd = w & 0x1F
        imm16 = (w >> 5) & 0xFFFF
        s += f"  mov w{rd}, #{imm16}"
    # CSINC
    if (w & 0xFFE00C00) == 0x1A800400:
        rd = w & 0x1F
        rn = (w >> 5) & 0x1F
        rm = (w >> 16) & 0x1F
        cond = (w >> 12) & 0xF
        s += f"  csinc w{rd}, w{rn}, w{rm}, cond={cond}"
    # CBZ
    if (w & 0x7F000000) == 0x34000000:
        imm19 = (w >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 -= 0x80000
        target = off + imm19 * 4
        rt = w & 0x1F
        s += f"  cbz w{rt}, 0x{target:05X}"
    # STR Wt, [Xn, #imm]
    if (w & 0xFFC00000) == 0xB9000000:
        imm = ((w >> 10) & 0xFFF) * 4
        rn = (w >> 5) & 0x1F
        rt = w & 0x1F
        s += f"  str w{rt}, [x{rn}, #{imm}]"
    if (w & 0xFF000010) == 0x54000000:
        imm19 = (w >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 -= 0x80000
        target = off + imm19 * 4
        cond = w & 0xF
        cond_names = {0:"EQ",1:"NE",2:"CS",3:"CC",4:"MI",5:"PL",6:"VS",7:"VC",
                      8:"HI",9:"LS",10:"GE",11:"LT",12:"GT",13:"LE",14:"AL"}
        s += f"  b.{cond_names.get(cond,'?')} 0x{target:05X}"
    print(s)

# --- Section 9: Check function at 0x48400-0x48500 (near unlocked variable pub) ---
print("\n" + "=" * 70)
print("=== 0x48400 region — unlocked variable publication ===")
print("=" * 70)
for off in range(0x48400, 0x48540, 4):
    w = u32(off)
    s = f"0x{off:05X}: 0x{w:08X}"
    bl = decode_bl(w, off)
    if bl is not None:
        s += f"  bl 0x{bl:05X}"
        known = {0x22C18: "IsDeviceUnlocked", 0x4C850: "FastbootPublish",
                 0x22D18: "IsUnlockCritical", 0x4DD78: "PrintStr?", 0x4DDCC: "FormatPrint?",
                 0x4D9DC: "DebugPrint?", 0x384D0: "init_defaults", 0x22DB8: "SetDeviceUnlocked",
                 0x22CA8: "WriteDeviceInfo", 0x384B0: "SetIsUnlocked"}
        if bl in known:
            s += f" ← {known[bl]}"
    if w == 0xD65F03C0: s += "  ret"
    adrp = decode_adrp(w, off)
    if adrp is not None:
        s += f"  adrp x{w&0x1F}, 0x{adrp:X}"
    add = decode_add_imm(w)
    if add:
        rd, rn, imm = add
        s += f"  add x{rd}, x{rn}, #0x{imm:X}"
    if (w & 0xFF000010) == 0x54000000:
        imm19 = (w >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 -= 0x80000
        target = off + imm19 * 4
        cond = w & 0xF
        cond_names = {0:"EQ",1:"NE",2:"CS",3:"CC",4:"MI",5:"PL",6:"VS",7:"VC",
                      8:"HI",9:"LS",10:"GE",11:"LT",12:"GT",13:"LE",14:"AL"}
        s += f"  b.{cond_names.get(cond,'?')} 0x{target:05X}"
    # B unconditional
    if (w & 0xFC000000) == 0x14000000:
        imm26 = w & 0x3FFFFFF
        if imm26 & 0x2000000: imm26 -= 0x4000000
        target = off + imm26 * 4
        s += f"  b 0x{target:05X}"
    print(s)

# --- Section 10: Look for CopyMem/SetMem with devinfo as target ---
# Search for BL to SetMem (0x4FE50) or similar within devinfo-accessing functions
print("\n" + "=" * 70)
print("=== Search: SetMem/CopyMem calls near devinfo references ===")
print("=" * 70)
# 0x4FE50 is SetMem?, 0x4FD10 is CompareMem
# We need to find all callers of potential memory functions
mem_funcs = [0x4FE50, 0x4FD10, 0x4FE60, 0x4FE70, 0x4FE80, 0x4FE40, 0x4FE30,
             0x4FD00, 0x4FD20, 0x4FD30, 0x4FC00]
for mf in mem_funcs:
    callers = []
    for off in range(0, CODE_END, 4):
        w = u32(off)
        bl = decode_bl(w, off)
        if bl == mf:
            callers.append(off)
    if callers:
        print(f"  BL 0x{mf:05X} called from: {', '.join(f'0x{c:05X}' for c in callers)}")

print("\n" + "=" * 70)
print("=== Search: ALL callers of init_defaults (0x384D0) ===")
print("=" * 70)
for off in range(0, CODE_END, 4):
    w = u32(off)
    bl = decode_bl(w, off)
    if bl == 0x384D0:
        print(f"  BL 0x384D0 at 0x{off:05X}")

print("\nDone.")
