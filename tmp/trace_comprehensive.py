#!/usr/bin/env python3
"""Comprehensive analysis: find the device-info handler, check critical functions,
and find ALL memset/memcpy targeting devinfo buffer."""

import struct

PE = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
pe = open(PE, "rb").read()

CODE_START = 0x1000
CODE_END = 0x6A000
DATA_START = 0x6A000
DATA_END = 0x1C8000

def u32(off):
    return struct.unpack_from("<I", pe, off)[0]

def disasm_basic(addr):
    """Basic single-instruction disassembly for common patterns."""
    if addr < 0 or addr + 4 > len(pe):
        return "OUT_OF_RANGE"
    w = u32(addr)
    # BL
    if (w >> 26) == 0x25:
        imm = w & 0x3FFFFFF
        if imm & 0x2000000:
            imm |= ~0x3FFFFFF
        target = addr + imm * 4
        return f"BL 0x{target & 0xFFFFFFFF:05X}"
    # B
    if (w >> 26) == 0x05:
        imm = w & 0x3FFFFFF
        if imm & 0x2000000:
            imm |= ~0x3FFFFFF
        target = addr + imm * 4
        return f"B 0x{target & 0xFFFFFFFF:05X}"
    # ADRP
    if (w & 0x9F000000) == 0x90000000:
        rd = w & 0x1F
        immlo = (w >> 29) & 0x3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm |= ~0x1FFFFF
        page = (addr & ~0xFFF) + (imm << 12)
        return f"ADRP x{rd}, 0x{page & 0xFFFFFFFF:X}"
    # ADD imm
    if (w & 0xFF800000) == 0x91000000:
        rd = w & 0x1F
        rn = (w >> 5) & 0x1F
        imm12 = (w >> 10) & 0xFFF
        sh = (w >> 22) & 1
        if sh:
            imm12 <<= 12
        return f"ADD x{rd}, x{rn}, #0x{imm12:X}"
    # STRB
    if (w & 0xFFC00000) == 0x39000000:
        rt = w & 0x1F
        rn = (w >> 5) & 0x1F
        imm12 = (w >> 10) & 0xFFF
        return f"STRB w{rt}, [x{rn}, #{imm12}]"
    # LDRB
    if (w & 0xFFC00000) == 0x39400000:
        rt = w & 0x1F
        rn = (w >> 5) & 0x1F
        imm12 = (w >> 10) & 0xFFF
        return f"LDRB w{rt}, [x{rn}, #{imm12}]"
    # STR (64-bit)
    if (w & 0xFFC00000) == 0xF9000000:
        rt = w & 0x1F
        rn = (w >> 5) & 0x1F
        imm12 = ((w >> 10) & 0xFFF) * 8
        return f"STR x{rt}, [x{rn}, #{imm12}]"
    # LDR (64-bit)
    if (w & 0xFFC00000) == 0xF9400000:
        rt = w & 0x1F
        rn = (w >> 5) & 0x1F
        imm12 = ((w >> 10) & 0xFFF) * 8
        return f"LDR x{rt}, [x{rn}, #{imm12}]"
    # STP
    if (w & 0xFFC00000) == 0xA9000000 or (w & 0xFE000000) == 0xA9000000:
        return f"STP ..."
    # MOV (wide)
    if (w & 0xFF800000) == 0xD2800000:
        rd = w & 0x1F
        imm16 = (w >> 5) & 0xFFFF
        return f"MOV x{rd}, #0x{imm16:X}"
    if (w & 0xFF800000) == 0x52800000:
        rd = w & 0x1F
        imm16 = (w >> 5) & 0xFFFF
        return f"MOV w{rd}, #0x{imm16:X}"
    # RET
    if w == 0xD65F03C0:
        return "RET"
    # CBZ
    if (w & 0xFF000000) == 0xB4000000:
        rt = w & 0x1F
        imm19 = (w >> 5) & 0x7FFFF
        if imm19 & 0x40000:
            imm19 |= ~0x7FFFF
        target = addr + imm19 * 4
        return f"CBZ x{rt}, 0x{target & 0xFFFFFFFF:05X}"
    if (w & 0xFF000000) == 0x34000000:
        rt = w & 0x1F
        imm19 = (w >> 5) & 0x7FFFF
        if imm19 & 0x40000:
            imm19 |= ~0x7FFFF
        target = addr + imm19 * 4
        return f"CBZ w{rt}, 0x{target & 0xFFFFFFFF:05X}"
    # CBNZ
    if (w & 0xFF000000) == 0xB5000000:
        rt = w & 0x1F
        imm19 = (w >> 5) & 0x7FFFF
        if imm19 & 0x40000:
            imm19 |= ~0x7FFFF
        target = addr + imm19 * 4
        return f"CBNZ x{rt}, 0x{target & 0xFFFFFFFF:05X}"
    # TBNZ/TBZ
    if (w & 0x7F000000) == 0x37000000:
        rt = w & 0x1F
        bit = ((w >> 31) << 5) | ((w >> 19) & 0x1F)
        imm14 = (w >> 5) & 0x3FFF
        if imm14 & 0x2000:
            imm14 |= ~0x3FFF
        target = addr + imm14 * 4
        op = "TBNZ" if (w >> 24) & 1 else "TBZ"
        return f"{op} w{rt}, #{bit}, 0x{target & 0xFFFFFFFF:05X}"
    # CMP
    if (w & 0xFF800000) == 0x71000000:
        rn = (w >> 5) & 0x1F
        imm12 = (w >> 10) & 0xFFF
        return f"CMP w{rn}, #{imm12}"
    # B.cond
    if (w & 0xFF000010) == 0x54000000:
        cond = w & 0xF
        imm19 = (w >> 5) & 0x7FFFF
        if imm19 & 0x40000:
            imm19 |= ~0x7FFFF
        target = addr + imm19 * 4
        conds = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
        return f"B.{conds[cond]} 0x{target & 0xFFFFFFFF:05X}"
    # NOP
    if w == 0xD503201F:
        return "NOP"
    return f"??? 0x{w:08X}"

def disasm_range(start, end):
    """Disassemble a range of addresses."""
    lines = []
    for addr in range(start, end, 4):
        d = disasm_basic(addr)
        lines.append(f"  0x{addr:05X}: {d}")
    return "\n".join(lines)

# ============================================================
# 1. Search for "Device unlocked" and related strings
# ============================================================
print("=" * 70)
print("=== 1. Search for device-info related strings ===")
print("=" * 70)

search_strs = [b"unlocked", b"Unlocked", b"UNLOCKED", b"device-info", b"Device",
               b"tampered", b"charger"]
for s in search_strs:
    idx = 0
    found = []
    while True:
        idx = pe.find(s, idx)
        if idx < 0:
            break
        # Get context
        start = max(0, idx - 10)
        end = min(len(pe), idx + len(s) + 40)
        ctx = pe[start:end]
        # Only show if it looks like a string (printable ASCII around it)
        if all(32 <= b < 127 or b == 0 for b in ctx):
            found.append((idx, ctx))
        idx += 1
    if found:
        print(f"\n'{s.decode()}' found at {len(found)} locations:")
        for addr, ctx in found[:10]:
            # Clean display
            display = ctx.split(b'\x00')[0]
            if len(display) < 3:
                # Try from the search string start
                display = pe[addr:min(len(pe), addr+60)].split(b'\x00')[0]
            print(f"  0x{addr:06X}: {display.decode('ascii', errors='replace')}")

# ============================================================
# 2. Find code references to device-info strings
# ============================================================
print("\n" + "=" * 70)
print("=== 2. Find ADRP+ADD referencing 'unlocked' strings ===")
print("=" * 70)

# Find all "unlocked" strings and their addresses
unlock_strings = []
idx = 0
while True:
    idx = pe.find(b"unlocked", idx)
    if idx < 0:
        break
    # Find the start of the string (backtrack to find beginning)
    start = idx
    while start > 0 and pe[start-1] >= 32 and pe[start-1] < 127:
        start -= 1
    end = idx + 8
    while end < len(pe) and pe[end] >= 32 and pe[end] < 127:
        end += 1
    full_str = pe[start:end].decode('ascii', errors='replace')
    unlock_strings.append((start, full_str))
    idx += 1

print(f"Found {len(unlock_strings)} strings containing 'unlocked':")
for addr, s in unlock_strings:
    print(f"  0x{addr:06X}: '{s}'")

# For each string address, search for ADRP+ADD pattern that references it
for str_addr, str_text in unlock_strings:
    page = str_addr & ~0xFFF
    offset = str_addr & 0xFFF
    # Search all ADRP instructions in code section
    for addr in range(CODE_START, CODE_END, 4):
        w = u32(addr)
        if (w & 0x9F000000) != 0x90000000:
            continue
        rd = w & 0x1F
        immlo = (w >> 29) & 0x3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm |= ~0x1FFFFF
        adrp_page = (addr & ~0xFFF) + (imm << 12)
        if (adrp_page & 0xFFFFFFFF) != page:
            continue
        # Check next instruction for ADD with matching offset
        if addr + 4 >= CODE_END:
            continue
        w2 = u32(addr + 4)
        if (w2 & 0xFF800000) == 0x91000000:
            rd2 = w2 & 0x1F
            rn2 = (w2 >> 5) & 0x1F
            imm12 = (w2 >> 10) & 0xFFF
            sh = (w2 >> 22) & 1
            if sh:
                imm12 <<= 12
            if rn2 == rd and imm12 == offset:
                print(f"\n  ADRP+ADD at 0x{addr:05X} → 0x{str_addr:06X} = '{str_text}'")
                # Disassemble surrounding code (15 before, 20 after)
                print(disasm_range(max(CODE_START, addr - 15*4), min(CODE_END, addr + 20*4)))

# ============================================================
# 3. Check initial value of "already read" flag at 0x1BE388
# ============================================================
print("\n" + "=" * 70)
print("=== 3. Initial value of 'already read' flag at 0x1BE388 ===")
print("=" * 70)
flag_val = pe[0x1BE388] if 0x1BE388 < len(pe) else None
print(f"PE[0x1BE388] = 0x{flag_val:02X}" if flag_val is not None else "OUT OF RANGE")
# Also check surrounding bytes
if 0x1BE380 < len(pe):
    print(f"Context (0x1BE380-0x1BE3A0):")
    for off in range(0x1BE380, min(len(pe), 0x1BE3A0), 16):
        chunk = pe[off:off+16]
        hexstr = ' '.join(f'{b:02X}' for b in chunk)
        print(f"  0x{off:06X}: {hexstr}")

# Check devinfo buffer area initial values
print(f"\nDevinfo buffer area (0x1BD978-0x1BD998):")
for off in range(0x1BD978, min(len(pe), 0x1BD998), 16):
    chunk = pe[off:off+16]
    hexstr = ' '.join(f'{b:02X}' for b in chunk)
    print(f"  0x{off:06X}: {hexstr}")

# ============================================================
# 4. Disassemble 0x38800 (real IsSecureBootEnabled)
# ============================================================
print("\n" + "=" * 70)
print("=== 4. Function at 0x38800 (IsSecureBootEnabled target) ===")
print("=" * 70)
print(disasm_range(0x38800, min(CODE_END, 0x388C0)))

# ============================================================
# 5. Check functions 0x1F8F0 and 0x1EA00 for devinfo access
# ============================================================
print("\n" + "=" * 70)
print("=== 5a. Function at 0x1F8F0 (called after ReadDeviceInfo) ===")
print("=" * 70)
# Disassemble first 64 instructions
print(disasm_range(0x1F8F0, min(CODE_END, 0x1FA00)))

print("\n" + "=" * 70)
print("=== 5b. Function at 0x1EA00 (called after ReadDeviceInfo) ===")
print("=" * 70)
print(disasm_range(0x1EA00, min(CODE_END, 0x1EB10)))

# Check if these functions contain ADRP to 0x1BD000 (devinfo page)
print("\n  Searching 0x1F8F0-0x1FA00 for ADRP 0x1BD000:")
for addr in range(0x1F8F0, min(CODE_END, 0x1FA00), 4):
    w = u32(addr)
    if (w & 0x9F000000) == 0x90000000:
        rd = w & 0x1F
        immlo = (w >> 29) & 0x3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm |= ~0x1FFFFF
        page = (addr & ~0xFFF) + (imm << 12)
        if (page & 0xFFFFFFFF) == 0x1BD000:
            print(f"  FOUND at 0x{addr:05X}: ADRP x{rd}, 0x1BD000")

print("\n  Searching 0x1EA00-0x1EB10 for ADRP 0x1BD000:")
for addr in range(0x1EA00, min(CODE_END, 0x1EB10), 4):
    w = u32(addr)
    if (w & 0x9F000000) == 0x90000000:
        rd = w & 0x1F
        immlo = (w >> 29) & 0x3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm |= ~0x1FFFFF
        page = (addr & ~0xFFF) + (imm << 12)
        if (page & 0xFFFFFFFF) == 0x1BD000:
            print(f"  FOUND at 0x{addr:05X}: ADRP x{rd}, 0x1BD000")

# ============================================================
# 6. ALL ADRP references to 0x1BD000 in entire code section
# ============================================================
print("\n" + "=" * 70)
print("=== 6. ALL ADRP references to devinfo page 0x1BD000 ===")
print("=" * 70)

adrp_refs = []
for addr in range(CODE_START, CODE_END, 4):
    w = u32(addr)
    if (w & 0x9F000000) != 0x90000000:
        continue
    rd = w & 0x1F
    immlo = (w >> 29) & 0x3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & 0x100000:
        imm |= ~0x1FFFFF
    page = (addr & ~0xFFF) + (imm << 12)
    if (page & 0xFFFFFFFF) == 0x1BD000:
        # Check next instruction for ADD with offset 0x978
        w2 = u32(addr + 4) if addr + 4 < CODE_END else 0
        add_info = ""
        if (w2 & 0xFF800000) == 0x91000000:
            imm12 = (w2 >> 10) & 0xFFF
            sh = (w2 >> 22) & 1
            if sh:
                imm12 <<= 12
            add_info = f" → ADD offset=0x{imm12:X}"
            if imm12 == 0x978:
                add_info += " ★ DEVINFO BUFFER"
        adrp_refs.append((addr, rd, add_info))

print(f"Found {len(adrp_refs)} ADRP references to 0x1BD000:")
for addr, rd, add_info in adrp_refs:
    print(f"  0x{addr:05X}: ADRP x{rd}, 0x1BD000{add_info}")

# For each devinfo buffer reference, check for nearby stores (within 20 instructions)
print("\n=== Devinfo buffer references with nearby stores ===")
for addr, rd, add_info in adrp_refs:
    if "DEVINFO BUFFER" not in add_info:
        continue
    # Check +4 to +80 (20 instructions) for any store instruction
    stores = []
    for off in range(addr + 8, min(CODE_END, addr + 80), 4):
        w = u32(off)
        d = disasm_basic(off)
        # Check for any store instruction
        if "STR" in d or "STP" in d:
            stores.append((off, d))
        # Also check for BL to known persist functions
        if "BL" in d:
            stores.append((off, d))
    if stores:
        print(f"\n  Near ADRP at 0x{addr:05X}:")
        for soff, sd in stores:
            print(f"    0x{soff:05X}: {sd}")

# ============================================================
# 7. Search for BL ReadWritePartition (0x18248) with devinfo buf
# ============================================================
print("\n" + "=" * 70)
print("=== 7. ALL BL to ReadWritePartition (0x18248) ===")
print("=" * 70)

rw_callers = []
for addr in range(CODE_START, CODE_END, 4):
    w = u32(addr)
    if (w >> 26) != 0x25:
        continue
    imm = w & 0x3FFFFFF
    if imm & 0x2000000:
        imm |= ~0x3FFFFFF
    target = (addr + imm * 4) & 0xFFFFFFFF
    if target == 0x18248:
        rw_callers.append(addr)

print(f"Found {len(rw_callers)} calls to ReadWritePartition:")
for addr in rw_callers:
    # Show 5 instructions before for context
    ctx = disasm_range(max(CODE_START, addr - 20), addr + 4)
    print(f"\n  BL at 0x{addr:05X}:")
    print(ctx)

# ============================================================
# 8. Disassemble 0x0184C context (caller of 0x189E8)
# ============================================================
print("\n" + "=" * 70)
print("=== 8. Context around 0x0184C (caller of 0x189E8) ===")
print("=" * 70)
print(disasm_range(0x01800, 0x018C0))

# ============================================================
# 9. Check 0x46AA0 (fastboot init) first 32 instructions
# ============================================================
print("\n" + "=" * 70)
print("=== 9. Fastboot init 0x46AA0 (first 40 instructions) ===")
print("=" * 70)
print(disasm_range(0x46AA0, min(CODE_END, 0x46BA0)))

# ============================================================
# 10. Search for STR/STP that could write to devinfo[13]
#     Look for stores to any register that previously loaded devinfo base
# ============================================================
print("\n" + "=" * 70)
print("=== 10. Search for memset/zeromem of devinfo buffer ===")
print("=" * 70)

# Search for SetMem patterns: function calls where x0 = devinfo buffer address
# Look for ADRP+ADD to 0x1BD978 followed by BL (to SetMem, CopyMem, etc.)
for addr, rd, add_info in adrp_refs:
    if "DEVINFO BUFFER" not in add_info:
        continue
    # Get the register that holds devinfo address
    w2 = u32(addr + 4)
    dest_reg = w2 & 0x1F  # destination register of ADD

    # Search for MOV x0, x{dest_reg} followed by BL within 30 instructions
    for off in range(addr + 8, min(CODE_END, addr + 120), 4):
        w = u32(off)
        # Check MOV x0, x{dest_reg}
        if w == (0xAA0003E0 | (dest_reg << 16)):
            # Found MOV x0, x{dest_reg} — look for nearby BL
            for off2 in range(off + 4, min(CODE_END, off + 20), 4):
                w3 = u32(off2)
                d3 = disasm_basic(off2)
                if "BL" in d3:
                    print(f"  0x{addr:05X}: ADRP+ADD→x{dest_reg}=devinfo, 0x{off:05X}: MOV x0, x{dest_reg}, 0x{off2:05X}: {d3}")
                    break
        # Also check if x0 is used directly (ADRP into x0, ADD x0)
        if dest_reg == 0:
            d = disasm_basic(off)
            if "BL" in d:
                if off == addr + 8:  # Very next instruction after ADD x0,...
                    print(f"  0x{addr:05X}: ADRP+ADD→x0=devinfo, 0x{off:05X}: {d}")
                break  # x0 might be clobbered by BL

print("\nDone.")
