#!/usr/bin/env python3
"""
Find AVB verification bypass patch points in T-Mobile ABL.
Corrected for PE32+ section layout where VA = file_offset - 0xb8
"""
import struct

with open('/Users/xmxx/pinganhuijia/tmobile_abl_decompressed.bin','rb') as f:
    d = bytearray(f.read())

# PE section layout:
# .text:  vaddr=0x1000, raw_off=0x10b8 → VA = file_offset - 0xb8
# .data:  vaddr=0x74000, raw_off=0x740b8 → VA = file_offset - 0xb8 (same)
# So globally: VA = file_offset - 0xb8

DELTA = 0xb8  # raw_off - vaddr (constant across sections)

def file_to_va(file_off):
    return file_off - DELTA

def va_to_file(va):
    return va + DELTA

# ===== String file offsets (confirmed by hex dump) =====
STR_UNLOCKED_FILE = 0x592b0   # "Unlocked, AvbSlotVerify returned %a, continue boot"
STR_ERROR_FILE    = 0x592e4   # "ERROR: Device State %a,AvbSlotVerify returned %a"
STR_VERDIS_FILE   = 0x5a7b9   # "VERIFICATION_DISABLED bit is set"

STR_UNLOCKED_VA   = file_to_va(STR_UNLOCKED_FILE)  # 0x591f8
STR_ERROR_VA      = file_to_va(STR_ERROR_FILE)      # 0x5922c
STR_VERDIS_VA     = file_to_va(STR_VERDIS_FILE)     # 0x5a701

print(f"String VAs:")
print(f"  'Unlocked': VA={hex(STR_UNLOCKED_VA)} (file {hex(STR_UNLOCKED_FILE)})")
print(f"  'ERROR':    VA={hex(STR_ERROR_VA)}    (file {hex(STR_ERROR_FILE)})")
print(f"  'VERDIS':   VA={hex(STR_VERDIS_VA)}   (file {hex(STR_VERDIS_FILE)})")
print()

# ===== ADRP+ADD search with correct VAs =====
def find_adrp_add_va(data, target_va, delta=DELTA):
    """Find ADRP+ADD pairs using correct VA calculation"""
    results = []
    target_page = target_va & ~0xFFF
    target_off  = target_va & 0xFFF

    # Only search through .text section: file 0x10b8 to 0x740b8
    search_start = 0x10b8
    search_end   = 0x740b8

    for i in range(search_start, min(search_end, len(data)-8), 4):
        insn = struct.unpack_from('<I', data, i)[0]
        if (insn & 0x9F000000) != 0x90000000:
            continue
        rd    = insn & 0x1f
        immlo = (insn >> 29) & 3
        immhi = (insn >> 5) & 0x7FFFF
        raw_imm = (immhi << 2) | immlo
        if raw_imm & (1 << 20):
            raw_imm -= (1 << 21)
        imm = raw_imm << 12

        # PC as VA (file_offset - delta)
        pc_va = i - delta
        page  = (pc_va & ~0xFFF) + imm

        if page != target_page:
            continue

        # Check NEXT insn: ADD xN, xN, #target_off
        next_insn = struct.unpack_from('<I', data, i+4)[0]
        if (next_insn >> 23) == 0x122:
            rn    = (next_insn >> 5) & 0x1f
            rd2   = next_insn & 0x1f
            shift = (next_insn >> 22) & 1
            imm12 = (next_insn >> 10) & 0xFFF
            if shift:
                imm12 <<= 12
            if rn == rd and imm12 == target_off:
                results.append(i)

        # Also check: ADD xN, xN, #target_off (allow any register pair)
        if (next_insn >> 23) == 0x122:
            imm12 = (next_insn >> 10) & 0xFFF
            shift = (next_insn >> 22) & 1
            if shift: imm12 <<= 12
            if imm12 == target_off:
                results.append(i)  # may add duplicate, will dedup

    return list(dict.fromkeys(results))  # dedup maintaining order


print("=== ADRP+ADD search with corrected VAs ===")
refs_error = find_adrp_add_va(d, STR_ERROR_VA)
refs_unlocked = find_adrp_add_va(d, STR_UNLOCKED_VA)
refs_verdis = find_adrp_add_va(d, STR_VERDIS_VA)

print(f"'ERROR' refs: {len(refs_error)}: {[hex(x) for x in refs_error]}")
print(f"'Unlocked' refs: {len(refs_unlocked)}: {[hex(x) for x in refs_unlocked]}")
print(f"'VERDIS' refs: {len(refs_verdis)}: {[hex(x) for x in refs_verdis]}")
print()

# ===== Show disassembly context around each ref =====
def show_context(data, file_off, n_before=10, n_after=20, delta=DELTA):
    """Show ARM64 instructions around file_off"""
    start = max(0, file_off - n_before*4)
    end   = min(len(data), file_off + n_after*4)
    print(f"  Context around {hex(file_off)} (VA {hex(file_off-delta)}):")
    for i in range(start, end, 4):
        insn = struct.unpack_from('<I', data, i)[0]
        marker = " <---" if i == file_off else ""
        # Decode instruction type for key ones
        desc = ""
        if (insn & 0x9F000000) == 0x90000000:
            desc = f"ADRP x{insn&0x1f}, ..."
        elif (insn >> 26) == 0b000101:
            # B unconditional
            imm26 = insn & 0x3FFFFFF
            if imm26 & (1<<25): imm26 -= (1<<26)
            target = (i - delta) + imm26*4
            desc = f"B {hex(target)} (file {hex(target+delta)})"
        elif (insn >> 24) == 0x54:
            # B.cond
            cond = insn & 0xF
            imm19 = (insn >> 5) & 0x7FFFF
            if imm19 & (1<<18): imm19 -= (1<<19)
            target = (i - delta) + imm19*4
            cname = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV'][cond]
            desc = f"B.{cname} {hex(target)} (file {hex(target+delta)})"
        elif (insn >> 24) == 0x35:
            # CBNZ
            imm19 = (insn >> 5) & 0x7FFFF
            if imm19 & (1<<18): imm19 -= (1<<19)
            target = (i - delta) + imm19*4
            desc = f"CBNZ x{insn&0x1f}, {hex(target)} (file {hex(target+delta)})"
        elif (insn >> 24) == 0x34:
            # CBZ
            imm19 = (insn >> 5) & 0x7FFFF
            if imm19 & (1<<18): imm19 -= (1<<19)
            target = (i - delta) + imm19*4
            desc = f"CBZ x{insn&0x1f}, {hex(target)} (file {hex(target+delta)})"
        elif (insn >> 23) == 0x122:
            imm12 = (next_insn >> 10) & 0xFFF if False else (insn >> 10) & 0xFFF
            shift = (insn >> 22) & 1
            if shift: imm12 <<= 12
            desc = f"ADD x{insn&0x1f}, x{(insn>>5)&0x1f}, #{hex(imm12)}"
        elif (insn & 0xFFC00000) == 0x52800000 or (insn & 0xFFC00000) == 0xD2800000:
            # MOVZ
            imm16 = (insn >> 5) & 0xFFFF
            desc = f"MOV/MOVZ x{insn&0x1f}, #{hex(imm16)}"
        print(f"  {hex(i)} [{insn:08x}] {desc}{marker}")

for ref in refs_error[:3]:
    show_context(d, ref)
    print()

for ref in refs_unlocked[:3]:
    show_context(d, ref)
    print()

# ===== Strategy B: search also in full file (in case strings ref from .data area code) =====
print("=== Extended search: entire file ===")
def find_adrp_add_full(data, target_va, delta=DELTA):
    results = []
    target_page = target_va & ~0xFFF
    target_off  = target_va & 0xFFF
    for i in range(0, len(data)-8, 4):
        insn = struct.unpack_from('<I', data, i)[0]
        if (insn & 0x9F000000) != 0x90000000: continue
        rd    = insn & 0x1f
        immlo = (insn >> 29) & 3
        immhi = (insn >> 5) & 0x7FFFF
        raw_imm = (immhi << 2) | immlo
        if raw_imm & (1 << 20): raw_imm -= (1 << 21)
        imm = raw_imm << 12
        pc_va = i - delta
        page  = (pc_va & ~0xFFF) + imm
        if page != target_page: continue
        next_insn = struct.unpack_from('<I', data, i+4)[0]
        if (next_insn >> 23) == 0x122:
            imm12 = (next_insn >> 10) & 0xFFF
            shift = (next_insn >> 22) & 1
            if shift: imm12 <<= 12
            if imm12 == target_off:
                results.append(i)
    return list(dict.fromkeys(results))

r_err = find_adrp_add_full(d, STR_ERROR_VA)
r_unl = find_adrp_add_full(d, STR_UNLOCKED_VA)
r_ver = find_adrp_add_full(d, STR_VERDIS_VA)
print(f"'ERROR' full scan: {len(r_err)}: {[hex(x) for x in r_err]}")
print(f"'Unlocked' full scan: {len(r_unl)}: {[hex(x) for x in r_unl]}")
print(f"'VERDIS' full scan: {len(r_ver)}: {[hex(x) for x in r_ver]}")
print()

# ===== Strategy C: Pointer to string in GOT/Data section =====
print("=== Pointer scan for string VAs ===")
for name, va in [('Unlocked', STR_UNLOCKED_VA), ('ERROR', STR_ERROR_VA), ('VERDIS', STR_VERDIS_VA)]:
    target_bytes = struct.pack('<Q', va)
    pos = 0
    found = []
    while True:
        pos = d.find(target_bytes, pos)
        if pos < 0: break
        found.append(hex(pos))
        pos += 1
    print(f"  '{name}' VA {hex(va)} as 8-byte ptr: {found}")
    # Also search for file offset
    target_bytes2 = struct.pack('<Q', va + DELTA)
    pos = 0
    found2 = []
    while True:
        pos = d.find(target_bytes2, pos)
        if pos < 0: break
        found2.append(hex(pos))
        pos += 1
    print(f"  '{name}' fileoff {hex(va+DELTA)} as 8-byte ptr: {found2}")

print()

# ===== Strategy D: ADRP+LDR from pointer table =====
print("=== ADRP+LDR pointer load search ===")
def find_adrp_ldr_full(data, target_va, delta=DELTA):
    results = []
    for i in range(0, len(data)-8, 4):
        insn = struct.unpack_from('<I', data, i)[0]
        if (insn & 0x9F000000) != 0x90000000: continue
        rd    = insn & 0x1f
        immlo = (insn >> 29) & 3
        immhi = (insn >> 5) & 0x7FFFF
        raw_imm = (immhi << 2) | immlo
        if raw_imm & (1 << 20): raw_imm -= (1 << 21)
        imm = raw_imm << 12
        pc_va = i - delta
        page  = (pc_va & ~0xFFF) + imm

        next_insn = struct.unpack_from('<I', data, i+4)[0]
        # LDR 64-bit unsigned: bits[31:22] = 1111100101
        if (next_insn >> 22) != 0x3E5: continue
        rn  = (next_insn >> 5) & 0x1f
        rd2 = next_insn & 0x1f
        scaled_off = ((next_insn >> 10) & 0xFFF) * 8
        if rn != rd: continue

        # The pointer is at VA = page + scaled_off
        ptr_va       = page + scaled_off
        ptr_file_off = ptr_va + delta
        if 0 <= ptr_file_off < len(data)-8:
            ptr_val = struct.unpack_from('<Q', data, ptr_file_off)[0]
            if ptr_val == target_va:
                results.append((i, hex(ptr_file_off), hex(ptr_val)))
    return results

for name, va in [('Unlocked', STR_UNLOCKED_VA), ('ERROR', STR_ERROR_VA)]:
    refs = find_adrp_ldr_full(d, va)
    print(f"  '{name}' ADRP+LDR refs: {len(refs)}: {refs[:5]}")
