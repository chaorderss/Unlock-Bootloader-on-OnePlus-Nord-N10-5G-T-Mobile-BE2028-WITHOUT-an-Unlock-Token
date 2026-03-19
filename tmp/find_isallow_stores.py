#!/usr/bin/env python3
"""Check all 23 ADRP refs to 0x1C0000 for STR with offset 0x10."""

from capstone import *
import struct

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

with open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb') as f:
    data = f.read()

target_page = 0x1C0000

# Find all ADRP to 0x1C0000 using binary search (proven working)
adrp_locs = []
for off in range(0x1000, 0x69000, 4):
    word = struct.unpack_from('<I', data, off)[0]
    if (word & 0x9F000000) == 0x90000000:
        immlo = (word >> 29) & 0x3
        immhi = (word >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm |= ~0x1FFFFF
            imm &= 0xFFFFFFFF
            imm = imm if imm < 0x80000000 else imm - 0x100000000
        page_base = off & ~0xFFF
        result_page = (page_base + (imm << 12)) & 0xFFFFFFFF
        if result_page == target_page:
            rd = word & 0x1F
            adrp_locs.append((off, rd))

print(f"Found {len(adrp_locs)} ADRP to 0x{target_page:X}")

# For each, check surrounding instructions for STR or LDR with offset 0x10
for addr, rd in adrp_locs:
    # Disassemble 10 instructions starting from ADRP
    ctx = data[addr:addr+44]
    is_store = False
    is_load = False
    detail = ''
    for insn in md.disasm(ctx, addr):
        if insn.address == addr:
            continue
        # Check for STR/LDR with offset 0x10
        if '#0x10]' in insn.op_str or '#0x10,' in insn.op_str:
            if 'str' in insn.mnemonic:
                is_store = True
                detail = f"0x{insn.address:05X}: {insn.mnemonic} {insn.op_str}"
            elif 'ldr' in insn.mnemonic:
                is_load = True
                detail = f"0x{insn.address:05X}: {insn.mnemonic} {insn.op_str}"

    # Also check for ADD #0x10 (computing address)
    for insn in md.disasm(ctx, addr):
        if '#0x10' in insn.op_str and insn.mnemonic == 'add':
            detail += f"  ADD: 0x{insn.address:05X}: {insn.mnemonic} {insn.op_str}"

    if is_store:
        print(f"\n  *** WRITE *** ADRP x{rd} at 0x{addr:05X}: {detail}")
        # Show full context
        full_ctx = data[max(0x1000, addr-16):addr+60]
        for insn in md.disasm(full_ctx, max(0x1000, addr-16)):
            extra = ''
            if insn.mnemonic == 'bl':
                extra = f'  ; CALL 0x{insn.operands[0].imm:X}'
            elif insn.mnemonic == 'adrp':
                extra = f'  ; page=0x{insn.operands[1].imm:X}'
            mark = ' <====' if insn.address == addr or ('str' in insn.mnemonic and '#0x10' in insn.op_str) else ''
            print(f"    0x{insn.address:05X}: {insn.mnemonic:<8s} {insn.op_str}{extra}{mark}")
    elif is_load:
        print(f"  READ at 0x{addr:05X}: {detail}")
    else:
        # Check all offsets used, not just 0x10
        all_offsets = set()
        for insn in md.disasm(ctx, addr):
            if insn.address == addr:
                continue
            for off_str in ['#0x', '#0']:
                if off_str in insn.op_str and ('str' in insn.mnemonic or 'ldr' in insn.mnemonic):
                    all_offsets.add(f"{insn.mnemonic} {insn.op_str}")
        if all_offsets:
            print(f"  OTHER at 0x{addr:05X}: {'; '.join(all_offsets)}")
