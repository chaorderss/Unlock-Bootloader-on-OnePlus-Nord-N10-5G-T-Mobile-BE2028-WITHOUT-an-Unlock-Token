#!/usr/bin/env python3
"""
Find all code that writes to IsAllowUnlock at [0x1C0010]
and trace the data flow from param/settings to the VB protocol check.
"""

from capstone import *
import struct

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

with open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb') as f:
    data = f.read()

# IsAllowUnlock is at 0x1C0010
# accessed via ADRP xN, #0x1C0000 + STR/LDR wM, [xN, #0x10]
target_page = 0x1C0000
target_off = 0x10

print("=== Finding all writes to 0x1C0010 (IsAllowUnlock) ===")
print(f"Target: [ADRP #0x{target_page:X}] + offset #0x{target_off:X}")

# Scan all ADRP instructions to page 0x1C0000
code = data[0x1000:0x69000]
adrp_locs = []
for insn in md.disasm(code, 0x1000):
    if insn.mnemonic == 'adrp' and len(insn.operands) >= 2:
        if insn.operands[1].imm == target_page:
            reg = insn.operands[0].reg
            adrp_locs.append((insn.address, reg))

print(f"Found {len(adrp_locs)} ADRP to page 0x{target_page:X}")

# For each ADRP, scan forward for STR/LDR with offset 0x10
stores = []
loads = []
for addr, reg in adrp_locs:
    # Check next 20 instructions
    for delta in range(4, 80, 4):
        off = addr + delta
        if off >= 0x69000:
            break
        inst_code = data[off:off+4]
        for ni in md.disasm(inst_code, off):
            if '#0x10' in ni.op_str or '#0x10]' in ni.op_str:
                if 'str' in ni.mnemonic:
                    stores.append((addr, off, ni.mnemonic, ni.op_str))
                elif 'ldr' in ni.mnemonic:
                    loads.append((addr, off, ni.mnemonic, ni.op_str))

print(f"\nSTORES to [page+0x10]:")
for adrp_addr, str_addr, mnem, ops in stores:
    print(f"  adrp@0x{adrp_addr:05X} → {mnem} at 0x{str_addr:05X}: {ops}")
    # Show context
    ctx_start = max(0x1000, adrp_addr - 24)
    ctx_end = min(0x69000, str_addr + 24)
    ctx_code = data[ctx_start:ctx_end]
    for insn in md.disasm(ctx_code, ctx_start):
        marker = ''
        if insn.address == adrp_addr:
            marker = ' <<<< ADRP 0x1C0000'
        elif insn.address == str_addr:
            marker = ' <<<< STORE to IsAllowUnlock'
        extra = ''
        if insn.mnemonic == 'bl':
            extra = f'  ; CALL 0x{insn.operands[0].imm:X}'
        elif insn.mnemonic == 'adrp':
            extra = f'  ; page=0x{insn.operands[1].imm:X}'
        print(f"    0x{insn.address:05X}: {insn.mnemonic:<8s} {insn.op_str}{extra}{marker}")
    print()

print(f"\nLOADS from [page+0x10] (IsAllowUnlock reads):")
for adrp_addr, ldr_addr, mnem, ops in loads:
    print(f"  adrp@0x{adrp_addr:05X} → {mnem} at 0x{ldr_addr:05X}: {ops}")

# Also check what value is right NEXT to IsAllowUnlock
# Check [0x1C0000] through [0x1C0020]
print(f"\n=== Data at 0x1C0000 region ===")
for off in [0x1C0000, 0x1C0008, 0x1C0010, 0x1C0018, 0x1C0020]:
    val = struct.unpack_from('<Q', data, off)[0]
    print(f"  [0x{off:05X}] = 0x{val:016X}")

# Let's also look at what the VB protocol method_0x30 might return
# by checking the DXE driver or other firmware modules
# First check if there are other PE32 modules extracted
import os
print(f"\n=== Checking /tmp/ffs_modules ===")
for f in sorted(os.listdir('/tmp/ffs_modules')):
    path = os.path.join('/tmp/ffs_modules', f)
    size = os.path.getsize(path)
    with open(path, 'rb') as fh:
        header = fh.read(4)
    is_pe = header[:2] == b'MZ'
    print(f"  {f}: {size} bytes {'(PE)' if is_pe else ''}")
