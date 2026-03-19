#!/usr/bin/env python3
"""Manually check ADRP and following instructions to understand the pattern."""
import struct
from capstone import *

with open('/tmp/abl_dec.bin', 'rb') as f:
    data = f.read()

MZ = 0xB8
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

def disasm_at(rva, count=8):
    foff = rva + MZ
    code = data[foff:foff+count*4]
    result = []
    for ins in md.disasm(code, rva):
        result.append(f"  0x{ins.address:06X}: {ins.bytes.hex():16s}  {ins.mnemonic:8s} {ins.op_str}")
    return result

# Check several ADRP X2, 0x61000 locations
adrp_rvas = [0x004DF0, 0x007714, 0x00773C, 0x007764, 0x008E80, 0x008EB0, 0x008F3C]

for rva in adrp_rvas:
    print(f"\n=== RVA 0x{rva:06X} (+8 instructions) ===")
    for line in disasm_at(rva, 8):
        print(line)

# The key insight: maybe the code uses ADRP + ADD but with a different ADD encoding
# Or ADRP + LDR or ADRP + STR
# Let's check what instruction follows each ADRP X2, 0x61000

print("\n\n=== All ADRP X2, 0x61000 + next instruction ===")
count = 0
for off in range(0x10B8, 0x6A0B8 - 8, 4):
    insn = struct.unpack_from('<I', data, off)[0]
    if (insn >> 24) & 0x9F != 0x90:
        continue
    pc_rva = off - MZ
    pc_page = pc_rva & ~0xFFF
    immlo = (insn >> 29) & 3
    immhi = (insn >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & 0x100000:
        imm -= 0x200000
    adrp_target = pc_page + (imm << 12)

    if adrp_target != 0x61000:
        continue

    rd = insn & 0x1F

    # Decode next instruction
    next_insn = struct.unpack_from('<I', data, off + 4)[0]
    next_rva = pc_rva + 4

    # Get capstone disassembly of the next instruction
    code2 = data[off+4:off+8]
    dis = list(md.disasm(code2, next_rva))
    if dis:
        ni = dis[0]
        next_str = f"{ni.mnemonic} {ni.op_str}"
    else:
        next_str = f"(raw: 0x{next_insn:08X})"

    if count < 30:  # Limit output
        print(f"  0x{pc_rva:06X}: ADRP X{rd}, 0x61000  ->  0x{next_rva:06X}: {next_str}")
    count += 1

print(f"\nTotal ADRP X2/etc targeting 0x61000: {count}")
