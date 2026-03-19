#!/usr/bin/env python3
"""Check what buffers each ReadWritePartition caller uses."""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

with open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb') as f:
    pe = f.read()

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = False

callers = [
    0x1D310, 0x22CDC, 0x22D6C, 0x22E54, 0x22EA8, 0x22F14, 0x23004,
    0x23208, 0x232FC, 0x2352C, 0x23648, 0x236DC, 0x30A94, 0x370F4,
    0x37570, 0x37C54, 0x38448, 0x385C4, 0x38638, 0x3A140, 0x3A19C,
    0x3A414, 0x3A6E8, 0x3A7D0, 0x3A8B0, 0x3BC70, 0x3BCE4, 0x3BD18,
    0x3BD4C, 0x3BD78, 0x3C1B8, 0x3C2D8, 0x3C384, 0x3C3B0, 0x3C5B8,
    0x3C698, 0x3C848, 0x3C9A4, 0x3CA60,
]

# For each caller, disassemble the 10 instructions before the BL
# to find what buffer (x1) and mode (w0) are set
print("Caller context analysis (instructions before BL 0x18248):")
print(f"{'='*70}")
for addr in callers:
    start = max(0, addr - 40)
    code = pe[start:addr+4]
    print(f"\n--- Caller at 0x{addr:05X} ---")
    for inst in md.disasm(code, start):
        line = f"  0x{inst.address:05X}: {inst.mnemonic:8s} {inst.op_str}"
        # Highlight buffer setup (x1/add involving 0x978 = devinfo buf offset)
        if '0x978' in inst.op_str:
            line += "  <<< devinfo buffer!"
        if '0x18248' in inst.op_str:
            line += "  <<< ReadWritePartition"
        print(line)
