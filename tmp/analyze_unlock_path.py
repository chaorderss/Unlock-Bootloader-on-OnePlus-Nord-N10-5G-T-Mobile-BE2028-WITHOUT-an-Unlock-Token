#!/usr/bin/env python3
"""Analyze function 0x1D3E8 (actual unlock call) and the complete unlock paths"""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

with open("/tmp/ffs_modules/pe32_59d536f5_1.bin", "rb") as f:
    data = f.read()

cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
cs.detail = True

def disasm(start, size=256):
    for insn in cs.disasm(data[start:start+size], start):
        print(f"  0x{insn.address:05X}: {insn.mnemonic:8s} {insn.op_str}")

def read_str(offset, max_len=80):
    end = data.find(b'\x00', offset, offset+max_len)
    if end == -1: end = offset + max_len
    return data[offset:end].decode('ascii', errors='replace')

# 1. Function 0x1D3E8 - actual unlock executor
print("=== Function 0x1D3E8 (unlock executor) ===")
disasm(0x1D3E8, 0x120)

# 2. Check what 0x4DD4C does (called in sdebug path)
print("\n=== Function 0x4DD4C ===")
disasm(0x4DD4C, 0x60)

# 3. Check what 0x4DD34 does (format function?)
print("\n=== Function 0x4DD34 ===")
disasm(0x4DD34, 0x40)

# 4. String at 0x667FC
print(f"\n=== String at 0x667FC ===")
print(f"  {read_str(0x667FC)}")
print(f"  {read_str(0x66816)}")

# 5. Check 0x38420 (called by carrier check after model match)
print("\n=== Function 0x38420 (carrier additional check) ===")
disasm(0x38420, 0xA0)

# 6. Find complete unlock handler entry point and disassemble
# Try 0x48708 which was detected as a possible entry
print("\n=== Unlock handler from 0x48708 ===")
disasm(0x48708, 0x110)

# 7. Check if 0x1D3E8 calls SetDeviceUnlocked (0x22DB8)
# Search for BL 0x22DB8 within 0x1D3E8 function
print("\n=== BL 0x22DB8 callers ===")
for offset in range(0, len(data)-4, 4):
    insn_bytes = struct.unpack_from('<I', data, offset)[0]
    if (insn_bytes & 0xFC000000) == 0x94000000:
        imm26 = insn_bytes & 0x03FFFFFF
        if imm26 & 0x02000000:
            imm26 |= ~0x03FFFFFF
        target = offset + (imm26 << 2)
        if target == 0x22DB8:
            print(f"  BL 0x22DB8 at 0x{offset:05X}")

# 8. Check what 0xD6C0 does (called at 0x489A0 in the sdebug null path)
print("\n=== Function 0xD6C0 (reboot control?) ===")
disasm(0xD6C0, 0x60)
