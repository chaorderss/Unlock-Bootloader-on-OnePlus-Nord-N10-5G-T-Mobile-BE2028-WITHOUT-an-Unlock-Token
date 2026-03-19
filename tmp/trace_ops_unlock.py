#!/usr/bin/env python3
"""Trace ops flag influence on unlock path and read error strings"""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

with open("/tmp/ffs_modules/pe32_59d536f5_1.bin", "rb") as f:
    data = f.read()

cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
cs.detail = True

def disasm(start, size=128):
    for insn in cs.disasm(data[start:start+size], start):
        print(f"  0x{insn.address:05X}: {insn.mnemonic:8s} {insn.op_str}")

def read_str(offset, max_len=80):
    end = data.find(b'\x00', offset, offset+max_len)
    if end == -1:
        end = offset + max_len
    return data[offset:end].decode('ascii', errors='replace')

# 1. Read all relevant error/info strings
print("=== Key Strings ===")
for addr in [0x667DC, 0x66816, 0x66846, 0x66860, 0x667BD, 0x667FC, 0x66DD2]:
    s = read_str(addr)
    print(f"  0x{addr:05X}: \"{s}\"")

# Carrier-related strings from 0x3BB48
for addr in [0x5F53B, 0x5F524, 0x5FB26, 0x5FB2C]:
    s = read_str(addr)
    print(f"  0x{addr:05X}: \"{s}\"")

# String from 0x60B30 (used by 0x35BB0 with SID 0x12C)
for addr in [0x60B30, 0x605BA]:
    s = read_str(addr)
    print(f"  0x{addr:05X}: \"{s}\"")

# 2. Disassemble the SINGLE caller of 0x361F0 at 0x47644
print("\n=== Context around caller of 0x361F0 at 0x47644 ===")
disasm(0x47600, 0xC0)

# 3. Function 0x34AF0 (validates protocol result after unlock)
print("\n=== Function 0x34AF0 ===")
disasm(0x34AF0, 0x80)

# 4. Check what 0x34B40's cmp #0xA9E means
print("\n=== Context at 0x34B40 (0xA9E check) ===")
disasm(0x34B20, 0x60)

# 5. Trace function 0x3A258 more carefully
# When IsAllowUnlock=0, this is called. It reads ops flag.
# At 0x3A290: bl 0x36158 → read ops flag
# At 0x3A294: bl 0x34A80 → check ops validity
# The result determines if unlock proceeds
print("\n=== Function 0x34A80 (ops validator) ===")
disasm(0x34A80, 0x80)

# 6. What does 0x3A258 return when ops=3?
# Let me trace the conditional logic more carefully
print("\n=== Full 0x3A258 function ===")
disasm(0x3A258, 0xB0)

# 7. String at 0x5F53B and others (carrier check)
print("\n=== Carrier check strings ===")
# 0x3BB48 calls 0x2A1EC with multiple strings
# Let me check what those strings are
for addr in [0x5F53B, 0x5F524, 0x5FB26, 0x5FB2C, 0x5F513]:
    s = read_str(addr)
    print(f"  0x{addr:05X}: \"{s}\"")

# 8. What's the global at 0x1C757C and 0x1C757D? These affect ops behavior
print("\n=== Globals 0x1C757C-0x1C757D ===")
print(f"  [0x1C757C] = 0x{data[0x1C757C]:02X}")
print(f"  [0x1C757D] = 0x{data[0x1C757D]:02X}")

# 9. What's at [0x1BFF38] (used in 0x3A258)?
print(f"  [0x1BFF38] = 0x{data[0x1BFF38]:02X}")

# 10. Function 0x38610 (called by 0x3BB48 - first thing)
print("\n=== Function 0x38610 (carrier data getter) ===")
disasm(0x38610, 0x60)

# 11. Check what function at 0x1D3E8 does (called at 0x4897C for actual unlock)
print("\n=== Function 0x1D3E8 (unlock executor?) ===")
disasm(0x1D3E8, 0x80)
