#!/usr/bin/env python3
"""Verify if 0x1DAC and 0x1DA4 are truly hardcoded or read from param/config"""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

with open("/tmp/ffs_modules/pe32_59d536f5_1.bin", "rb") as f:
    data = f.read()

cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
cs.detail = True

def disasm(start, size=64):
    for insn in cs.disasm(data[start:start+size], start):
        print(f"  0x{insn.address:05X}: {insn.mnemonic:8s} {insn.op_str}")

# Full context around 0x1DAC and 0x1DA4
print("=== Function at 0x1DA4 (returns 2?) ===")
disasm(0x1D90, 48)

print("\n=== Function at 0x1DAC (returns 1?) ===")
disasm(0x1DA8, 32)

# Search for BL callers
print("\n=== Searching for BL 0x1DA4 callers ===")
for offset in range(0, len(data)-4, 4):
    insn_bytes = struct.unpack_from('<I', data, offset)[0]
    if (insn_bytes & 0xFC000000) == 0x94000000:
        imm26 = insn_bytes & 0x03FFFFFF
        if imm26 & 0x02000000:
            imm26 |= ~0x03FFFFFF
        target = offset + (imm26 << 2)
        if target == 0x1DA4:
            print(f"  Caller at 0x{offset:05X}")

print("\n=== Searching for BL 0x1DAC callers ===")
for offset in range(0, len(data)-4, 4):
    insn_bytes = struct.unpack_from('<I', data, offset)[0]
    if (insn_bytes & 0xFC000000) == 0x94000000:
        imm26 = insn_bytes & 0x03FFFFFF
        if imm26 & 0x02000000:
            imm26 |= ~0x03FFFFFF
        target = offset + (imm26 << 2)
        if target == 0x1DAC:
            print(f"  Caller at 0x{offset:05X}")

# Wider context
print("\n=== Context 0x1D80-0x1DD0 ===")
disasm(0x1D80, 80)

# Raw bytes
print(f"\n=== Raw bytes at 0x1DA0-0x1DB8 ===")
for i in range(0x1DA0, 0x1DB8, 4):
    val = struct.unpack_from('<I', data, i)[0]
    print(f"  0x{i:05X}: {val:08X}")

# Now trace what param partition does to ABL
# Search for "param" string in UTF-16
print("\n=== Searching for 'param' UTF-16 references ===")
param_utf16 = "param".encode('utf-16-le')
idx = 0
while True:
    pos = data.find(param_utf16, idx)
    if pos == -1:
        break
    # Check if null-terminated
    end = pos + len(param_utf16)
    if end < len(data) and data[end] == 0 and data[end+1] == 0:
        print(f"  'param' at 0x{pos:05X}: {data[pos:pos+20].hex()}")
    idx = pos + 1

# Search for "ops" string
print("\n=== Searching for 'ops' references ===")
for pattern in [b"ops\x00", b"OPS\x00", b"o\x00p\x00s\x00\x00\x00"]:
    idx = 0
    while True:
        pos = data.find(pattern, idx)
        if pos == -1:
            break
        print(f"  Pattern {pattern!r} at 0x{pos:05X}")
        idx = pos + 1

# Search for SID 0x12C (300 decimal) - the param sector ID used by enable_ops
print("\n=== Searching for immediate #0x12C in code ===")
for offset in range(0, min(0x69000, len(data)-4), 4):
    insn_bytes = struct.unpack_from('<I', data, offset)[0]
    # MOV immediate or CMP/ADD with #0x12C
    # MOVZ Wd, #imm16
    if (insn_bytes & 0xFF800000) == 0x52800000:
        imm16 = (insn_bytes >> 5) & 0xFFFF
        if imm16 == 0x12C:
            print(f"  MOV at 0x{offset:05X}: imm=0x{imm16:X}")
    # MOVZ Xd, #imm16
    if (insn_bytes & 0xFF800000) == 0xD2800000:
        imm16 = (insn_bytes >> 5) & 0xFFFF
        if imm16 == 0x12C:
            print(f"  MOV at 0x{offset:05X}: imm=0x{imm16:X}")

# Also search for value 0x80 near param-related code
# Better: search for "reset_devinfo" string
print("\n=== Searching for 'reset_devinfo' ===")
idx = data.find(b"reset_devinfo")
while idx != -1:
    print(f"  Found at 0x{idx:05X}")
    idx = data.find(b"reset_devinfo", idx+1)

# Search "IsAllowUnlock" string
print("\n=== Searching for 'IsAllowUnlock' ===")
idx = data.find(b"IsAllowUnlock")
while idx != -1:
    print(f"  Found at 0x{idx:05X}")
    idx = data.find(b"IsAllowUnlock", idx+1)

# Check for "OemCheckResetDevInfo"
print("\n=== Searching for 'OemCheck' ===")
idx = data.find(b"OemCheck")
while idx != -1:
    print(f"  Found at 0x{idx:05X}: {data[idx:idx+40]}")
    idx = data.find(b"OemCheck", idx+1)
