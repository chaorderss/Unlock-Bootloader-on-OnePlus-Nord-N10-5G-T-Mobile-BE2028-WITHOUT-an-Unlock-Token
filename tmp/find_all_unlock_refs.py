#!/usr/bin/env python3
"""Brute-force scan: find ALL ADRP+ADD pairs and check targets in key ranges."""

import struct

PE32 = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
with open(PE32, 'rb') as f:
    data = f.read()

def get_string_at(addr):
    if addr < 0 or addr >= len(data):
        return None
    end = data.find(b'\x00', addr)
    if end < 0 or end - addr > 200:
        return None
    try:
        s = data[addr:end].decode('ascii')
        return s if len(s) >= 3 else None
    except:
        return None

SCAN_END = 0x89000

# Scan ALL ADRP+ADD and check for key string ranges
interesting_ranges = [
    (0x05000, 0x070000, "strings area"),
]

print("=== All ADRP+ADD pairs pointing to unlock/devinfo strings ===")
count = 0
for pc in range(0, SCAN_END, 4):
    if pc + 8 > len(data):
        break
    insn1 = struct.unpack_from('<I', data, pc)[0]
    insn2 = struct.unpack_from('<I', data, pc + 4)[0]

    # Must be ADRP
    if (insn1 & 0x9F000000) != 0x90000000:
        continue

    immlo = (insn1 >> 29) & 0x3
    immhi = (insn1 >> 5) & 0x7FFFF
    imm = ((immhi << 2) | immlo) << 12
    if imm & (1 << 32):
        imm -= (1 << 33)

    adrp_result = (pc & ~0xFFF) + imm
    rd = insn1 & 0x1F

    # Check ADD imm12
    if (insn2 & 0xFFC00000) == 0x91000000:
        add_imm = (insn2 >> 10) & 0xFFF
        add_rn = (insn2 >> 5) & 0x1F
        add_rd = insn2 & 0x1F

        if add_rn == rd:
            target = adrp_result + add_imm
            s = get_string_at(target)
            if s and any(kw in s.lower() for kw in [
                'unlock', 'devinfo', 'param', 'set_param', 'get_param',
                'oem', 'locked', 'is_unlock', 'reset_dev', 'device_info',
                'android-boot', 'tamper', 'encrypt', 'md5'
            ]):
                print(f"  0x{pc:05x}: x{add_rd} -> 0x{target:06x} \"{s[:100]}\"")
                count += 1

print(f"\nTotal: {count} references found")
print("\n[done]")
