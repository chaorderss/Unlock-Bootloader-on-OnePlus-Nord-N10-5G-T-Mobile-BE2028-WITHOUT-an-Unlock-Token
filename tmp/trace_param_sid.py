#!/usr/bin/env python3
"""Trace SID 0x12C usage and OemCheckResetDevInfo in ABL"""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

with open("/tmp/ffs_modules/pe32_59d536f5_1.bin", "rb") as f:
    data = f.read()

cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
cs.detail = True

def disasm(start, size=128):
    result = []
    for insn in cs.disasm(data[start:start+size], start):
        line = f"  0x{insn.address:05X}: {insn.mnemonic:8s} {insn.op_str}"
        result.append(line)
        print(line)
    return result

# 1. Disassemble context around each 0x12C reference
sid_refs = [0x28BD4, 0x33D64, 0x344D4, 0x34AB0, 0x34B20, 0x34B9C, 0x35B88, 0x36164, 0x36224]
for ref in sid_refs:
    print(f"\n=== Context around 0x12C ref at 0x{ref:05X} ===")
    disasm(ref - 0x20, 0x60)

# 2. Trace OemCheckResetDevInfo function
# String at 0x60B93 is referenced by ADRP+ADD pattern
print("\n\n=== Finding OemCheckResetDevInfo callers ===")
# Search for ADRP to page 0x60000 with ADD targeting 0x60B93
for offset in range(0, 0x69000, 4):
    insn_bytes = struct.unpack_from('<I', data, offset)[0]
    # ADRP instruction: [31] op=1 [30:29] immlo [28:24] 10000 [23:5] immhi [4:0] Rd
    if (insn_bytes & 0x9F000000) == 0x90000000:
        rd = insn_bytes & 0x1F
        immhi = (insn_bytes >> 5) & 0x7FFFF
        immlo = (insn_bytes >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm -= 0x200000
        page = ((offset >> 12) + imm) << 12
        if page == 0x60000:
            # Check next instruction for ADD with offset
            if offset + 4 < len(data):
                next_bytes = struct.unpack_from('<I', data, offset+4)[0]
                # ADD Xd, Xn, #imm12
                if (next_bytes & 0xFFC00000) == 0x91000000:
                    add_imm = (next_bytes >> 10) & 0xFFF
                    rn = (next_bytes >> 5) & 0x1F
                    if rn == rd and add_imm == 0xB93:
                        print(f"  Reference to 0x60B93 at 0x{offset:05X}")

# 3. Find the actual OemCheckResetDevInfo function
# Search for "reset_devinfo" string ref (at 0x60BA9)
print("\n=== Finding refs to reset_devinfo string (0x60BA9) ===")
for offset in range(0, 0x69000, 4):
    insn_bytes = struct.unpack_from('<I', data, offset)[0]
    if (insn_bytes & 0x9F000000) == 0x90000000:
        rd = insn_bytes & 0x1F
        immhi = (insn_bytes >> 5) & 0x7FFFF
        immlo = (insn_bytes >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm -= 0x200000
        page = ((offset >> 12) + imm) << 12
        if page == 0x60000:
            if offset + 4 < len(data):
                next_bytes = struct.unpack_from('<I', data, offset+4)[0]
                if (next_bytes & 0xFFC00000) == 0x91000000:
                    add_imm = (next_bytes >> 10) & 0xFFF
                    rn = (next_bytes >> 5) & 0x1F
                    if rn == rd and add_imm == 0xBA9:
                        print(f"  Reference to 0x60BA9 at 0x{offset:05X}")
                    elif rn == rd and add_imm == 0xBD5:
                        print(f"  Reference to 0x60BD5 at 0x{offset:05X}")

# 4. Disasm the caller at 0x48838 (uses 0x1DA4 near IsAllowUnlock code)
print("\n=== Context around IsAllowUnlock caller of 0x1DA4 at 0x48838 ===")
disasm(0x487F0, 0xC0)

# 5. Check what "set_param_by_index" does - find string
print("\n=== Searching for 'set_param_by_index' ===")
idx = data.find(b"set_param_by_index")
while idx != -1:
    print(f"  Found at 0x{idx:05X}: {data[idx:idx+50]}")
    idx = data.find(b"set_param_by_index", idx+1)

# 6. Check param read functions - "read_param" or "get_param"
print("\n=== Searching for param-related strings ===")
for s in [b"read_param", b"get_param", b"write_param", b"set_param",
          b"param_by_index", b"param_index"]:
    idx = 0
    while True:
        pos = data.find(s, idx)
        if pos == -1:
            break
        print(f"  '{s.decode()}' at 0x{pos:05X}: {data[pos:pos+60]}")
        idx = pos + 1
