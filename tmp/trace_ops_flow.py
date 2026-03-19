#!/usr/bin/env python3
"""Trace how ops flag (SID 0x12C, offset 0x80) affects unlock decision"""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

with open("/tmp/ffs_modules/pe32_59d536f5_1.bin", "rb") as f:
    data = f.read()

cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
cs.detail = True

def disasm(start, size=128):
    for insn in cs.disasm(data[start:start+size], start):
        print(f"  0x{insn.address:05X}: {insn.mnemonic:8s} {insn.op_str}")

# 1. Find callers of 0x36158 (ops flag reader function)
print("=== Callers of 0x36158 (ops flag reader) ===")
for offset in range(0, len(data)-4, 4):
    insn_bytes = struct.unpack_from('<I', data, offset)[0]
    if (insn_bytes & 0xFC000000) == 0x94000000:
        imm26 = insn_bytes & 0x03FFFFFF
        if imm26 & 0x02000000:
            imm26 |= ~0x03FFFFFF
        target = offset + (imm26 << 2)
        if target == 0x36158:
            print(f"  Caller at 0x{offset:05X}")

# 2. Find callers of 0x361F0 (the other function with SID 0x12C + offset 0x80)
# Let me find its entry point first - look for prologue before 0x36204
print("\n=== Function near 0x36224 (entry) ===")
disasm(0x361E8, 0x100)

# 3. Check what data is at 0x6842C (GUID or partition name used in unlock handler)
print("\n=== Data at 0x6842C (used by unlock handler at 0x48850) ===")
guid_data = data[0x6842C:0x6843C]
print(f"  Raw: {guid_data.hex()}")
a, b, c = struct.unpack_from('<IHH', guid_data, 0)
d = guid_data[8:16]
print(f"  GUID: {a:08X}-{b:04X}-{c:04X}-{d[:2].hex()}-{d[2:].hex()}")
# Also check UTF-16 at that offset
try:
    s = guid_data.decode('utf-16-le').rstrip('\x00')
    print(f"  UTF-16: {s}")
except:
    pass

# 4. Disassemble the full unlock handler from entry to understand flow
# First, find the entry point. The code at 0x487F0 is mid-function.
# Search backwards for prologue
print("\n=== Searching for unlock handler entry point ===")
for addr in range(0x487F0, 0x48400, -4):
    insn_bytes = struct.unpack_from('<I', data, addr)[0]
    # STP with pre-index (prologue pattern)
    if (insn_bytes & 0xFFC00000) in [0xA9800000, 0xA9A00000, 0xA9C00000]:
        # Check if it's a plausible function entry
        if addr > 0 and struct.unpack_from('<I', data, addr-4)[0] & 0xFC000000 in [0x14000000, 0xD6000000, 0xD5000000]:
            print(f"  Possible entry at 0x{addr:05X}")
    # Also check for "sub sp, sp, #imm" pattern
    if (insn_bytes & 0xFF0003E0) == 0xD10003E0:  # SUB SP, SP, #imm
        imm = (insn_bytes >> 10) & 0xFFF
        if imm >= 0x40:  # reasonable stack frame
            print(f"  SUB SP at 0x{addr:05X} (frame size 0x{imm:X})")

# 5. Disasm around 0x48968 (error when IsAllowUnlock=0 and 0x3A258 returns 0)
print("\n=== Error path at 0x48968 (IsAllowUnlock=0 blocked) ===")
disasm(0x48960, 0x60)

# 6. Disasm function 0x3A258 (called when IsAllowUnlock=0)
print("\n=== Function 0x3A258 (IsAllowUnlock=0 fallback) ===")
disasm(0x3A258, 0x80)

# 7. Disasm function 0x3BB48 (called before level check)
print("\n=== Function 0x3BB48 (pre-unlock check) ===")
disasm(0x3BB48, 0x80)

# 8. What happens after protocol->method_0x10 call?
print("\n=== After protocol call at 0x488A8 ===")
disasm(0x488A8, 0x100)

# 9. Check the OemCheckResetDevInfo function - find its entry
# The string "OemCheckResetDevInfo" at 0x60B93 and reset_devinfo at 0x60BA9
# Let me search ADRP refs to these
print("\n=== Finding ADRP refs to 0x60B93 area (page 0x60000) ===")
refs_60000 = []
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
                    if rn == rd:
                        target_addr = 0x60000 + add_imm
                        if 0x60B80 <= target_addr <= 0x60C10:
                            refs_60000.append((offset, target_addr))

for addr, target in refs_60000:
    string_end = data.find(b'\x00', target)
    s = data[target:string_end].decode('ascii', errors='replace')
    print(f"  0x{addr:05X} → 0x{target:05X}: \"{s}\"")

# 10. Disasm the actual OemCheckResetDevInfo function
# Let me check callers and their context
print("\n=== Tracing OemCheckResetDevInfo ===")
# From boot sequence: BL OemCheckResetDevInfo within ProcessParams
# Find BL targets in 0x36000-0x38000 range (param processing area)
for target_addr in [0x36158, 0x361F0, 0x361F8]:
    count = 0
    for offset in range(0, len(data)-4, 4):
        insn_bytes = struct.unpack_from('<I', data, offset)[0]
        if (insn_bytes & 0xFC000000) == 0x94000000:
            imm26 = insn_bytes & 0x03FFFFFF
            if imm26 & 0x02000000:
                imm26 |= ~0x03FFFFFF
            t = offset + (imm26 << 2)
            if t == target_addr:
                count += 1
                if count <= 5:
                    print(f"  BL 0x{target_addr:05X} called from 0x{offset:05X}")
    if count > 5:
        print(f"  ... and {count-5} more callers")
