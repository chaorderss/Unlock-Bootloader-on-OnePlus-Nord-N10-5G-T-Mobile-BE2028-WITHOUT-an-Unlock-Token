#!/usr/bin/env python3
"""Trace boot sequence after ReadDeviceInfo failure, and find other partition GUIDs."""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

with open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb') as f:
    pe = f.read()

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = False

def disasm_range(name, start, end):
    print(f"\n{'='*60}")
    print(f"  {name} @ 0x{start:X} - 0x{end:X}")
    print(f"{'='*60}")
    code = pe[start:end]
    for inst in md.disasm(code, start):
        line = f"  0x{inst.address:05X}: {inst.mnemonic:8s} {inst.op_str}"
        if inst.mnemonic == 'bl':
            try:
                target = int(inst.op_str.replace('#', ''), 16)
                known = {
                    0x18248: "ReadWritePartition_devinfo",
                    0x384D0: "init_defaults",
                    0x232D8: "ReadDeviceInfo",
                    0x4FD10: "CompareMem",
                    0x280FC: "LogPrint",
                    0x22C18: "IsDeviceUnlocked",
                    0x38800: "IsSecureBootEnabled",
                    0x362D8: "OemCheckResetDevInfo",
                    0x367F0: "MainBoot",
                    0x1F8F0: "PostInit1",
                    0x1EA00: "PostInit2",
                    0x1B990: "PreInit",
                }
                if target in known:
                    line += f"  ; {known[target]}"
            except:
                pass
        print(line)

# 1. Boot sequence around ReadDeviceInfo call
disasm_range("Boot sequence around ReadDeviceInfo", 0x01540, 0x01680)

# 2. Find all BL 0x18248 calls (ReadWritePartition for devinfo)
print(f"\n{'='*60}")
print(f"  ALL callers of ReadWritePartition (0x18248)")
print(f"{'='*60}")
callers = []
for i in range(0, len(pe) - 4, 4):
    word = struct.unpack('<I', pe[i:i+4])[0]
    if (word >> 26) == 0x25:  # BL
        imm = word & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        target = i + imm * 4
        if target == 0x18248:
            callers.append(i)
            print(f"  0x{i:05X}: BL 0x18248")
print(f"  Total: {len(callers)} callers")

# 3. Find other BL instructions near each caller to understand context
# Look for OTHER functions similar to ReadWritePartition that use different GUIDs
# Search for LocateProtocol pattern: ADRP + ADD to 0x69000 page (where GUIDs are)
print(f"\n{'='*60}")
print(f"  All ADRP references to GUID page 0x69000")
print(f"{'='*60}")
for i in range(0, len(pe) - 4, 4):
    word = struct.unpack('<I', pe[i:i+4])[0]
    if (word & 0x9F000000) == 0x90000000:  # ADRP
        rd = word & 0x1F
        immhi = (word >> 5) & 0x7FFFF
        immlo = (word >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm -= 0x200000
        page = (i & ~0xFFF) + (imm << 12)
        if page == 0x69000:
            # Check next instruction for ADD to get exact offset
            if i + 4 < len(pe):
                next_word = struct.unpack('<I', pe[i+4:i+8])[0]
                if (next_word >> 24) == 0x91:  # ADD imm
                    imm12 = (next_word >> 10) & 0xFFF
                    target = page + imm12
                    print(f"  0x{i:05X}: ADRP+ADD -> 0x{target:05X}")

# 4. Dump all GUIDs in the 0x69000 page area
print(f"\n{'='*60}")
print(f"  GUIDs in the 0x69B00-0x69D00 region")
print(f"{'='*60}")
for off in range(0x69B00, 0x69D00, 16):
    data = pe[off:off+16]
    if data == b'\x00' * 16:
        continue
    a, b, c = struct.unpack('<IHH', data[:8])
    d = data[8:16]
    guid = f"{a:08X}-{b:04X}-{c:04X}-{d[:2].hex().upper()}-{d[2:].hex().upper()}"
    print(f"  0x{off:05X}: {guid}")
