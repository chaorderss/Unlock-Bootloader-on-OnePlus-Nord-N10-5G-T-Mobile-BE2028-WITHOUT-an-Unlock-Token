#!/usr/bin/env python3
"""
1. Find get_param_by_index_and_offset function and its callers
2. Check if any code reads param SID 13 and writes to devinfo
3. Compare param.bin vs param_global_patched.bin
4. Trace OemCheckResetDevInfo complete flow
"""

import struct

PE32 = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
with open(PE32, 'rb') as f:
    pe = f.read()

# set_param_by_index_and_offset is at 0x32620 (called by OemCheckResetDevInfo)
# Find get_param_by_index_and_offset by looking near 0x32620
# The "get" variant string is at 0x06044b

# First: find all BL targets that match 0x32620 (set_param callers)
print("=== Callers of set_param_by_index_and_offset (bl 0x32620) ===")
for pc in range(0, 0x6A000, 4):
    insn = struct.unpack_from('<I', pe, pc)[0]
    if (insn & 0xFC000000) != 0x94000000:
        continue
    offset = insn & 0x3FFFFFF
    if offset & (1 << 25):
        offset -= (1 << 26)
    target = pc + offset * 4
    if target == 0x32620:
        print(f"  0x{pc:05x}: bl 0x32620")

# Find the function that contains the "get_param_by_index_and_offset" string
# Try to find ADRP+ADD refs to 0x06044b and nearby (the string)
print("\n=== Searching for get_param_by_index_and_offset refs ===")
for pc in range(0, 0x6A000, 4):
    if pc + 8 > len(pe):
        break
    insn1 = struct.unpack_from('<I', pe, pc)[0]
    insn2 = struct.unpack_from('<I', pe, pc + 4)[0]

    if (insn1 & 0x9F000000) != 0x90000000:
        continue
    if (insn2 & 0xFFC00000) != 0x91000000:
        continue

    immlo = (insn1 >> 29) & 0x3
    immhi = (insn1 >> 5) & 0x7FFFF
    imm = ((immhi << 2) | immlo) << 12
    if imm & (1 << 32):
        imm -= (1 << 33)

    adrp_result = (pc & ~0xFFF) + imm
    rd = insn1 & 0x1F
    add_rn = (insn2 >> 5) & 0x1F
    if add_rn != rd:
        continue

    add_imm = (insn2 >> 10) & 0xFFF
    target = adrp_result + add_imm

    if target in [0x06044b, 0x060469]:  # get_param string and nearby
        def get_s(a):
            end = pe.find(b'\x00', a)
            return pe[a:end].decode('ascii', errors='replace') if end > a else ''
        print(f"  0x{pc:05x}: x{insn2 & 0x1F} -> 0x{target:06x} \"{get_s(target)[:60]}\"")

# Compare param.bin vs param_global_patched.bin
print("\n\n=== Comparing param.bin vs param_global_patched.bin ===")
with open('/Users/xmxx/pinganhuijia/edl_backup/param.bin', 'rb') as f:
    param_orig = f.read()
with open('/Users/xmxx/pinganhuijia/edl_backup/param_global_patched.bin', 'rb') as f:
    param_patch = f.read()

diff_count = 0
for i in range(min(len(param_orig), len(param_patch))):
    if param_orig[i] != param_patch[i]:
        if diff_count < 100:
            print(f"  0x{i:06x}: orig=0x{param_orig[i]:02x} patch=0x{param_patch[i]:02x}")
        diff_count += 1

print(f"\nTotal different bytes: {diff_count}")
if diff_count > 0 and diff_count < 500:
    # Show the diff regions
    in_diff = False
    start = 0
    diffs = []
    for i in range(min(len(param_orig), len(param_patch))):
        if param_orig[i] != param_patch[i]:
            if not in_diff:
                start = i
                in_diff = True
        else:
            if in_diff:
                diffs.append((start, i))
                in_diff = False
    if in_diff:
        diffs.append((start, min(len(param_orig), len(param_patch))))

    print(f"\nDiff regions: {len(diffs)}")
    for s, e in diffs[:20]:
        print(f"\n  Region 0x{s:06x}-0x{e:06x} ({e-s} bytes):")
        for off in range(s, min(e, s + 64)):
            if off < len(param_orig) and off < len(param_patch):
                print(f"    0x{off:06x}: {param_orig[off]:02x} -> {param_patch[off]:02x}")

print("\n[done]")
