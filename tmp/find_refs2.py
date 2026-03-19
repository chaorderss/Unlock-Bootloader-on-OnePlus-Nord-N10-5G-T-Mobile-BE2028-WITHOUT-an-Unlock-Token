#!/usr/bin/env python3
"""Find code references to key strings using multiple strategies."""
import struct

with open('/tmp/abl_dec.bin', 'rb') as f:
    data = f.read()

MZ = 0xB8
TEXT_START = 0x10B8
TEXT_END = 0x6A0B8

def file_to_rva(foff):
    return foff - MZ

# Target string RVAs
targets = {
    'sw_proj_id_proc: %u': 0x0613E4,
    'init_param_sw_prj_id': 0x06139D,
    'GetParamSoftwareProjectIDProcState': 0x06074F,
    'rpmb_enable=%a': 0x05F9D5,
}

# Strategy 1: Look for 8-byte literal pointers to string RVAs
print("=== Strategy 1: 8-byte pointer literals ===")
for name, rva in targets.items():
    pattern = struct.pack('<Q', rva)
    idx = 0
    while True:
        pos = data.find(pattern, idx)
        if pos == -1:
            break
        print(f"  Found 8-byte ptr to '{name}' at file 0x{pos:06X} (RVA 0x{file_to_rva(pos):06X})")
        idx = pos + 1

# Strategy 2: Look for 4-byte literal pointers
print("\n=== Strategy 2: 4-byte pointer literals ===")
for name, rva in targets.items():
    pattern = struct.pack('<I', rva)
    idx = 0
    found = 0
    while found < 5:
        pos = data.find(pattern, idx)
        if pos == -1:
            break
        ref_rva = file_to_rva(pos)
        print(f"  Found 4-byte at file 0x{pos:06X} (RVA 0x{ref_rva:06X}) -> '{name}'")
        found += 1
        idx = pos + 1

# Strategy 3: ADR instruction
print("\n=== Strategy 3: ADR references ===")
for name, rva in targets.items():
    for off in range(TEXT_START, TEXT_END - 4, 4):
        insn = struct.unpack_from('<I', data, off)[0]
        if (insn >> 24) & 0x9F != 0x10:
            continue
        pc_rva = file_to_rva(off)
        immlo = (insn >> 29) & 3
        immhi = (insn >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm -= 0x200000
        target = pc_rva + imm
        if target == rva:
            rd = insn & 0x1F
            print(f"  ADR X{rd} at RVA 0x{pc_rva:06X} -> '{name}'")

# Strategy 4: All ADRP targeting pages near our strings
print("\n=== Strategy 4: ADRP targeting pages 0x5F000-0x62000 ===")
for off in range(TEXT_START, TEXT_END - 4, 4):
    insn = struct.unpack_from('<I', data, off)[0]
    if (insn >> 24) & 0x9F != 0x90:
        continue
    pc_rva = file_to_rva(off)
    pc_page = pc_rva & ~0xFFF
    immlo = (insn >> 29) & 3
    immhi = (insn >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & 0x100000:
        imm -= 0x200000
    adrp_target = pc_page + (imm << 12)
    if 0x5F000 <= adrp_target <= 0x62000:
        rd = insn & 0x1F
        print(f"  ADRP X{rd}, 0x{adrp_target:X} at RVA 0x{pc_rva:06X}")

# Strategy 5: First 10 ADRP for decode verification
print("\n=== Strategy 5: First 10 ADRP (decode check) ===")
count = 0
for off in range(TEXT_START, TEXT_END - 4, 4):
    insn = struct.unpack_from('<I', data, off)[0]
    if (insn >> 24) & 0x9F != 0x90:
        continue
    pc_rva = file_to_rva(off)
    pc_page = pc_rva & ~0xFFF
    immlo = (insn >> 29) & 3
    immhi = (insn >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & 0x100000:
        imm -= 0x200000
    adrp_target = pc_page + (imm << 12)
    rd = insn & 0x1F
    print(f"  0x{pc_rva:06X}: ADRP X{rd}, 0x{adrp_target:X}   (insn=0x{insn:08X})")
    count += 1
    if count >= 10:
        break
