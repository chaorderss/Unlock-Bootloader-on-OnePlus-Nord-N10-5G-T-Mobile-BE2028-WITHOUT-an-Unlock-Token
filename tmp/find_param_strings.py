#!/usr/bin/env python3
"""Find param/unlock related strings in PE32+ and their code references."""

import struct

PE32 = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
with open(PE32, 'rb') as f:
    data = f.read()

# 1. Find all relevant strings
print("=== String locations ===")
terms = [
    b'set_param_by_index_and_offset', b'get_param_by_index_and_offset',
    b'reset_devinfo', b'is_unlocked', b'unlock_ability',
    b'OemCheckResetDevInfo', b'initEncryptedBlockMD5',
    b'write_param_block', b'read_param_block',
    b'param_init', b'is_unlock', b'unlocked',
    b'DevInfo] reset_devinfo', b'DevInfo] set_param',
    b'write_param_encrypt_block', b'read_param_encrypt_block',
]

string_addrs = {}
for t in terms:
    idx = 0
    while True:
        pos = data.find(t, idx)
        if pos < 0:
            break
        end = data.find(b'\x00', pos)
        s = data[pos:end] if end > pos else data[pos:pos+80]
        try:
            txt = s.decode('ascii')
        except:
            txt = s.decode('latin1')
        print(f"  0x{pos:06x}: {txt!r}")
        string_addrs[pos] = txt
        idx = pos + 1

# 2. For each string, find ADRP+ADD code references
# ADRP: (imm[20:2] << 12) + (PC & ~0xFFF) -> register
# ADD:  reg = reg + imm12
print("\n=== Code references (ADRP+ADD) ===")
TEXT_END = 0x89000  # .text section end

for str_addr, str_text in sorted(string_addrs.items()):
    page = str_addr & ~0xFFF
    page_off = str_addr & 0xFFF

    # Search for ADRP instructions that target this page
    for pc in range(0, min(TEXT_END, len(data)), 4):
        insn = struct.unpack_from('<I', data, pc)[0]

        # Check if ADRP (bit pattern: 1xx10000...)
        if (insn & 0x9F000000) != 0x90000000:
            continue

        # Decode ADRP immediate
        immlo = (insn >> 29) & 0x3
        immhi = (insn >> 5) & 0x7FFFF
        imm = ((immhi << 2) | immlo) << 12
        if imm & (1 << 32):
            imm -= (1 << 33)

        adrp_result = (pc & ~0xFFF) + imm
        if adrp_result != page:
            continue

        rd = insn & 0x1F

        # Check next instruction for ADD with matching page offset
        if pc + 4 >= len(data):
            continue
        next_insn = struct.unpack_from('<I', data, pc + 4)[0]

        # ADD Xd, Xn, #imm12 : 1001000100 imm12 Rn Rd
        if (next_insn & 0xFFC00000) != 0x91000000:
            continue

        add_imm = (next_insn >> 10) & 0xFFF
        add_rn = (next_insn >> 5) & 0x1F
        add_rd = next_insn & 0x1F

        if add_rn != rd:
            continue

        target = adrp_result + add_imm
        if target == str_addr:
            print(f"  0x{pc:05x}: x{add_rd} -> 0x{str_addr:06x} {str_text!r}")

print("\n[done]")
