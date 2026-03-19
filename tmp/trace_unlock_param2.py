#!/usr/bin/env python3
"""
Broader search for code references to unlock-related strings.
Also searches for ADRP+LDR patterns and indirect references.
"""

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
        return data[addr:end].decode('ascii')
    except:
        return None

CODE_END = 0x6A000  # actual code ends here based on disasm

# Targets of interest
targets = {
    0x060b93: "OemCheckResetDevInfo] reset_devinfo",
    0x060ba0: "DevInfo] reset_devinfo",
    0x060bd5: "OemCheckResetDevInfo] set_param failed",
    0x060be2: "DevInfo] set_param failed",
    0x0603b2: "set_param_by_index_and_offset",
    0x05ff8d: "set_param_by_index_and_offset_plaintext",
    0x0602bd: "set_param_by_index_and_offset_encrypt",
    0x06044b: "get_param_by_index_and_offset",
    0x05361c: "unlocked",
    0x066ba3: "unlock_ability",
    0x067aa5: "unlock_ability: %d",
    0x0667d2: "unlocked!",
    0x062154: "unlocked.",
    0x061387: "initEncryptedBlockMD5",
}

print("=== ADRP+ADD scan (full code range) ===")
for pc in range(0, CODE_END, 4):
    if pc + 8 > len(data):
        break
    insn1 = struct.unpack_from('<I', data, pc)[0]
    insn2 = struct.unpack_from('<I', data, pc + 4)[0]

    # Must be ADRP
    if (insn1 & 0x9F000000) != 0x90000000:
        continue

    # Decode ADRP
    immlo = (insn1 >> 29) & 0x3
    immhi = (insn1 >> 5) & 0x7FFFF
    imm = ((immhi << 2) | immlo) << 12
    if imm & (1 << 32):
        imm -= (1 << 33)

    adrp_result = (pc & ~0xFFF) + imm
    rd = insn1 & 0x1F

    # Check ADD Xd, Xn, #imm12
    if (insn2 & 0xFFC00000) == 0x91000000:
        add_imm = (insn2 >> 10) & 0xFFF
        add_rn = (insn2 >> 5) & 0x1F
        add_rd = insn2 & 0x1F

        if add_rn == rd:
            target = adrp_result + add_imm
            if target in targets:
                print(f"  0x{pc:05x}: ADRP+ADD x{add_rd} -> 0x{target:06x} \"{targets[target]}\"")

    # Also check ADRP + LDR patterns (load from page+offset)
    # LDR Xt, [Xn, #imm12*8]: 0xF9400000 mask 0xFFC00000
    if (insn2 & 0xFFC00000) == 0xF9400000:
        ldr_imm = ((insn2 >> 10) & 0xFFF) * 8
        ldr_rn = (insn2 >> 5) & 0x1F
        ldr_rd = insn2 & 0x1F
        if ldr_rn == rd:
            mem_addr = adrp_result + ldr_imm
            if mem_addr in targets:
                print(f"  0x{pc:05x}: ADRP+LDR x{ldr_rd} <- [0x{mem_addr:06x}] \"{targets[target]}\"")
            # Also check if the memory at mem_addr contains a pointer to a target
            if 0 <= mem_addr < len(data) - 8:
                ptr = struct.unpack_from('<Q', data, mem_addr)[0]
                if ptr in targets:
                    print(f"  0x{pc:05x}: ADRP+LDR x{ldr_rd} <- [0x{mem_addr:06x}] -> ptr 0x{ptr:06x} \"{targets[ptr]}\"")

    # LDR Wt, [Xn, #imm12*4]: 0xB9400000 mask 0xFFC00000
    if (insn2 & 0xFFC00000) == 0xB9400000:
        ldr_imm = ((insn2 >> 10) & 0xFFF) * 4
        ldr_rn = (insn2 >> 5) & 0x1F
        ldr_rd = insn2 & 0x1F
        if ldr_rn == rd:
            mem_addr = adrp_result + ldr_imm
            if mem_addr in targets:
                print(f"  0x{pc:05x}: ADRP+LDR w{ldr_rd} <- [0x{mem_addr:06x}]")

# Also look for ADR (not ADRP) patterns
print("\n=== ADR scan ===")
for pc in range(0, CODE_END, 4):
    insn = struct.unpack_from('<I', data, pc)[0]
    # ADR: 0 immlo 10000 immhi Rd
    if (insn & 0x9F000000) != 0x10000000:
        continue
    immlo = (insn >> 29) & 0x3
    immhi = (insn >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    target = pc + imm
    if target in targets:
        rd = insn & 0x1F
        print(f"  0x{pc:05x}: ADR x{rd}, 0x{target:06x} \"{targets[target]}\"")

# Search for the page 0x60000 ADRP instructions near known DevInfo code
print("\n=== All ADRP targeting page 0x60000 in range 0x38000-0x3c000 ===")
for pc in range(0x38000, 0x3c000, 4):
    if pc + 4 > len(data):
        break
    insn = struct.unpack_from('<I', data, pc)[0]
    if (insn & 0x9F000000) != 0x90000000:
        continue
    immlo = (insn >> 29) & 0x3
    immhi = (insn >> 5) & 0x7FFFF
    imm = ((immhi << 2) | immlo) << 12
    if imm & (1 << 32):
        imm -= (1 << 33)
    adrp_result = (pc & ~0xFFF) + imm
    rd = insn & 0x1F
    if 0x60000 <= adrp_result <= 0x61000:
        # decode the following ADD if any
        if pc + 4 < len(data):
            insn2 = struct.unpack_from('<I', data, pc + 4)[0]
            if (insn2 & 0xFFC00000) == 0x91000000:
                add_imm = (insn2 >> 10) & 0xFFF
                add_rn = (insn2 >> 5) & 0x1F
                final = adrp_result + add_imm
                s = get_string_at(final)
                if s:
                    print(f"  0x{pc:05x}: x{rd} -> 0x{final:06x} \"{s[:80]}\"")
                else:
                    print(f"  0x{pc:05x}: x{rd} -> page 0x{adrp_result:05x} + ADD -> 0x{final:06x}")
            else:
                print(f"  0x{pc:05x}: x{rd} -> page 0x{adrp_result:05x} (no ADD)")

# Also look for known devinfo code area 0x384d0 (WriteDeviceInfo init defaults)
print("\n=== Code around WriteDeviceInfo/InitDefaults (0x384d0-0x38700) ===")
for pc in range(0x384d0, 0x38700, 4):
    if pc + 8 > len(data):
        break
    insn1 = struct.unpack_from('<I', data, pc)[0]
    insn2 = struct.unpack_from('<I', data, pc + 4)[0]

    # Check ADRP+ADD targeting any string
    if (insn1 & 0x9F000000) != 0x90000000:
        continue

    immlo = (insn1 >> 29) & 0x3
    immhi = (insn1 >> 5) & 0x7FFFF
    imm = ((immhi << 2) | immlo) << 12
    if imm & (1 << 32):
        imm -= (1 << 33)

    adrp_result = (pc & ~0xFFF) + imm
    rd = insn1 & 0x1F

    if (insn2 & 0xFFC00000) == 0x91000000:
        add_imm = (insn2 >> 10) & 0xFFF
        add_rn = (insn2 >> 5) & 0x1F
        if add_rn == rd:
            final = adrp_result + add_imm
            s = get_string_at(final)
            if s and len(s) > 3:
                print(f"  0x{pc:05x}: x{insn2 & 0x1F} -> 0x{final:06x} \"{s[:80]}\"")

print("\n[done]")
