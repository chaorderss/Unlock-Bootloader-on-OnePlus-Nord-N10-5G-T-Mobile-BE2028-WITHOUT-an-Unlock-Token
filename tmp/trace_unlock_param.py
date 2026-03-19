#!/usr/bin/env python3
"""
Trace the unlock flag location in the param system.
1. Decode function at 0x33a18 (called on CmdTokenFlash success)
2. Find OemCheckResetDevInfo function and its param operations
3. Map which SID index and offset stores the unlock flag
"""

import struct

PE32 = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
DISASM = "/tmp/linuxloader_disasm.txt"

with open(PE32, 'rb') as f:
    data = f.read()

def get_string_at(addr):
    end = data.find(b'\x00', addr)
    if end < 0 or end - addr > 200:
        return None
    try:
        return data[addr:end].decode('ascii')
    except:
        return None

def decode_adrp_add(pc, insn1, insn2):
    """Decode ADRP+ADD pair, return target address or None."""
    if (insn1 & 0x9F000000) != 0x90000000:
        return None
    if (insn2 & 0xFFC00000) != 0x91000000:
        return None

    immlo = (insn1 >> 29) & 0x3
    immhi = (insn1 >> 5) & 0x7FFFF
    imm = ((immhi << 2) | immlo) << 12
    if imm & (1 << 32):
        imm -= (1 << 33)

    adrp_result = (pc & ~0xFFF) + imm
    rd = insn1 & 0x1F

    add_rn = (insn2 >> 5) & 0x1F
    if add_rn != rd:
        return None

    add_imm = (insn2 >> 10) & 0xFFF
    add_rd = insn2 & 0x1F

    return adrp_result + add_imm, add_rd

def analyze_function(start, name, max_insn=300):
    """Analyze a function from start address, printing key operations."""
    print(f"\n{'='*70}")
    print(f"Function: {name} @ 0x{start:05x}")
    print(f"{'='*70}")

    for i in range(max_insn):
        pc = start + i * 4
        if pc + 4 > len(data):
            break
        insn = struct.unpack_from('<I', data, pc)[0]

        # Decode BL (branch with link)
        if (insn & 0xFC000000) == 0x94000000:
            offset = insn & 0x3FFFFFF
            if offset & (1 << 25):
                offset -= (1 << 26)
            target = pc + offset * 4
            print(f"  0x{pc:05x}: bl 0x{target:05x}")

        # Decode MOV immediate
        elif (insn & 0xFF800000) == 0x52800000:  # MOVZ w
            rd = insn & 0x1F
            imm16 = (insn >> 5) & 0xFFFF
            hw = (insn >> 21) & 0x3
            val = imm16 << (hw * 16)
            print(f"  0x{pc:05x}: mov w{rd}, #{val} (0x{val:x})")

        # Decode ADRP+ADD
        if i + 1 < max_insn and pc + 8 <= len(data):
            insn2 = struct.unpack_from('<I', data, pc + 4)[0]
            result = decode_adrp_add(pc, insn, insn2)
            if result:
                addr, rd = result
                s = get_string_at(addr)
                if s:
                    print(f"  0x{pc:05x}: x{rd} -> 0x{addr:06x} \"{s}\"")
                else:
                    print(f"  0x{pc:05x}: x{rd} -> 0x{addr:06x} (data)")

        # Detect RET
        if insn == 0xD65F03C0:
            print(f"  0x{pc:05x}: ret")
            break

        # Detect STP with negative offset (function prologue)
        # and LDP with post-index (function epilogue)
        # STR/LDR with specific patterns for parameter access
        if (insn & 0xFFE00000) == 0xB9000000:  # STR Wt, [Xn, #imm]
            rt = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            imm12 = ((insn >> 10) & 0xFFF) * 4
            print(f"  0x{pc:05x}: str w{rt}, [x{rn}, #{imm12}]")

        if (insn & 0xFFE00000) == 0xB9400000:  # LDR Wt, [Xn, #imm]
            rt = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            imm12 = ((insn >> 10) & 0xFFF) * 4
            print(f"  0x{pc:05x}: ldr w{rt}, [x{rn}, #{imm12}]")

# 1. Analyze function at 0x33a18 — called on CmdTokenFlash unlock success
analyze_function(0x33a18, "unlock_state_write (0x33a18)")

# 2. Find and analyze OemCheckResetDevInfo
# String "OemCheckResetDevInfo] reset_devinfo" is at 0x060b93
# "DevInfo] set_param_by_index_and_offset failed" at 0x060be2
# Need to find code that references 0x060b93
print("\n\n" + "="*70)
print("Searching for OemCheckResetDevInfo function...")
print("="*70)

# Search for ADRP that targets page 0x60000
for pc in range(0, 0x89000, 4):
    insn1 = struct.unpack_from('<I', data, pc)[0]
    if pc + 4 >= len(data):
        break
    insn2 = struct.unpack_from('<I', data, pc + 4)[0]

    result = decode_adrp_add(pc, insn1, insn2)
    if result:
        addr, rd = result
        # Check for OemCheckResetDevInfo related strings
        if addr in [0x060b93, 0x060ba0, 0x060bd5, 0x060be2]:
            s = get_string_at(addr)
            print(f"  0x{pc:05x}: x{rd} -> 0x{addr:06x} \"{s[:60]}\"")

# 3. Find references to set_param_by_index_and_offset string
print("\n\nSearching for set_param_by_index_and_offset code refs...")
for pc in range(0, 0x89000, 4):
    insn1 = struct.unpack_from('<I', data, pc)[0]
    if pc + 4 >= len(data):
        break
    insn2 = struct.unpack_from('<I', data, pc + 4)[0]

    result = decode_adrp_add(pc, insn1, insn2)
    if result:
        addr, rd = result
        if addr in [0x0603b2, 0x05ff8d, 0x0602bd]:
            s = get_string_at(addr)
            print(f"  0x{pc:05x}: x{rd} -> 0x{addr:06x} \"{s[:60]}\"")

# 4. Find references to "unlocked" string (0x05361c)
print("\n\nSearching for 'unlocked' string refs...")
for pc in range(0, 0x89000, 4):
    insn1 = struct.unpack_from('<I', data, pc)[0]
    if pc + 4 >= len(data):
        break
    insn2 = struct.unpack_from('<I', data, pc + 4)[0]

    result = decode_adrp_add(pc, insn1, insn2)
    if result:
        addr, rd = result
        if addr in [0x05361c, 0x066ba3, 0x067aa5, 0x062154, 0x0667d2]:
            s = get_string_at(addr)
            print(f"  0x{pc:05x}: x{rd} -> 0x{addr:06x} \"{s[:60]}\"")

print("\n[done]")
