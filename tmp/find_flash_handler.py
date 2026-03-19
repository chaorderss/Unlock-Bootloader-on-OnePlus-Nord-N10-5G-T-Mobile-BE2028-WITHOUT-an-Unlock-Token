#!/usr/bin/env python3
"""Find ADRP+ADD references to the unlock token strings to locate CmdCustUnlockFlash"""
import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin','rb').read()

# Target strings:
# 0x062e3b: "Please flash unlock token first."
# 0x061f98: "Unable to finding related information (-1)"
targets = {0x062e3b, 0x061f98}
target_pages = {addr & ~0xFFF for addr in targets}

print("Looking for references to:")
print(f"  0x062e3b: 'Please flash unlock token first.'  (page 0x62000, off 0xe3b)")
print(f"  0x061f98: 'Unable to finding related info'  (page 0x61000, off 0xf98)")
print()

# Scan entire .text section for ADRP+ADD pairs that ref these addresses
text_start = 0x1000
text_end = 0x89000   # approximate .text end

adrp_map = {}  # pc -> (rd, page)

for off in range(text_start, text_end, 4):
    if off + 4 > len(data):
        break
    insn = struct.unpack_from('<I', data, off)[0]

    # ADRP
    if (insn & 0x9F000000) == 0x90000000:
        rd = insn & 0x1F
        immlo = (insn >> 29) & 0x3
        immhi = (insn >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= (1 << 21)
        page = (off & ~0xFFF) + (imm << 12)
        if page in target_pages:
            adrp_map[off] = (rd, page)

    # ADD
    if (insn & 0xFF800000) == 0x91000000:
        rd = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = (insn >> 10) & 0xFFF
        sh = (insn >> 22) & 1
        if sh:
            imm12 <<= 12

        # Check all recent ADRP entries for matching register within +-16 instructions
        for adrp_off, (adrp_rd, adrp_page) in adrp_map.items():
            if adrp_rd == rn and 0 < (off - adrp_off) <= 64:
                final_addr = adrp_page + imm12
                if final_addr in targets:
                    end = data.index(0, final_addr) if 0 in data[final_addr:final_addr+200] else final_addr+80
                    s = data[final_addr:end].decode('ascii', errors='replace')[:60]
                    print(f"  FOUND ref at {off:#07x} (ADRP at {adrp_off:#07x}): x{rd} = {final_addr:#x}")
                    print(f"    -> \"{s}\"")

                    # Show surrounding function context
                    # Look backward for function prologue (stp x29,x30 or str x28,[sp...])
                    for back in range(off, max(off-0x400, text_start), -4):
                        b_insn = struct.unpack_from('<I', data, back)[0]
                        # STP x29, x30, [sp, #imm] = 0xA9xx7BFD pattern
                        if (b_insn & 0xFFE003FF) == 0xA9007BFD:
                            print(f"    Likely function start near {back:#07x}")
                            break
                        # STR x28, [sp, #-N]! pattern
                        if (b_insn & 0xFFE00FFF) == 0xF81A0FFC or (b_insn & 0xFFE00FFF) == 0xF8000FFC:
                            print(f"    Likely function start near {back:#07x}")
                            break
                    print()
