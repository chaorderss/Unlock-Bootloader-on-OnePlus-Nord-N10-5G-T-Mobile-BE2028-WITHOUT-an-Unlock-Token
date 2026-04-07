#!/usr/bin/env python3
"""Find the exact ADRP+ADD references to the REJECTED string and trace the function"""
import struct

with open('qtmir_app.so', 'rb') as f:
    data = f.read()

# String offsets = vaddr (since first LOAD vaddr=0x0, offset=0x0)
REJECTED_VADDR = 0x99203
NOT_LAUNCHED_VADDR = 0x99302
DESKTOP_HINT_VADDR = 0x992ca

strings_to_find = {
    "REJECTED": REJECTED_VADDR,
    "not launched": NOT_LAUNCHED_VADDR,
    "desktop_file_hint": DESKTOP_HINT_VADDR,
}

def find_adrp_add_refs(data, target_vaddr):
    """Find ADRP+ADD instruction pairs that reference a specific vaddr"""
    target_page = target_vaddr & ~0xFFF
    target_lo = target_vaddr & 0xFFF
    refs = []
    for off in range(0, min(len(data), 0xB0000), 4):
        insn = struct.unpack_from('<I', data, off)[0]
        if (insn & 0x9F000000) == 0x90000000:  # ADRP
            rd = insn & 0x1F
            immhi = (insn >> 5) & 0x7FFFF
            immlo = (insn >> 29) & 0x3
            imm = (immhi << 2) | immlo
            if imm & (1 << 20): imm -= (1 << 21)
            page = ((off >> 12) + imm) << 12
            if page == target_page and off + 4 < len(data):
                next_insn = struct.unpack_from('<I', data, off + 4)[0]
                # ADD Xd, Xn, #imm12
                if (next_insn & 0xFFC00000) == 0x91000000:
                    add_rn = (next_insn >> 5) & 0x1F
                    add_imm = (next_insn >> 10) & 0xFFF
                    if add_rn == rd and add_imm == target_lo:
                        add_rd = next_insn & 0x1F
                        refs.append(off)
    return refs

for name, vaddr in strings_to_find.items():
    refs = find_adrp_add_refs(data, vaddr)
    print(f"References to '{name}' (0x{vaddr:x}):")
    for ref in refs:
        print(f"  0x{ref:x}")
    print()

# Now let's look at the area around the REJECTED reference
# and trace back to the function entry point
for name, vaddr in [("REJECTED", REJECTED_VADDR)]:
    refs = find_adrp_add_refs(data, vaddr)
    for ref in refs:
        print(f"\n=== Context around {name} ref at 0x{ref:x} ===")
        # Print 30 instructions before and 10 after
        for i in range(-40, 15):
            addr = ref + i * 4
            if 0 <= addr < len(data) - 4:
                insn = struct.unpack_from('<I', data, addr)[0]
                marker = " <<<< REF" if addr == ref else ""
                # Basic decode
                desc = ""
                if insn == 0xd503201f: desc = "NOP"
                elif (insn & 0x9F000000) == 0x90000000:
                    rd = insn & 0x1F
                    immhi = (insn >> 5) & 0x7FFFF; immlo = (insn >> 29) & 0x3
                    imm = (immhi << 2) | immlo
                    if imm & (1<<20): imm -= (1<<21)
                    page = ((addr >> 12) + imm) << 12
                    desc = f"ADRP X{rd}, 0x{page:x}"
                elif (insn >> 26) == 0b100101:
                    imm26 = insn & 0x3FFFFFF
                    if imm26 & (1<<25): imm26 -= (1<<26)
                    desc = f"BL 0x{addr + imm26*4:x}"
                elif (insn & 0xFC000000) == 0x14000000:
                    imm26 = insn & 0x3FFFFFF
                    if imm26 & (1<<25): imm26 -= (1<<26)
                    desc = f"B 0x{addr + imm26*4:x}"
                elif insn == 0xd65f03c0: desc = "RET"
                elif (insn & 0xFFC003E0) == 0xA98003E0:
                    desc = "STP (prologue)"
                elif (insn & 0x52800000) == 0x52800000 and (insn & 0xFF800000) == 0x52800000:
                    rd = insn & 0x1F; imm = (insn >> 5) & 0xFFFF
                    desc = f"MOVZ W{rd}, #{imm}"
                elif (insn & 0xFFC00000) == 0x91000000:
                    rd = insn & 0x1F; rn = (insn >> 5) & 0x1F; imm = (insn >> 10) & 0xFFF
                    desc = f"ADD X{rd}, X{rn}, #0x{imm:x}"
                elif (insn & 0x7E000000) == 0x34000000:
                    op = (insn >> 24) & 1; rt = insn & 0x1F
                    off19 = (insn >> 5) & 0x7FFFF
                    if off19 & (1<<18): off19 -= (1<<19)
                    tgt = addr + off19 * 4
                    desc = f"{'CBNZ' if op else 'CBZ'} W{rt}, 0x{tgt:x}"
                elif (insn & 0x7F000000) == 0x36000000:
                    op = (insn >> 24) & 1; rt = insn & 0x1F
                    bit = ((insn >> 31) << 5) | ((insn >> 19) & 0x1F)
                    off14 = (insn >> 5) & 0x3FFF
                    if off14 & (1<<13): off14 -= (1<<14)
                    tgt = addr + off14 * 4
                    desc = f"{'TBNZ' if op else 'TBZ'} W{rt}, #{bit}, 0x{tgt:x}"

                print(f"  0x{addr:05x}: {insn:08x}  {desc}{marker}")
