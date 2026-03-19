#!/usr/bin/env python3
"""Find CmdCustUnlockFlash and analyze its full verification logic"""
import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin','rb').read()

def decode_adrp(insn, pc):
    if (insn & 0x9F000000) != 0x90000000:
        return None
    rd = insn & 0x1F
    immlo = (insn >> 29) & 0x3
    immhi = (insn >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    return rd, (pc & ~0xFFF) + (imm << 12)

def decode_add_imm(insn):
    if (insn & 0xFF800000) == 0x91000000:
        rd = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = (insn >> 10) & 0xFFF
        sh = (insn >> 22) & 1
        if sh:
            imm12 <<= 12
        return rd, rn, imm12
    return None

def get_str(off, maxlen=120):
    if off < 0 or off >= len(data):
        return f"<OOB {off:#x}>"
    end = off
    while end < len(data) and end < off + maxlen and data[end] != 0:
        end += 1
    try:
        return data[off:end].decode('ascii')
    except:
        return data[off:min(off+40,end)].hex()

# We KNOW 0x3bbd8 references "Please flash unlock token first."
# Let me find the function containing it by looking backward for prologue
print("=== Finding function prologue before 0x3bbd8 ===")
for back in range(0x3bbd0, 0x3b000, -4):
    insn = struct.unpack_from('<I', data, back)[0]
    # Common prologues: STP x29,x30,[sp,#-N]! or SUB sp,sp,#N or STR x28,[sp,#-N]!
    # STP with pre-index: 1010100110...
    # STR x28,[sp,#-N]!: F81xxxFC
    if (insn & 0xFFE00FFF) == 0xF8000FFC:  # STR x28, [sp, #-N]!
        print(f"  Possible func start: {back:#07x} (str x28, [sp, ...])")
    if (insn & 0xFFC003FF) == 0xA98003FD:  # STP x29, x30, [sp, #-N]!
        print(f"  Possible func start: {back:#07x} (stp x29, x30, [sp, ...])")
    # Also check for ret preceding
    if insn == 0xD65F03C0:  # RET
        print(f"  RET at {back:#07x} -> function likely starts at {back+4:#07x}")
        break

# Now scan a WIDER range around 0x3bbd8 for the full function
# First find the exact function boundaries
# Look for the ret after 0x3bbd8
print("\n=== Scanning CmdCustUnlockFlash region (0x3b500 - 0x3c200) ===")
print("All ADRP+ADD refs and BL calls:\n")

adrp_regs = {}
for pc in range(0x3b500, 0x3c200, 4):
    if pc + 4 > len(data):
        break
    insn = struct.unpack_from('<I', data, pc)[0]

    # RET
    if insn == 0xD65F03C0:
        print(f"  {pc:#07x}: RET")

    # ADRP
    a = decode_adrp(insn, pc)
    if a:
        adrp_regs[a[0]] = (pc, a[1])

    # ADD
    add = decode_add_imm(insn)
    if add:
        rd, rn, imm12 = add
        if rn in adrp_regs:
            adrp_pc, page = adrp_regs[rn]
            if 0 < (pc - adrp_pc) <= 64:
                final = page + imm12
                s = get_str(final)
                if len(s) > 0:
                    print(f"  {pc:#07x}: x{rd} = {final:#x}  \"{s[:80]}\"")

    # BL
    if (insn & 0xFC000000) == 0x94000000:
        imm26 = insn & 0x3FFFFFF
        if imm26 & (1 << 25):
            imm26 -= (1 << 26)
        target = pc + (imm26 << 2)
        print(f"  {pc:#07x}: bl {target:#x}")

    # BLR
    if (insn & 0xFFFFFC1F) == 0xD63F0100:
        reg = (insn >> 5) & 0x1F
        print(f"  {pc:#07x}: blr x{reg}")

    # CBZ/CBNZ
    if (insn & 0x7E000000) == 0x34000000:
        op = (insn >> 24) & 1
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1 << 18):
            imm19 -= (1 << 19)
        rt = insn & 0x1F
        target = pc + (imm19 << 2)
        name = 'cbnz' if op else 'cbz'
        print(f"  {pc:#07x}: {name} x{rt}, {target:#x}")

    # B.cond
    if (insn & 0xFF000010) == 0x54000000:
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1 << 18):
            imm19 -= (1 << 19)
        cond = insn & 0xF
        conds = ['eq','ne','cs','cc','mi','pl','vs','vc','hi','ls','ge','lt','gt','le','al','nv']
        target = pc + (imm19 << 2)
        print(f"  {pc:#07x}: b.{conds[cond]} {target:#x}")
