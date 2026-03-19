#!/usr/bin/env python3
"""Full decode of CmdCustUnlockFlash - the real one around 0x36e00-0x37100"""
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
        return None
    end = off
    while end < len(data) and end < off + maxlen and data[end] != 0:
        end += 1
    try:
        return data[off:end].decode('ascii')
    except:
        return data[off:min(off+40,end)].hex()

# The HMAC strings ("9sLeM7jAuFKcXoxr" etc) are ref'd at 0x36f98-0x3706c
# Let me find the function start (scan backward from 0x36f98 for RET)
print("=== Finding function boundaries ===")
for pc in range(0x36f94, 0x36000, -4):
    insn = struct.unpack_from('<I', data, pc)[0]
    if insn == 0xD65F03C0:  # RET
        print(f"RET at {pc:#x} -> function starts around {pc+4:#x}")
        break

# Find function end (first RET after 0x3706c)
for pc in range(0x37070, 0x37800, 4):
    insn = struct.unpack_from('<I', data, pc)[0]
    if insn == 0xD65F03C0:  # RET
        print(f"Function ends with RET at {pc:#x}")
        break

# Now let me do full decode of the region 0x36b00-0x37200
print()
print("=== Full ADRP+ADD + BL + branch decode: 0x36b00 - 0x37200 ===")
adrp_regs = {}
for pc in range(0x36b00, 0x37200, 4):
    if pc + 4 > len(data):
        break
    insn = struct.unpack_from('<I', data, pc)[0]

    a = decode_adrp(insn, pc)
    if a:
        adrp_regs[a[0]] = (pc, a[1])

    add = decode_add_imm(insn)
    if add:
        rd, rn, imm12 = add
        if rn in adrp_regs:
            apc, page = adrp_regs[rn]
            if 0 < (pc - apc) <= 64:
                final = page + imm12
                s = get_str(final)
                if s and len(s) > 0:
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

    # RET
    if insn == 0xD65F03C0:
        print(f"  {pc:#07x}: RET")

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

    # B (unconditional)
    if (insn & 0xFC000000) == 0x14000000:
        imm26 = insn & 0x3FFFFFF
        if imm26 & (1 << 25):
            imm26 -= (1 << 26)
        target = pc + (imm26 << 2)
        print(f"  {pc:#07x}: b {target:#x}")

# Also specifically search for the "Unable to finding" ref in wider range
print()
print("=== Searching for 'Unable to finding' reference (0x61f98) in 0x36000-0x38000 ===")
for pc in range(0x36000, 0x38000, 4):
    insn = struct.unpack_from('<I', data, pc)[0]
    a = decode_adrp(insn, pc)
    if a:
        rd, page = a
        # Check next few ADD insns
        for npc in range(pc+4, min(pc+40, 0x38000), 4):
            ni = struct.unpack_from('<I', data, npc)[0]
            ai = decode_add_imm(ni)
            if ai and ai[1] == rd:
                final = page + ai[2]
                if final == 0x61f98:
                    print(f"  Found! ADRP at {pc:#x}, ADD at {npc:#x}: x{ai[0]} = 0x61f98")
