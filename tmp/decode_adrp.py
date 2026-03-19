#!/usr/bin/env python3
"""Precisely decode all ADRP+ADD pairs in CmdCustUnlockFlash to get real string refs"""
import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin','rb').read()

def decode_adrp(insn, pc):
    """ADRP Xd, label -> page address"""
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
    """ADD Xd, Xn, #imm"""
    if (insn & 0xFF800000) == 0x91000000:  # 64-bit ADD, shift=0
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
        return f"<OUT OF RANGE {off:#x}>"
    end = off
    while end < len(data) and end < off + maxlen and data[end] != 0:
        end += 1
    try:
        return data[off:end].decode('ascii')
    except:
        return data[off:min(off+40, end)].hex()

# The PE32+ in this binary has imagebase = 0 and sections at VA == file offset
# (confirmed from conversation summary). So ADRP addresses = file offsets.
# But wait - the disassembly was of linuxloader_text.bin which starts at pe32+[0x1000]
# And "disasm addr = text_bin offset" with objdump --start-address=0x1000
# So disasm addresses ARE pe32+ file offsets.

# Let me scan the whole function from 0x35ca8 to 0x36120 for ADRP+ADD pairs
print("=== All ADRP+ADD string references in CmdCustUnlockFlash (0x35ca8 - 0x36120) ===")
print()

start = 0x35ca8
end_addr = 0x36200

# pe32+ .text section starts at file offset 0x1000
# The disasm uses pe32+ offsets directly
# We read instructions from pe32+ data at those offsets

adrp_regs = {}  # track last ADRP target per register
pc = start
while pc < end_addr:
    off = pc  # pe32+ file offset = disasm address
    if off + 4 > len(data):
        break
    insn = struct.unpack_from('<I', data, off)[0]

    # Check ADRP
    a = decode_adrp(insn, pc)
    if a:
        rd, page = a
        adrp_regs[rd] = (pc, page)

    # Check ADD
    add = decode_add_imm(insn)
    if add:
        rd, rn, imm12 = add
        if rn in adrp_regs:
            adrp_pc, page = adrp_regs[rn]
            final_addr = page + imm12
            s = get_str(final_addr)
            if s and len(s) > 0 and all(32 <= ord(c) < 127 for c in s[:20]):
                print(f"  {pc:#07x}: x{rd} = {final_addr:#x}  \"{s[:80]}\"")
            elif final_addr < len(data):
                print(f"  {pc:#07x}: x{rd} = {final_addr:#x}  [binary: {data[final_addr:final_addr+16].hex()}]")

    pc += 4

# Also check the key function calls
print()
print("=== Key BL calls ===")
pc = start
while pc < end_addr:
    off = pc
    if off + 4 > len(data):
        break
    insn = struct.unpack_from('<I', data, off)[0]
    if (insn & 0xFC000000) == 0x94000000:  # BL
        imm26 = insn & 0x3FFFFFF
        if imm26 & (1 << 25):
            imm26 -= (1 << 26)
        target = pc + (imm26 << 2)
        print(f"  {pc:#07x}: bl {target:#x}")
    elif (insn & 0xFFE0001F) == 0xD63F0100:  # BLR x8
        print(f"  {pc:#07x}: blr x8")
    pc += 4
