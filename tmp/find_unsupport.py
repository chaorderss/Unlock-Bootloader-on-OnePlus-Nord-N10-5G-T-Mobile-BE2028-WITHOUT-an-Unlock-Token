#!/usr/bin/env python3
"""Search for line number 2783 in p2p_process_mgmt_tx."""
import struct

with open('/android/vendor/lib/modules/qca_cld3_wlan.ko', 'rb') as f:
    f.seek(0)
    ehdr = f.read(64)
    e_shoff = struct.unpack_from('<Q', ehdr, 40)[0]
    e_shentsize = struct.unpack_from('<H', ehdr, 58)[0]
    e_shnum = struct.unpack_from('<H', ehdr, 60)[0]
    e_shstrndx = struct.unpack_from('<H', ehdr, 62)[0]

    f.seek(e_shoff + e_shstrndx * e_shentsize)
    shstrtab_hdr = f.read(e_shentsize)
    shstrtab_off = struct.unpack_from('<Q', shstrtab_hdr, 24)[0]
    shstrtab_sz = struct.unpack_from('<Q', shstrtab_hdr, 32)[0]
    f.seek(shstrtab_off)
    shstrtab = f.read(shstrtab_sz)

    text_off = None
    for i in range(e_shnum):
        f.seek(e_shoff + i * e_shentsize)
        shdr = f.read(e_shentsize)
        name_off = struct.unpack_from('<I', shdr, 0)[0]
        name = shstrtab[name_off:shstrtab.index(b'\x00', name_off)].decode()
        sh_offset = struct.unpack_from('<Q', shdr, 24)[0]
        if name == '.text':
            text_off = sh_offset
            break

    func_file_off = text_off + 0x2c0758
    f.seek(func_file_off)
    data = f.read(2064)

    # Search for MOVZ with values near 2783
    for target_val in [2783, 2782, 2784, 2785, 2780, 2790]:
        for j in range(0, len(data), 4):
            insn = struct.unpack_from('<I', data, j)[0]
            if (insn & 0x7f800000) == 0x52800000:
                imm16 = (insn >> 5) & 0xffff
                hw = (insn >> 21) & 3
                if hw == 0 and imm16 == target_val:
                    Rd = insn & 0x1f
                    print("+0x%03x: %08x  MOVZ W%d, #%d" % (j, insn, Rd, imm16))

    print("\n--- All MOVZ W4 values (line numbers) in function ---")
    for j in range(0, len(data), 4):
        insn = struct.unpack_from('<I', data, j)[0]
        if (insn & 0x7f800000) == 0x52800000:
            Rd = insn & 0x1f
            imm16 = (insn >> 5) & 0xffff
            hw = (insn >> 21) & 3
            if Rd == 4 and hw == 0 and imm16 > 100:
                print("+0x%03x: W4=#%d" % (j, imm16))

    # Now look at what happens at the B.ne target at +0x4e4
    # From earlier: at +0x1ec: B.ne +0x4e4
    print("\n--- Instructions around +0x4e4 (B.ne target) ---")
    for j in range(0x4e0, min(0x530, len(data)), 4):
        insn = struct.unpack_from('<I', data, j)[0]
        decoded = ""
        if (insn & 0x7f800000) == 0x71000000:
            Rd = insn & 0x1f
            Rn = (insn >> 5) & 0x1f
            imm12 = (insn >> 10) & 0xfff
            if Rd == 31:
                decoded = "CMP W%d, #%d" % (Rn, imm12)
        elif (insn & 0x7f800000) == 0x52800000:
            Rd = insn & 0x1f
            imm16 = (insn >> 5) & 0xffff
            hw = (insn >> 21) & 3
            if hw == 0:
                decoded = "MOVZ W%d, #%d" % (Rd, imm16)
        elif (insn & 0xff000010) == 0x54000000:
            cond = insn & 0xf
            imm19 = (insn >> 5) & 0x7ffff
            if imm19 & 0x40000: imm19 -= 0x80000
            target = j + imm19 * 4
            conds = ['eq','ne','cs','cc','mi','pl','vs','vc','hi','ls','ge','lt','gt','le','al','nv']
            decoded = "B.%s +0x%x" % (conds[cond], target)
        elif (insn & 0x7c000000) == 0x14000000:
            is_link = (insn >> 31) & 1
            imm26 = insn & 0x3ffffff
            if imm26 & 0x2000000: imm26 -= 0x4000000
            target = j + imm26 * 4
            decoded = "%s +0x%x" % ('BL' if is_link else 'B', target & 0xffffffff)
        else:
            decoded = "%08x" % insn
        print("+0x%03x: %08x  %s" % (j, insn, decoded))
