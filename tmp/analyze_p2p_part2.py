#!/usr/bin/env python3
"""Disassemble second half of p2p_process_mgmt_tx."""
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

    conds = ['eq','ne','cs','cc','mi','pl','vs','vc','hi','ls','ge','lt','gt','le','al','nv']

    for j in range(0x400, min(len(data), 0x810), 4):
        insn = struct.unpack_from('<I', data, j)[0]
        decoded = ""

        # CMP Wn, #imm
        if (insn & 0x7f800000) == 0x71000000:
            Rd = insn & 0x1f
            Rn = (insn >> 5) & 0x1f
            imm12 = (insn >> 10) & 0xfff
            if Rd == 31:
                decoded = "CMP W%d, #%d" % (Rn, imm12)
        # MOVZ Wn, #imm
        elif (insn & 0x7f800000) == 0x52800000:
            Rd = insn & 0x1f
            imm16 = (insn >> 5) & 0xffff
            hw = (insn >> 21) & 3
            if hw == 0:
                decoded = "MOVZ W%d, #%d" % (Rd, imm16)
        # B.cond
        elif (insn & 0xff000010) == 0x54000000:
            cond = insn & 0xf
            imm19 = (insn >> 5) & 0x7ffff
            if imm19 & 0x40000: imm19 -= 0x80000
            target = j + imm19 * 4
            decoded = "B.%s +0x%x" % (conds[cond], target)
        # CBZ/CBNZ
        elif (insn & 0x7e000000) == 0x34000000:
            is_nz = (insn >> 24) & 1
            Rt = insn & 0x1f
            imm19 = (insn >> 5) & 0x7ffff
            if imm19 & 0x40000: imm19 -= 0x80000
            target = j + imm19 * 4
            decoded = "%s W%d, +0x%x" % ('CBNZ' if is_nz else 'CBZ', Rt, target)
        # B/BL
        elif (insn & 0x7c000000) == 0x14000000:
            is_link = (insn >> 31) & 1
            imm26 = insn & 0x3ffffff
            if imm26 & 0x2000000: imm26 -= 0x4000000
            target = j + imm26 * 4
            decoded = "%s +0x%x" % ('BL' if is_link else 'B', target & 0xffffffff)
        # RET
        elif insn == 0xd65f03c0:
            decoded = "RET"
        # LDRB
        elif (insn & 0xffc00000) == 0x39400000:
            Rt = insn & 0x1f
            Rn = (insn >> 5) & 0x1f
            imm12 = (insn >> 10) & 0xfff
            decoded = "LDRB W%d, [X%d, #%d]" % (Rt, Rn, imm12)
        # STP/LDP (frame setup/teardown)
        elif insn == 0xd65f03c0:
            decoded = "RET"

        if decoded:
            print('+0x%03x: %08x  %s' % (j, insn, decoded))
