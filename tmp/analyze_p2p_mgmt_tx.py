#!/usr/bin/env python3
"""Disassemble p2p_process_mgmt_tx to find subtype switch/case."""
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
    print(f'.text at file offset 0x{text_off:x}')
    print(f'p2p_process_mgmt_tx at file offset 0x{func_file_off:x}')

    f.seek(func_file_off)
    data = f.read(2064)

    for j in range(0, min(len(data), 0x400), 4):
        insn = struct.unpack_from('<I', data, j)[0]

        decoded = ""

        # CMP Wn, #imm
        if (insn & 0x7f800000) == 0x71000000:
            Rd = insn & 0x1f
            Rn = (insn >> 5) & 0x1f
            imm12 = (insn >> 10) & 0xfff
            shift = (insn >> 22) & 1
            if Rd == 31:
                decoded = f"CMP W{Rn}, #{imm12}"
                if shift: decoded += " LSL#12"

        # SUB with Rd=WZR (CMP form) 64-bit
        elif (insn & 0xff800000) == 0xf1000000:
            Rd = insn & 0x1f
            Rn = (insn >> 5) & 0x1f
            imm12 = (insn >> 10) & 0xfff
            if Rd == 31:
                decoded = f"CMP X{Rn}, #{imm12}"

        # MOVZ Wn, #imm
        elif (insn & 0x7f800000) == 0x52800000:
            Rd = insn & 0x1f
            imm16 = (insn >> 5) & 0xffff
            hw = (insn >> 21) & 3
            if hw == 0 and imm16 < 0x200:
                decoded = f"MOVZ W{Rd}, #{imm16}"

        # B.cond
        elif (insn & 0xff000010) == 0x54000000:
            cond = insn & 0xf
            imm19 = (insn >> 5) & 0x7ffff
            if imm19 & 0x40000: imm19 -= 0x80000
            target = j + imm19 * 4
            conds = ['eq','ne','cs','cc','mi','pl','vs','vc','hi','ls','ge','lt','gt','le','al','nv']
            decoded = f"B.{conds[cond]} +0x{target:x}"

        # CBZ/CBNZ
        elif (insn & 0x7e000000) == 0x34000000:
            is_nz = (insn >> 24) & 1
            sf = (insn >> 31) & 1
            Rt = insn & 0x1f
            imm19 = (insn >> 5) & 0x7ffff
            if imm19 & 0x40000: imm19 -= 0x80000
            target = j + imm19 * 4
            reg = f"X{Rt}" if sf else f"W{Rt}"
            decoded = f"{'CBNZ' if is_nz else 'CBZ'} {reg}, +0x{target:x}"

        # TBZ/TBNZ
        elif (insn & 0x7e000000) == 0x36000000:
            is_nz = (insn >> 24) & 1
            b5 = (insn >> 31) & 1
            b40 = (insn >> 19) & 0x1f
            bit = (b5 << 5) | b40
            Rt = insn & 0x1f
            imm14 = (insn >> 5) & 0x3fff
            if imm14 & 0x2000: imm14 -= 0x4000
            target = j + imm14 * 4
            decoded = f"{'TBNZ' if is_nz else 'TBZ'} W{Rt}, #{bit}, +0x{target:x}"

        # B/BL
        elif (insn & 0x7c000000) == 0x14000000:
            is_link = (insn >> 31) & 1
            imm26 = insn & 0x3ffffff
            if imm26 & 0x2000000: imm26 -= 0x4000000
            target = j + imm26 * 4
            decoded = f"{'BL' if is_link else 'B'} +0x{target:x}"

        # AND/ORR/UBFM etc for extracting subtype field
        elif (insn & 0x7f800000) == 0x53000000:
            Rd = insn & 0x1f
            Rn = (insn >> 5) & 0x1f
            imms = (insn >> 10) & 0x3f
            immr = (insn >> 16) & 0x3f
            decoded = f"UBFM W{Rd}, W{Rn}, #{immr}, #{imms}"

        # LSR (UBFM alias)
        # LDRB/LDRH for reading frame header
        elif (insn & 0xffc00000) == 0x39400000:
            Rt = insn & 0x1f
            Rn = (insn >> 5) & 0x1f
            imm12 = (insn >> 10) & 0xfff
            decoded = f"LDRB W{Rt}, [X{Rn}, #{imm12}]"

        # RET
        elif insn == 0xd65f03c0:
            decoded = "RET"

        if decoded:
            print(f'+0x{j:03x}: {insn:08x}  {decoded}')
