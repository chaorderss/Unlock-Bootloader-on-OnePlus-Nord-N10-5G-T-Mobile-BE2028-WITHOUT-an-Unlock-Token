#!/usr/bin/env python3
"""Dump the FULL authorizeSession function disassembly."""
import struct, re

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

with open('/Users/xmxx/pinganhuijia/tmp/qtmir_orig.so', 'rb') as f:
    data = f.read()

# Parse ELF sections for rodata strings
e_shoff = struct.unpack_from('<Q', data, 40)[0]
e_shentsize = struct.unpack_from('<H', data, 58)[0]
e_shnum = struct.unpack_from('<H', data, 60)[0]
e_shstrndx = struct.unpack_from('<H', data, 62)[0]
shstrtab_hdr_off = e_shoff + e_shstrndx * e_shentsize
shstrtab_off = struct.unpack_from('<Q', data, shstrtab_hdr_off + 24)[0]

sections = {}
for i in range(e_shnum):
    s_off = e_shoff + i * e_shentsize
    nm_idx = struct.unpack_from('<I', data, s_off)[0]
    nm_end = data.find(b'\0', shstrtab_off + nm_idx)
    nm = data[shstrtab_off + nm_idx:nm_end].decode('ascii', errors='replace')
    sections[nm] = {
        'addr': struct.unpack_from('<Q', data, s_off + 16)[0],
        'offset': struct.unpack_from('<Q', data, s_off + 24)[0],
        'size': struct.unpack_from('<Q', data, s_off + 32)[0],
        'entsize': struct.unpack_from('<Q', data, s_off + 56)[0],
    }

# PLT symbol resolution
plt = sections.get('.plt', {})
rela_plt = sections.get('.rela.plt', {})
dynsym_sec = sections.get('.dynsym', {})
dynstr_sec = sections.get('.dynstr', {})

plt_sym = {}
if plt and rela_plt and dynsym_sec and dynstr_sec:
    dynstr_data = data[dynstr_sec['offset']:dynstr_sec['offset']+dynstr_sec['size']]
    got_to_sym = {}
    for i in range(rela_plt['size'] // 24):
        roff = rela_plt['offset'] + i * 24
        r_offset = struct.unpack_from('<Q', data, roff)[0]
        r_info = struct.unpack_from('<Q', data, roff + 8)[0]
        r_sym = r_info >> 32
        sym_off = dynsym_sec['offset'] + r_sym * (dynsym_sec['entsize'] or 24)
        if sym_off + 24 > len(data): continue
        st_name = struct.unpack_from('<I', data, sym_off)[0]
        end = dynstr_data.find(b'\0', st_name)
        if end > st_name:
            got_to_sym[r_offset] = dynstr_data[st_name:end].decode('ascii', errors='replace')
    for off in range(plt['offset'], plt['offset'] + plt['size'], 4):
        insn = read_u32(data, off)
        if (insn & 0x9f000000) == 0x90000000:
            rd = insn & 0x1f
            if rd in (16, 17):
                immhi = (insn >> 5) & 0x7ffff
                immlo = (insn >> 29) & 0x3
                imm = (immhi << 2) | immlo
                if imm & 0x100000: imm -= 0x200000
                page = (off & ~0xfff) + (imm << 12)
                if off + 4 < plt['offset'] + plt['size']:
                    ni = read_u32(data, off + 4)
                    if (ni & 0xffc00000) == 0xf9400000:
                        imm12 = (ni >> 10) & 0xfff
                        rn = (ni >> 5) & 0x1f
                        if rn == rd:
                            got_addr = page + imm12 * 8
                            if got_addr in got_to_sym:
                                plt_sym[off] = got_to_sym[got_addr]

rodata = sections.get('.rodata', {})
def get_string_at(foff):
    if foff < len(data):
        end = data.find(b'\0', foff)
        if end > foff and end - foff < 300:
            try: return data[foff:end].decode('utf-8')
            except: pass
    return None

func_start = 0x4ea00
func_size = 4804
func_end = func_start + func_size

# Full disassembly
for off in range(func_start, min(func_end, len(data)), 4):
    insn = read_u32(data, off)
    asm = ""
    note = ""

    if insn == 0xd65f03c0: asm = "RET"
    elif insn == 0xd503201f: asm = "NOP"
    elif insn == 0xd503233f: asm = "PACIASP"
    elif insn == 0xd50323bf: asm = "AUTIASP"
    elif (insn >> 26) == 0x25:
        imm26 = insn & 0x3ffffff
        if imm26 & 0x2000000: imm26 -= 0x4000000
        t = off + imm26*4
        sym = plt_sym.get(t, "")
        if sym:
            # Demangle common patterns
            short = sym[:80]
            asm = f"BL <{short}>"
        else:
            asm = f"BL 0x{t:x}"
    elif (insn >> 26) == 0x05:
        imm26 = insn & 0x3ffffff
        if imm26 & 0x2000000: imm26 -= 0x4000000
        asm = f"B 0x{off + imm26*4:x}"
    elif (insn & 0xff000010) == 0x54000000:
        cond = insn & 0xf
        imm19 = (insn >> 5) & 0x7ffff
        if imm19 & 0x40000: imm19 -= 0x80000
        c = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV'][cond]
        asm = f"B.{c} 0x{off + imm19*4:x}"
    elif (insn & 0x7e000000) == 0x34000000:
        sf = (insn >> 31) & 1
        op = (insn >> 24) & 1
        imm19 = (insn >> 5) & 0x7ffff
        if imm19 & 0x40000: imm19 -= 0x80000
        rt = insn & 0x1f
        nm = f"{'X' if sf else 'W'}{rt}"
        asm = f"{'CBNZ' if op else 'CBZ'} {nm}, 0x{off + imm19*4:x}"
    elif (insn & 0x7e000000) == 0x36000000:
        op = (insn >> 24) & 1
        b5 = (insn >> 31) & 1
        b40 = (insn >> 19) & 0x1f
        bit = (b5 << 5) | b40
        imm14 = (insn >> 5) & 0x3fff
        if imm14 & 0x2000: imm14 -= 0x4000
        rt = insn & 0x1f
        asm = f"{'TBNZ' if op else 'TBZ'} W{rt}, #{bit}, 0x{off + imm14*4:x}"
    elif (insn & 0x9f000000) == 0x90000000:
        rd = insn & 0x1f
        immhi = (insn >> 5) & 0x7ffff
        immlo = (insn >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm & 0x100000: imm -= 0x200000
        page = (off & ~0xfff) + (imm << 12)
        asm = f"ADRP X{rd}, 0x{page:x}"
        # Check for ADD following to get full address -> string
        for j in range(1, 4):
            if off + j*4 >= func_end: break
            ni = read_u32(data, off + j*4)
            if (ni & 0xff800000) == 0x91000000:
                n_rn = (ni >> 5) & 0x1f
                if n_rn == rd:
                    n_imm12 = (ni >> 10) & 0xfff
                    n_sh = (ni >> 22) & 1
                    if n_sh: n_imm12 <<= 12
                    full = page + n_imm12
                    s = get_string_at(full)
                    if s: note = f'  ; => 0x{full:x} "{s[:80]}"'
                    break
    elif (insn & 0x7f800000) == 0x11000000:
        sf = (insn >> 31) & 1
        sh = (insn >> 22) & 1
        imm12 = (insn >> 10) & 0xfff
        if sh: imm12 <<= 12
        rn = (insn >> 5) & 0x1f; rd = insn & 0x1f
        rp = "X" if sf else "W"
        rn_s = "SP" if rn==31 else f"{rp}{rn}"; rd_s = "SP" if rd==31 else f"{rp}{rd}"
        asm = f"ADD {rd_s}, {rn_s}, #0x{imm12:x}"
    elif (insn & 0x7f800000) == 0x51000000:
        sf = (insn >> 31) & 1
        imm12 = (insn >> 10) & 0xfff; rn = (insn >> 5) & 0x1f; rd = insn & 0x1f
        rp = "X" if sf else "W"
        rn_s = "SP" if rn==31 else f"{rp}{rn}"; rd_s = "SP" if rd==31 else f"{rp}{rd}"
        asm = f"SUB {rd_s}, {rn_s}, #0x{imm12:x}"
    elif (insn & 0x7f800000) == 0x52800000:
        hw = (insn >> 21) & 3; imm16 = (insn >> 5) & 0xffff; rd = insn & 0x1f
        sf = (insn >> 31) & 1; rp = "X" if sf else "W"
        asm = f"MOV {rp}{rd}, #0x{imm16 << (hw*16):x}"
    elif (insn & 0x7fe0ffe0) == 0x2a0003e0:
        sf = (insn >> 31) & 1; rm = (insn >> 16) & 0x1f; rd = insn & 0x1f
        rp = "X" if sf else "W"
        asm = f"MOV {rp}{rd}, {rp}{rm}"
    elif (insn & 0xffe0fc00) == 0xaa0003e0:
        rm = (insn >> 16) & 0x1f; rd = insn & 0x1f
        asm = f"MOV X{rd}, X{rm}"
    elif (insn & 0xffe0ffe0) == 0xaa0003e0:
        rm = (insn >> 16) & 0x1f; rd = insn & 0x1f
        asm = f"MOV X{rd}, X{rm}"
    elif (insn & 0xfffffc1f) == 0xd63f0000:
        rn = (insn >> 5) & 0x1f
        asm = f"BLR X{rn}"
    elif (insn & 0xfffffc1f) == 0xd61f0000:
        rn = (insn >> 5) & 0x1f
        asm = f"BR X{rn}"
    # LDR/STR various sizes
    elif (insn & 0xffc00000) == 0xf9400000:
        imm12 = (insn >> 10) & 0xfff; rn = (insn >> 5) & 0x1f; rt = insn & 0x1f
        rn_s = "SP" if rn==31 else f"X{rn}"
        asm = f"LDR X{rt}, [{rn_s}, #0x{imm12*8:x}]"
    elif (insn & 0xffc00000) == 0xf9000000:
        imm12 = (insn >> 10) & 0xfff; rn = (insn >> 5) & 0x1f; rt = insn & 0x1f
        rn_s = "SP" if rn==31 else f"X{rn}"
        asm = f"STR X{rt}, [{rn_s}, #0x{imm12*8:x}]"
    elif (insn & 0xffc00000) == 0xb9400000:
        imm12 = (insn >> 10) & 0xfff; rn = (insn >> 5) & 0x1f; rt = insn & 0x1f
        rn_s = "SP" if rn==31 else f"X{rn}"
        asm = f"LDR W{rt}, [{rn_s}, #0x{imm12*4:x}]"
    elif (insn & 0xffc00000) == 0xb9000000:
        imm12 = (insn >> 10) & 0xfff; rn = (insn >> 5) & 0x1f; rt = insn & 0x1f
        rn_s = "SP" if rn==31 else f"X{rn}"
        asm = f"STR W{rt}, [{rn_s}, #0x{imm12*4:x}]"
    elif (insn & 0xffc00000) == 0x39000000:
        imm12 = (insn >> 10) & 0xfff; rn = (insn >> 5) & 0x1f; rt = insn & 0x1f
        rn_s = "SP" if rn==31 else f"X{rn}"
        asm = f"STRB W{rt}, [{rn_s}, #0x{imm12:x}]"
    elif (insn & 0xffc00000) == 0x39400000:
        imm12 = (insn >> 10) & 0xfff; rn = (insn >> 5) & 0x1f; rt = insn & 0x1f
        rn_s = "SP" if rn==31 else f"X{rn}"
        asm = f"LDRB W{rt}, [{rn_s}, #0x{imm12:x}]"
    elif (insn & 0x7fc00000) in (0x29000000,0x29400000,0x29800000,0x29c00000,
                                   0xa9000000,0xa9400000,0xa9800000,0xa9c00000,
                                   0xa8c00000):
        opc = (insn >> 30) & 3
        l = (insn >> 22) & 1
        imm7 = (insn >> 15) & 0x7f
        if imm7 & 0x40: imm7 -= 0x80
        rt2 = (insn >> 10) & 0x1f
        rn = (insn >> 5) & 0x1f; rt = insn & 0x1f
        scale = 2 + (opc >> 1)
        rp = "X" if opc >= 2 else "W"
        rn_s = "SP" if rn==31 else f"X{rn}"
        mnem = "LDP" if l else "STP"
        asm = f"{mnem} {rp}{rt}, {rp}{rt2}, [{rn_s}, #{imm7 << scale}]"
    else:
        asm = f"??? 0x{insn:08x}"

    # Mark important lines
    marker = ""
    if "STRB" in asm and "X20" in asm:
        marker = "  <<<< STRB to authorized"
    if asm == "RET":
        marker = "  <<<< RET"

    print(f"  0x{off:05x}: {insn:08x}  {asm}{note}{marker}")
