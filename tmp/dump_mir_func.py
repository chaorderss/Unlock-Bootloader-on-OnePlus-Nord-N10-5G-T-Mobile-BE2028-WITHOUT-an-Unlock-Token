#!/usr/bin/env python3
"""Dump full function containing wl_client_get_credentials call at 0x14fd00 in libmir1server.so"""
import struct

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

with open('/Users/xmxx/pinganhuijia/tmp/libmir1server.so', 'rb') as f:
    data = f.read()

# Load PLT symbol map from previous analysis
# PLT stubs: ADRP X16/X17 + LDR
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

# Build PLT map
plt = sections['.plt']
plt_to_got = {}
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
                next_insn = read_u32(data, off + 4)
                if (next_insn & 0xffc00000) == 0xf9400000:
                    imm12 = (next_insn >> 10) & 0xfff
                    rn = (next_insn >> 5) & 0x1f
                    if rn == rd:
                        got_addr = page + imm12 * 8
                        plt_to_got[off] = got_addr

rela = sections['.rela.plt']
dynsym = sections['.dynsym']
dynstr = sections['.dynstr']
dynstr_data = data[dynstr['offset']:dynstr['offset']+dynstr['size']]

got_to_sym = {}
for i in range(rela['size'] // 24):
    roff = rela['offset'] + i * 24
    r_offset = struct.unpack_from('<Q', data, roff)[0]
    r_info = struct.unpack_from('<Q', data, roff + 8)[0]
    r_sym = r_info >> 32
    sym_off = dynsym['offset'] + r_sym * (dynsym['entsize'] or 24)
    if sym_off + 24 > len(data): continue
    st_name = struct.unpack_from('<I', data, sym_off)[0]
    end2 = dynstr_data.find(b'\0', st_name)
    if end2 < 0: continue
    got_to_sym[r_offset] = dynstr_data[st_name:end2].decode('ascii', errors='replace')

plt_sym = {}
for p, g in plt_to_got.items():
    if g in got_to_sym:
        plt_sym[p] = got_to_sym[g]

import re

def disasm(addr, insn):
    if insn == 0xd65f03c0: return "RET"
    if insn == 0xd503201f: return "NOP"
    if insn == 0xd503233f: return "PACIASP"
    if insn == 0xd50323bf: return "AUTIASP"

    # STP/LDP
    if (insn & 0x3e000000) == 0x28000000:
        opc = (insn >> 30) & 3
        l = (insn >> 22) & 1
        pre = (insn >> 24) & 1
        post = not pre and ((insn >> 23) & 1)
        imm7 = (insn >> 15) & 0x7f
        if imm7 & 0x40: imm7 -= 0x80
        rt2 = (insn >> 10) & 0x1f
        rn = (insn >> 5) & 0x1f
        rt = insn & 0x1f
        scale = 2 + (opc >> 1)
        rp = "X" if opc >= 2 else "W"
        rn_s = "SP" if rn == 31 else f"X{rn}"
        mnem = "LDP" if l else "STP"
        off_val = imm7 << scale
        if pre:
            return f"{mnem} {rp}{rt}, {rp}{rt2}, [{rn_s}, #{off_val}]!"
        elif post:
            return f"{mnem} {rp}{rt}, {rp}{rt2}, [{rn_s}], #{off_val}"
        else:
            return f"{mnem} {rp}{rt}, {rp}{rt2}, [{rn_s}, #{off_val}]"

    if (insn >> 26) == 0x25:  # BL
        imm26 = insn & 0x3ffffff
        if imm26 & 0x2000000: imm26 -= 0x4000000
        t = addr + imm26*4
        sym = plt_sym.get(t, "")
        if sym:
            # Demangle
            sym = re.sub(r'^_Z\w+', lambda m: m.group(), sym)
            return f"BL 0x{t:x} <{sym}>"
        return f"BL 0x{t:x}"
    if (insn >> 26) == 0x05:
        imm26 = insn & 0x3ffffff
        if imm26 & 0x2000000: imm26 -= 0x4000000
        return f"B 0x{addr + imm26*4:x}"
    if (insn & 0xff000010) == 0x54000000:
        cond = insn & 0xf
        imm19 = (insn >> 5) & 0x7ffff
        if imm19 & 0x40000: imm19 -= 0x80000
        conds = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
        return f"B.{conds[cond]} 0x{addr + imm19*4:x}"
    if (insn & 0x7e000000) == 0x34000000:
        sf = (insn >> 31) & 1
        op = (insn >> 24) & 1
        imm19 = (insn >> 5) & 0x7ffff
        if imm19 & 0x40000: imm19 -= 0x80000
        rt = insn & 0x1f
        nm = "SP" if rt == 31 else f"{'X' if sf else 'W'}{rt}"
        return f"{'CBNZ' if op else 'CBZ'} {nm}, 0x{addr + imm19*4:x}"
    if (insn & 0x7e000000) == 0x36000000:  # TBZ/TBNZ
        op = (insn >> 24) & 1
        b5 = (insn >> 31) & 1
        b40 = (insn >> 19) & 0x1f
        bit = (b5 << 5) | b40
        imm14 = (insn >> 5) & 0x3fff
        if imm14 & 0x2000: imm14 -= 0x4000
        rt = insn & 0x1f
        rp = "X" if b5 else "W"
        return f"{'TBNZ' if op else 'TBZ'} {rp}{rt}, #{bit}, 0x{addr + imm14*4:x}"
    if (insn & 0x9f000000) == 0x90000000:
        rd = insn & 0x1f
        immhi = (insn >> 5) & 0x7ffff
        immlo = (insn >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm & 0x100000: imm -= 0x200000
        page = (addr & ~0xfff) + (imm << 12)
        return f"ADRP X{rd}, 0x{page:x}"
    if (insn & 0x9f000000) == 0x10000000:  # ADR
        rd = insn & 0x1f
        immhi = (insn >> 5) & 0x7ffff
        immlo = (insn >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm & 0x100000: imm -= 0x200000
        return f"ADR X{rd}, 0x{addr + imm:x}"
    if (insn & 0x7f800000) == 0x11000000:
        sf = (insn >> 31) & 1
        sh = (insn >> 22) & 1
        imm12 = (insn >> 10) & 0xfff
        rn = (insn >> 5) & 0x1f
        rd = insn & 0x1f
        if sh: imm12 <<= 12
        rp = "X" if sf else "W"
        rn_s = "SP" if rn == 31 else f"{rp}{rn}"
        rd_s = "SP" if rd == 31 else f"{rp}{rd}"
        return f"ADD {rd_s}, {rn_s}, #0x{imm12:x}"
    if (insn & 0x7f800000) == 0x51000000:
        sf = (insn >> 31) & 1
        imm12 = (insn >> 10) & 0xfff
        rn = (insn >> 5) & 0x1f
        rd = insn & 0x1f
        rp = "X" if sf else "W"
        rn_s = "SP" if rn == 31 else f"{rp}{rn}"
        rd_s = "SP" if rd == 31 else f"{rp}{rd}"
        return f"SUB {rd_s}, {rn_s}, #0x{imm12:x}"
    if (insn & 0x7f800000) == 0x52800000:
        hw = (insn >> 21) & 3
        imm16 = (insn >> 5) & 0xffff
        rd = insn & 0x1f
        sf = (insn >> 31) & 1
        rp = "X" if sf else "W"
        val = imm16 << (hw*16)
        return f"MOV {rp}{rd}, #0x{val:x}"
    if (insn & 0x7fe0ffe0) == 0x2a0003e0:
        sf = (insn >> 31) & 1
        rm = (insn >> 16) & 0x1f
        rd = insn & 0x1f
        rp = "X" if sf else "W"
        return f"MOV {rp}{rd}, {rp}{rm}"
    if (insn & 0xffe0fc00) == 0xaa0003e0:  # MOV Xd, Xm (ORR Xd, XZR, Xm)
        rm = (insn >> 16) & 0x1f
        rd = insn & 0x1f
        return f"MOV X{rd}, X{rm}"
    if (insn & 0xffffffc0) == 0xdac10000:  # AUTIA
        rn = (insn >> 5) & 0x1f
        rd = insn & 0x1f
        return f"AUTIA X{rd}, X{rn}"
    if (insn & 0xfffffc1f) == 0xd63f0000:
        rn = (insn >> 5) & 0x1f
        return f"BLR X{rn}"
    if (insn & 0xfffffc1f) == 0xd61f0000:
        rn = (insn >> 5) & 0x1f
        return f"BR X{rn}"
    # LDR/STR immediate (unsigned offset)
    for size_bits, size_name, scale in [(3, "X", 8), (2, "W", 4), (1, "H", 2), (0, "B", 1)]:
        # LDR
        mask = (0b11 << 30) | (0b111111 << 24) | (0b11 << 22)
        val_ldr = (size_bits << 30) | (0b111001 << 24) | (0b01 << 22)
        val_str = (size_bits << 30) | (0b111001 << 24) | (0b00 << 22)
        if (insn & mask) == val_ldr:
            imm12 = (insn >> 10) & 0xfff
            rn = (insn >> 5) & 0x1f
            rt = insn & 0x1f
            rn_s = "SP" if rn == 31 else f"X{rn}"
            rt_s = f"{'X' if size_bits==3 else 'W'}{rt}"
            return f"LDR {rt_s}, [{rn_s}, #0x{imm12*scale:x}]"
        if (insn & mask) == val_str:
            imm12 = (insn >> 10) & 0xfff
            rn = (insn >> 5) & 0x1f
            rt = insn & 0x1f
            rn_s = "SP" if rn == 31 else f"X{rn}"
            rt_s = f"{'X' if size_bits==3 else 'W'}{rt}"
            return f"STR {rt_s}, [{rn_s}, #0x{imm12*scale:x}]"
    # LDRSW
    if (insn & 0xffc00000) == 0xb9800000:
        imm12 = (insn >> 10) & 0xfff
        rn = (insn >> 5) & 0x1f
        rt = insn & 0x1f
        rn_s = "SP" if rn == 31 else f"X{rn}"
        return f"LDRSW X{rt}, [{rn_s}, #0x{imm12*4:x}]"
    # CMP (SUBS with Rd=XZR)
    if (insn & 0x7f20001f) == 0x6b00001f:
        sf = (insn >> 31) & 1
        rm = (insn >> 16) & 0x1f
        rn = (insn >> 5) & 0x1f
        rp = "X" if sf else "W"
        return f"CMP {rp}{rn}, {rp}{rm}"
    # MADD/MSUB (for multiply)
    if (insn & 0x7fe08000) == 0x1b000000:
        sf = (insn >> 31) & 1
        rm = (insn >> 16) & 0x1f
        ra = (insn >> 10) & 0x1f
        rn = (insn >> 5) & 0x1f
        rd = insn & 0x1f
        o0 = (insn >> 15) & 1
        rp = "X" if sf else "W"
        if o0 == 0 and ra == 31:
            return f"MUL {rp}{rd}, {rp}{rn}, {rp}{rm}"
        elif o0 == 0:
            return f"MADD {rp}{rd}, {rp}{rn}, {rp}{rm}, {rp}{ra}"
        else:
            return f"MSUB {rp}{rd}, {rp}{rn}, {rp}{rm}, {rp}{ra}"
    # LDAR / STLR / LDXR / STXR
    if (insn & 0x3f000000) == 0x08000000:
        size = (insn >> 30) & 3
        L = (insn >> 22) & 1
        o0 = (insn >> 15) & 1
        rn = (insn >> 5) & 0x1f
        rt = insn & 0x1f
        rp = "X" if size == 3 else "W"
        rn_s = "SP" if rn == 31 else f"X{rn}"
        if L:
            return f"LDAR {rp}{rt}, [{rn_s}]"
        else:
            return f"STLR {rp}{rt}, [{rn_s}]"
    # STR reg (post-index)
    if (insn & 0xffe00c00) == 0xf8000400:
        imm9 = (insn >> 12) & 0x1ff
        if imm9 & 0x100: imm9 -= 0x200
        rn = (insn >> 5) & 0x1f
        rt = insn & 0x1f
        rn_s = "SP" if rn == 31 else f"X{rn}"
        return f"STR X{rt}, [{rn_s}], #{imm9}"
    # LDR reg (post-index)
    if (insn & 0xffe00c00) == 0xf8400400:
        imm9 = (insn >> 12) & 0x1ff
        if imm9 & 0x100: imm9 -= 0x200
        rn = (insn >> 5) & 0x1f
        rt = insn & 0x1f
        rn_s = "SP" if rn == 31 else f"X{rn}"
        return f"LDR X{rt}, [{rn_s}], #{imm9}"
    # STR X reg (pre-index)
    if (insn & 0xffe00c00) == 0xf8000c00:
        imm9 = (insn >> 12) & 0x1ff
        if imm9 & 0x100: imm9 -= 0x200
        rn = (insn >> 5) & 0x1f
        rt = insn & 0x1f
        rn_s = "SP" if rn == 31 else f"X{rn}"
        return f"STR X{rt}, [{rn_s}, #{imm9}]!"
    # LDR X from register offset
    if (insn & 0xffe00c00) == 0xf8600800:
        rm = (insn >> 16) & 0x1f
        rn = (insn >> 5) & 0x1f
        rt = insn & 0x1f
        rn_s = "SP" if rn == 31 else f"X{rn}"
        return f"LDR X{rt}, [{rn_s}, X{rm}]"

    return f"??? 0x{insn:08x}"

# Find the function boundary around 0x14fd00
# Scan backward for STP X29, X30 (function prologue) or PACIASP
target = 0x14fd00
func_start = None
for off in range(target, max(0, target - 2000), -4):
    insn = read_u32(data, off)
    d = disasm(off, insn)
    # Common function prologues: STP X29, X30, [SP, #-N]! or SUB SP, SP, #N
    if 'PACIASP' in d:
        func_start = off
        break
    # STP X29, X30 with pre-index (negative offset)
    if (insn & 0xffe07fff) == 0xa9800000 or 'STP X29, X30' in d:
        # Check if this looks like a prologue
        if off + 4 < target:
            next_d = disasm(off+4, read_u32(data, off+4))
            if 'MOV X29' in next_d or 'ADD X29' in next_d or 'STP' in next_d or 'SUB SP' in next_d:
                func_start = off
                break

if not func_start:
    # Try finding by scanning for RET before our code
    for off in range(target - 4, max(0, target - 2000), -4):
        insn = read_u32(data, off)
        if insn == 0xd65f03c0:  # RET
            func_start = off + 4
            break

# Also find function end (RET)
func_end = None
for off in range(target, min(len(data), target + 2000), 4):
    insn = read_u32(data, off)
    if insn == 0xd65f03c0:
        func_end = off + 4
        break

print(f"Function: 0x{func_start:06x} - 0x{func_end:06x} ({func_end - func_start} bytes)")
print()

# Look for strings referenced by ADRP+ADD in the function
rodata = sections['.rodata']

def get_string_at(addr):
    if addr >= rodata['offset'] and addr < rodata['offset'] + rodata['size']:
        end = data.find(b'\0', addr)
        if end > addr:
            s = data[addr:end]
            try:
                return s.decode('ascii')
            except:
                return None
    return None

# Dump the function
for off in range(func_start, func_end, 4):
    insn = read_u32(data, off)
    d = disasm(off, insn)

    # Check for string references
    string_ref = ""
    if 'ADRP' in d and off + 4 < func_end:
        next_insn = read_u32(data, off + 4)
        next_d = disasm(off + 4, next_insn)
        if 'ADD' in next_d:
            # Extract the full address
            rd = insn & 0x1f
            immhi = (insn >> 5) & 0x7ffff
            immlo = (insn >> 29) & 0x3
            imm = (immhi << 2) | immlo
            if imm & 0x100000: imm -= 0x200000
            page = (off & ~0xfff) + (imm << 12)

            n_imm12 = (next_insn >> 10) & 0xfff
            n_sh = (next_insn >> 22) & 1
            if n_sh: n_imm12 <<= 12
            full_addr = page + n_imm12

            s = get_string_at(full_addr)
            if s:
                string_ref = f'  ; "{s[:60]}"'

    marker = ""
    if off == 0x14fd00:
        marker = " <<<< wl_client_get_credentials"

    print(f"  0x{off:06x}: {insn:08x}  {d}{string_ref}{marker}")
