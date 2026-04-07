#!/usr/bin/env python3
"""Analyze libmir1server.so to find create_client_session and the empty session name"""
import struct, sys

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def disasm_one(addr, insn):
    if insn == 0xd65f03c0: return "RET"
    if insn == 0xd503201f: return "NOP"
    if insn == 0xd503233f: return "PACIASP"
    if insn == 0xd50323bf: return "AUTIASP"
    if (insn >> 26) == 0x25:
        imm26 = insn & 0x3ffffff
        if imm26 & 0x2000000: imm26 -= 0x4000000
        return f"BL 0x{addr + imm26*4:x}"
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
        reg = f"{'X' if sf else 'W'}{rt}"
        return f"{'CBNZ' if op else 'CBZ'} {reg}, 0x{addr + imm19*4:x}"
    if (insn & 0x9f000000) == 0x90000000:
        rd = insn & 0x1f
        immhi = (insn >> 5) & 0x7ffff
        immlo = (insn >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm & 0x100000: imm -= 0x200000
        page = (addr & ~0xfff) + (imm << 12)
        return f"ADRP X{rd}, 0x{page:x}"
    if (insn & 0x7f800000) == 0x11000000:
        sf = (insn >> 31) & 1
        sh = (insn >> 22) & 1
        imm12 = (insn >> 10) & 0xfff
        rn = (insn >> 5) & 0x1f
        rd = insn & 0x1f
        if sh: imm12 <<= 12
        rp = "X" if sf else "W"
        return f"ADD {rp}{rd}, {rp}{rn}, #0x{imm12:x}"
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
    if (insn & 0xfffffc1f) == 0xd63f0000:
        rn = (insn >> 5) & 0x1f
        return f"BLR X{rn}"
    if (insn & 0xffc00000) == 0xf9400000:
        imm12 = (insn >> 10) & 0xfff
        rn = (insn >> 5) & 0x1f
        rt = insn & 0x1f
        return f"LDR X{rt}, [X{rn}, #0x{imm12*8:x}]"
    if (insn & 0xffc00000) == 0xf9000000:
        imm12 = (insn >> 10) & 0xfff
        rn = (insn >> 5) & 0x1f
        rt = insn & 0x1f
        return f"STR X{rt}, [X{rn}, #0x{imm12*8:x}]"
    if (insn & 0xffc00000) == 0x39400000:
        imm12 = (insn >> 10) & 0xfff
        rn = (insn >> 5) & 0x1f
        rt = insn & 0x1f
        return f"LDRB W{rt}, [X{rn}, #0x{imm12:x}]"
    if (insn & 0xffc00000) == 0x39000000:
        imm12 = (insn >> 10) & 0xfff
        rn = (insn >> 5) & 0x1f
        rt = insn & 0x1f
        return f"STRB W{rt}, [X{rn}, #0x{imm12:x}]"
    if (insn & 0x7f800000) == 0x51000000:
        sf = (insn >> 31) & 1
        imm12 = (insn >> 10) & 0xfff
        rn = (insn >> 5) & 0x1f
        rd = insn & 0x1f
        rp = "X" if sf else "W"
        return f"SUB {rp}{rd}, {rp}{rn}, #0x{imm12:x}"
    if (insn & 0x3e000000) == 0x28000000:
        opc = (insn >> 30) & 3
        v = (insn >> 26) & 1
        pre = (insn >> 24) & 1
        post = (insn >> 23) & 1
        l = (insn >> 22) & 1
        imm7 = (insn >> 15) & 0x7f
        if imm7 & 0x40: imm7 -= 0x80
        rt2 = (insn >> 10) & 0x1f
        rn = (insn >> 5) & 0x1f
        rt = insn & 0x1f
        scale = 2 + (opc >> 1)
        rp = "X" if opc >= 2 else "W"
        mnem = "LDP" if l else "STP"
        return f"{mnem} {rp}{rt}, {rp}{rt2}, [X{rn}, #{imm7 << scale}]"
    return f"??? 0x{insn:08x}"

with open('/Users/xmxx/pinganhuijia/tmp/libmir1server.so', 'rb') as f:
    data = f.read()

# Parse ELF headers
e_shoff = struct.unpack_from('<Q', data, 40)[0]
e_shentsize = struct.unpack_from('<H', data, 58)[0]
e_shnum = struct.unpack_from('<H', data, 60)[0]
e_shstrndx = struct.unpack_from('<H', data, 62)[0]

# Get section header string table
shstrtab_hdr_off = e_shoff + e_shstrndx * e_shentsize
shstrtab_off = struct.unpack_from('<Q', data, shstrtab_hdr_off + 24)[0]
shstrtab_sz = struct.unpack_from('<Q', data, shstrtab_hdr_off + 32)[0]

# Parse all sections
sections = {}
for i in range(e_shnum):
    s_off = e_shoff + i * e_shentsize
    nm_idx = struct.unpack_from('<I', data, s_off)[0]
    nm_end = data.find(b'\0', shstrtab_off + nm_idx)
    nm = data[shstrtab_off + nm_idx:nm_end].decode('ascii', errors='replace')
    sh_type = struct.unpack_from('<I', data, s_off + 4)[0]
    sh_addr = struct.unpack_from('<Q', data, s_off + 16)[0]
    sh_offset = struct.unpack_from('<Q', data, s_off + 24)[0]
    sh_size = struct.unpack_from('<Q', data, s_off + 32)[0]
    sh_link = struct.unpack_from('<I', data, s_off + 40)[0]
    sh_entsize = struct.unpack_from('<Q', data, s_off + 56)[0]
    sections[nm] = {'type': sh_type, 'addr': sh_addr, 'offset': sh_offset,
                    'size': sh_size, 'link': sh_link, 'entsize': sh_entsize}

print("=== Key Sections ===")
for nm in ['.plt', '.rela.plt', '.dynsym', '.dynstr', '.got.plt', '.text', '.rodata']:
    if nm in sections:
        s = sections[nm]
        print(f"  {nm}: addr=0x{s['addr']:06x} offset=0x{s['offset']:06x} size=0x{s['size']:06x}")

# Parse dynamic symbol table for PLT resolution
dynsym = sections['.dynsym']
dynstr = sections['.dynstr']
dynstr_data = data[dynstr['offset']:dynstr['offset']+dynstr['size']]

def get_dynsym_name(idx):
    sym_off = dynsym['offset'] + idx * (dynsym['entsize'] or 24)
    if sym_off + 24 > len(data): return ""
    st_name = struct.unpack_from('<I', data, sym_off)[0]
    end = dynstr_data.find(b'\0', st_name)
    return dynstr_data[st_name:end].decode('ascii', errors='replace')

# Find PLT entries for our target functions
rela_plt = sections['.rela.plt']
plt_sec = sections['.plt']
got_plt = sections.get('.got.plt', None)

plt_addrs = {}
entry_size = 24  # sizeof(Elf64_Rela)
for i in range(rela_plt['size'] // entry_size):
    roff = rela_plt['offset'] + i * entry_size
    r_offset = struct.unpack_from('<Q', data, roff)[0]
    r_info = struct.unpack_from('<Q', data, roff + 8)[0]
    r_sym = r_info >> 32
    sym_name = get_dynsym_name(r_sym)

    # PLT entry address: plt_start + (i+1)*16 for aarch64
    # Actually depends on PLT format - let's compute from GOT offset
    if got_plt:
        got_idx = (r_offset - got_plt['addr']) // 8
        plt_entry = plt_sec['addr'] + got_idx * 16  # Each PLT entry is 16 bytes

    if any(k in sym_name for k in ['wl_client_get_credentials', 'wl_client_get_fd',
                                      'open_session', 'wl_display_add_client_created_listener']):
        if got_plt:
            print(f"\n  PLT: {sym_name}")
            print(f"    GOT@0x{r_offset:x}, PLT slot ~0x{plt_entry:x}")
            plt_addrs[sym_name] = plt_entry

# Now find all BL calls to wl_client_get_credentials
text = sections['.text']
target_sym = 'wl_client_get_credentials'
if target_sym in plt_addrs:
    plt_addr = plt_addrs[target_sym]
    print(f"\n=== BL calls to {target_sym} (PLT@0x{plt_addr:x}) ===")

    for off in range(text['offset'], text['offset'] + text['size'], 4):
        insn = read_u32(data, off)
        if (insn >> 26) == 0x25:  # BL
            imm26 = insn & 0x3ffffff
            if imm26 & 0x2000000: imm26 -= 0x4000000
            target = off + imm26 * 4
            # Check if target is close to PLT entry (PLT entries can vary)
            if abs(target - plt_addr) < 32:
                print(f"\n  BL at 0x{off:06x} -> 0x{target:06x}")
                # Print surrounding context
                start = max(text['offset'], off - 80)
                end = min(text['offset'] + text['size'], off + 80)
                for a in range(start, end, 4):
                    i2 = read_u32(data, a)
                    d = disasm_one(a, i2)
                    marker = " <<< wl_client_get_credentials" if a == off else ""
                    # Check if any BL targets a known PLT
                    if (i2 >> 26) == 0x25 and a != off:
                        bl_imm = i2 & 0x3ffffff
                        if bl_imm & 0x2000000: bl_imm -= 0x4000000
                        bl_tgt = a + bl_imm * 4
                        for pn, pa in plt_addrs.items():
                            if abs(bl_tgt - pa) < 32:
                                marker = f" <<< {pn}"
                    print(f"    0x{a:06x}: {i2:08x}  {d}{marker}")
else:
    print(f"\nWARNING: {target_sym} not found in PLT!")
    # Try scanning for it via symbol name
    for k, v in plt_addrs.items():
        print(f"  Available PLT: {k} @ 0x{v:x}")

# Also find calls to wl_display_add_client_created_listener
for target_sym in ['wl_display_add_client_created_listener']:
    if target_sym in plt_addrs:
        plt_addr = plt_addrs[target_sym]
        print(f"\n=== BL calls to {target_sym} (PLT@0x{plt_addr:x}) ===")
        for off in range(text['offset'], text['offset'] + text['size'], 4):
            insn = read_u32(data, off)
            if (insn >> 26) == 0x25:
                imm26 = insn & 0x3ffffff
                if imm26 & 0x2000000: imm26 -= 0x4000000
                target = off + imm26 * 4
                if abs(target - plt_addr) < 32:
                    print(f"\n  BL at 0x{off:06x} -> 0x{target:06x}")
                    start = max(text['offset'], off - 60)
                    end = min(text['offset'] + text['size'], off + 40)
                    for a in range(start, end, 4):
                        i2 = read_u32(data, a)
                        d = disasm_one(a, i2)
                        marker = f" <<< {target_sym}" if a == off else ""
                        print(f"    0x{a:06x}: {i2:08x}  {d}{marker}")
