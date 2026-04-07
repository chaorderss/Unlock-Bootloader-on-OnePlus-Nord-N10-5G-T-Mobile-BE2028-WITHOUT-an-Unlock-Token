#!/usr/bin/env python3
"""Find wl_client_get_credentials calls in libmir1server.so - fixed PLT resolution"""
import struct

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
    if (insn & 0x3e000000) == 0x28000000:
        opc = (insn >> 30) & 3
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

# Parse ELF
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
        'type': struct.unpack_from('<I', data, s_off + 4)[0],
        'addr': struct.unpack_from('<Q', data, s_off + 16)[0],
        'offset': struct.unpack_from('<Q', data, s_off + 24)[0],
        'size': struct.unpack_from('<Q', data, s_off + 32)[0],
        'link': struct.unpack_from('<I', data, s_off + 40)[0],
        'entsize': struct.unpack_from('<Q', data, s_off + 56)[0],
    }

# Approach: scan the .plt section to build a map of PLT_addr -> GOT_addr
plt = sections['.plt']
print(f"PLT: addr=0x{plt['addr']:x}, size=0x{plt['size']:x}")

# Each PLT stub on AArch64 looks like:
#   ADRP Xip0, <GOT page>
#   LDR  Xip0, [Xip0, <GOT offset>]  (could also be Xip1)
#   ADD  Xip1, Xip1, <something>  (or BR Xip0)
#   BR   Xip0
# ip0=X16, ip1=X17

plt_to_got = {}
for off in range(plt['offset'], plt['offset'] + plt['size'], 4):
    insn = read_u32(data, off)
    # Check for ADRP X16 or ADRP X17
    if (insn & 0x9f000000) == 0x90000000:
        rd = insn & 0x1f
        if rd in (16, 17):
            immhi = (insn >> 5) & 0x7ffff
            immlo = (insn >> 29) & 0x3
            imm = (immhi << 2) | immlo
            if imm & 0x100000: imm -= 0x200000
            page = (off & ~0xfff) + (imm << 12)
            # Check next instruction for LDR
            if off + 4 < plt['offset'] + plt['size']:
                next_insn = read_u32(data, off + 4)
                if (next_insn & 0xffc00000) == 0xf9400000:
                    imm12 = (next_insn >> 10) & 0xfff
                    rn = (next_insn >> 5) & 0x1f
                    if rn == rd:
                        got_addr = page + imm12 * 8
                        plt_addr = off  # file offset = virtual addr for this lib
                        plt_to_got[plt_addr] = got_addr

print(f"Found {len(plt_to_got)} PLT stubs")

# Now map GOT addresses to symbol names via .rela.plt
rela = sections['.rela.plt']
dynsym_sec = sections['.dynsym']
dynstr_sec = sections['.dynstr']
dynstr_data = data[dynstr_sec['offset']:dynstr_sec['offset']+dynstr_sec['size']]

got_to_sym = {}
ent_size = 24
for i in range(rela['size'] // ent_size):
    roff = rela['offset'] + i * ent_size
    r_offset = struct.unpack_from('<Q', data, roff)[0]
    r_info = struct.unpack_from('<Q', data, roff + 8)[0]
    r_sym = r_info >> 32

    sym_off = dynsym_sec['offset'] + r_sym * (dynsym_sec['entsize'] or 24)
    if sym_off + 24 > len(data): continue
    st_name = struct.unpack_from('<I', data, sym_off)[0]
    end2 = dynstr_data.find(b'\0', st_name)
    if end2 < 0: continue
    sym_name = dynstr_data[st_name:end2].decode('ascii', errors='replace')
    got_to_sym[r_offset] = sym_name

# Build PLT addr -> symbol name
plt_sym_map = {}
for plt_addr, got_addr in plt_to_got.items():
    if got_addr in got_to_sym:
        plt_sym_map[plt_addr] = got_to_sym[got_addr]

# Print our target PLT entries
targets = ['wl_client_get_credentials', 'wl_client_get_fd',
           'wl_display_add_client_created_listener', 'open_session']
for plt_addr, sym_name in sorted(plt_sym_map.items()):
    if any(t in sym_name for t in targets):
        print(f"  PLT 0x{plt_addr:06x} -> {sym_name}")

# Find all BL calls to wl_client_get_credentials
text = sections['.text']
target_plt_addrs = {plt_addr: sym_name for plt_addr, sym_name in plt_sym_map.items()
                    if 'wl_client_get_credentials' in sym_name}

if not target_plt_addrs:
    print("\nwl_client_get_credentials NOT found in resolved PLT stubs!")
    print("Searching ALL dynsym entries containing 'wl_client'...")
    for i in range(dynsym_sec['size'] // (dynsym_sec['entsize'] or 24)):
        sym_off = dynsym_sec['offset'] + i * (dynsym_sec['entsize'] or 24)
        if sym_off + 24 > len(data): continue
        st_name = struct.unpack_from('<I', data, sym_off)[0]
        st_value = struct.unpack_from('<Q', data, sym_off + 8)[0]
        st_size = struct.unpack_from('<Q', data, sym_off + 16)[0]
        end2 = dynstr_data.find(b'\0', st_name)
        if end2 < 0: continue
        sym_name = dynstr_data[st_name:end2].decode('ascii', errors='replace')
        if 'wl_client' in sym_name:
            print(f"  dynsym[{i}]: {sym_name} value=0x{st_value:x} size={st_size}")
else:
    for plt_addr, sym_name in target_plt_addrs.items():
        print(f"\n=== Searching for BL to {sym_name} @ PLT 0x{plt_addr:06x} ===")
        for off in range(text['offset'], text['offset'] + text['size'], 4):
            insn = read_u32(data, off)
            if (insn >> 26) == 0x25:  # BL
                imm26 = insn & 0x3ffffff
                if imm26 & 0x2000000: imm26 -= 0x4000000
                target = off + imm26 * 4
                if target == plt_addr:
                    print(f"\n  BL at 0x{off:06x}")
                    start = max(text['offset'], off - 120)
                    end = min(text['offset'] + text['size'], off + 80)
                    for a in range(start, end, 4):
                        i2 = read_u32(data, a)
                        d = disasm_one(a, i2)
                        marker = ""
                        if a == off:
                            marker = f" <<< {sym_name}"
                        elif (i2 >> 26) == 0x25:
                            bl_imm = i2 & 0x3ffffff
                            if bl_imm & 0x2000000: bl_imm -= 0x4000000
                            bl_tgt = a + bl_imm * 4
                            if bl_tgt in plt_sym_map:
                                marker = f" <<< {plt_sym_map[bl_tgt]}"
                        print(f"    0x{a:06x}: {i2:08x}  {d}{marker}")
