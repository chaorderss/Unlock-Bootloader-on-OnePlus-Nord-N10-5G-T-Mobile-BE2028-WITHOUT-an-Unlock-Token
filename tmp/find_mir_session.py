#!/usr/bin/env python3
"""Find BL calls to open_session from Wayland connector code"""
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
        return f"MOV {rp}{rd}, #{imm16 << (hw*16)}"
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
    if (insn & 0x3b200c00) == 0x39000000:
        size = (insn >> 30) & 3
        opc = (insn >> 22) & 3
        imm12 = (insn >> 10) & 0xfff
        rn = (insn >> 5) & 0x1f
        rt = insn & 0x1f
        offset = imm12 << size
        mnems = {(0,0):"STRB",(0,1):"LDRB",(1,0):"STRH",(1,1):"LDRH",
                 (2,0):"STR W",(2,1):"LDR W",(3,0):"STR X",(3,1):"LDR X"}
        mnem = mnems.get((size,opc), f"MEM{size}_{opc}")
        return f"{mnem}{rt}, [X{rn}, #0x{offset:x}]"
    if (insn & 0x7f800000) == 0x51000000:
        sf = (insn >> 31) & 1
        imm12 = (insn >> 10) & 0xfff
        rn = (insn >> 5) & 0x1f
        rd = insn & 0x1f
        rp = "X" if sf else "W"
        return f"SUB {rp}{rd}, {rp}{rn}, #0x{imm12:x}"
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

# Find open_session virtual call pattern
# open_session is at vtable offset, called via BLR after loading from vtable
# ShellWrapper::open_session is at 0x184f70
# AbstractShell::open_session is at 0x17ad60

# More importantly — find create_client_session which sets up the session name for Wayland

# Look for code near "client_created_listener" string (0x017eb5)
# This is a wl_listener used to hook into client creation events
# The callback is create_client_session

# Let me find all references to the string "client_created_listener" (at offset 0x017eb5)
target_str = 0x017eb5
target_page = target_str & ~0xfff
target_lo = target_str & 0xfff

print(f"Looking for ADRP+ADD referencing 'client_created_listener' at 0x{target_str:06x}")
print(f"Page=0x{target_page:x}, offset=0x{target_lo:x}")

for off in range(0, len(data) - 8, 4):
    insn = read_u32(data, off)
    if (insn & 0x9f000000) == 0x90000000:  # ADRP
        rd = insn & 0x1f
        immhi = (insn >> 5) & 0x7ffff
        immlo = (insn >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm & 0x100000: imm -= 0x200000
        page = (off & ~0xfff) + (imm << 12)
        if page == target_page and off + 4 < len(data):
            next_insn = read_u32(data, off + 4)
            if (next_insn & 0x7f800000) == 0x11000000:
                imm12 = (next_insn >> 10) & 0xfff
                sh = (next_insn >> 22) & 1
                if sh: imm12 <<= 12
                if imm12 == target_lo:
                    print(f"  Found reference at 0x{off:06x}")

# Also find references to wl_client_get_credentials (at address in PLT)
# It's imported, so should be in PLT
# Find string "wl_client_get_credentials" at 0x017f5d
cred_str = data.find(b'wl_client_get_credentials\x00')
print(f"\nwl_client_get_credentials string at 0x{cred_str:06x}")

# Look for BL calls to wl_client_get_credentials PLT
# First find PLT
e_shoff2 = struct.unpack_from('<Q', data, 40)[0]
for i in range(e_shnum):
    off = e_shoff2 + i * e_shentsize
    name_off = struct.unpack_from('<I', data, off)[0]
    name = get_sh_name(data, sections, e_shstrndx, e_shentsize, name_off)

# Actually let me just search for BL targets more directly
# Look for functions that call wl_client_get_credentials
# The pattern is: BL to PLT stub for wl_client_get_credentials
# The PLT stub should be in the PLT section

# Parse ELF to find PLT and rela.plt
plt_sec = rela_plt_sec = None
for i_sec in range(e_shnum):
    s_off = e_shoff + i_sec * e_shentsize
    nm_off = struct.unpack_from('<I', data, s_off)[0]
    end = shstrtab_data.find(b'\0', nm_off) if shstrtab_data else nm_off
    sh_nm = shstrtab_data[nm_off:end].decode() if shstrtab_data else ""
    if sh_nm == '.plt':
        plt_sec = {
            'offset': struct.unpack_from('<Q', data, s_off+24)[0],
            'size': struct.unpack_from('<Q', data, s_off+32)[0],
        }
    elif sh_nm == '.rela.plt':
        rela_plt_sec = {
            'offset': struct.unpack_from('<Q', data, s_off+24)[0],
            'size': struct.unpack_from('<Q', data, s_off+32)[0],
        }

# Parse ELF properly
e_shoff = struct.unpack_from('<Q', data, 40)[0]
e_shentsize = struct.unpack_from('<H', data, 58)[0]
e_shnum = struct.unpack_from('<H', data, 60)[0]
e_shstrndx = struct.unpack_from('<H', data, 62)[0]

shstrtab_off = e_shoff + e_shstrndx * e_shentsize
shstrtab_data_off = struct.unpack_from('<Q', data, shstrtab_off+24)[0]
shstrtab_size = struct.unpack_from('<Q', data, shstrtab_off+32)[0]

sec_info = {}
for i in range(e_shnum):
    s_off = e_shoff + i * e_shentsize
    nm_off = struct.unpack_from('<I', data, s_off)[0]
    nm_end = data.find(b'\0', shstrtab_data_off + nm_off)
    nm = data[shstrtab_data_off + nm_off:nm_end].decode()
    sec_info[nm] = {
        'offset': struct.unpack_from('<Q', data, s_off+24)[0],
        'size': struct.unpack_from('<Q', data, s_off+32)[0],
        'addr': struct.unpack_from('<Q', data, s_off+16)[0],
        'link': struct.unpack_from('<I', data, s_off+40)[0],
        'entsize': struct.unpack_from('<Q', data, s_off+56)[0],
    }

print("\n=== Sections ===")
for nm in ['.plt', '.rela.plt', '.dynsym', '.dynstr', '.got.plt']:
    if nm in sec_info:
        s = sec_info[nm]
        print(f"  {nm}: offset=0x{s['offset']:06x} size=0x{s['size']:06x}")

# Find wl_client_get_credentials PLT entry thru rela.plt
if '.rela.plt' in sec_info and '.dynsym' in sec_info and '.dynstr' in sec_info:
    rela = sec_info['.rela.plt']
    dynsym = sec_info['.dynsym']
    dynstr_sec = sec_info['.dynstr']
    dynstr_d = data[dynstr_sec['offset']:dynstr_sec['offset']+dynstr_sec['size']]

    got_plt = sec_info.get('.got.plt', {})
    plt = sec_info.get('.plt', {})

    for roff in range(rela['offset'], rela['offset'] + rela['size'], 24):
        r_offset = struct.unpack_from('<Q', data, roff)[0]
        r_info = struct.unpack_from('<Q', data, roff + 8)[0]
        r_sym = r_info >> 32

        sym_off = dynsym['offset'] + r_sym * (dynsym['entsize'] or 24)
        if sym_off + 24 > len(data):
            continue
        st_name = struct.unpack_from('<I', data, sym_off)[0]
        if st_name >= len(dynstr_d):
            continue
        nm_end = dynstr_d.find(b'\0', st_name)
        sym_name = dynstr_d[st_name:nm_end].decode('ascii', errors='replace')

        if 'wl_client_get_credentials' in sym_name or 'open_session' in sym_name:
            # Calculate PLT entry index
            got_plt_start = got_plt.get('offset', 0)
            plt_start = plt.get('offset', 0)
            if got_plt_start and plt_start:
                idx = (r_offset - got_plt.get('addr', 0)) // 8
                plt_entry_addr = plt['addr'] + idx * 16
                print(f"\n  {sym_name}: GOT@0x{r_offset:06x} PLT_idx={idx} PLT_addr=~0x{plt_entry_addr:06x}")
                # Find all BL calls to this PLT address
                for code_off in range(0, min(len(data), 0x1f0000), 4):
                    insn = read_u32(data, code_off)
                    if (insn >> 26) == 0x25:  # BL
                        imm26 = insn & 0x3ffffff
                        if imm26 & 0x2000000: imm26 -= 0x4000000
                        target = code_off + imm26 * 4
                        if abs(target - plt_entry_addr) < 32:  # Allow some PLT entry size tolerance
                            print(f"    BL to {sym_name} at code offset 0x{code_off:06x}")
                            # Print context
                            start = max(0, code_off - 40)
                            end = min(len(data), code_off + 24)
                            for a in range(start, end, 4):
                                i = read_u32(data, a)
                                d = disasm_one(a, i)
                                marker = " <<<<" if a == code_off else ""
                                print(f"      0x{a:06x}: {i:08x}  {d}{marker}")
