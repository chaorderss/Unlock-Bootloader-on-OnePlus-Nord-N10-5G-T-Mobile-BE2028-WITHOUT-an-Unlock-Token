#!/usr/bin/env python3
"""Analyze PLT entries and find set_maximized call site"""
import struct

with open("/Users/xmxx/pinganhuijia/tmp/hwc.so", "rb") as f:
    data = f.read()

# Parse ELF to find PLT/GOT and dynamic symbols
# ELF header
e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
e_phnum = struct.unpack_from("<H", data, 0x38)[0]

print(f"Program headers: offset=0x{e_phoff:x}, size={e_phentsize}, count={e_phnum}")

# Find .dynstr and .dynsym sections via section headers
e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
e_shentsize = struct.unpack_from("<H", data, 0x3a)[0]
e_shnum = struct.unpack_from("<H", data, 0x3c)[0]
e_shstrndx = struct.unpack_from("<H", data, 0x3e)[0]

# Get section name string table
shstr_off = struct.unpack_from("<Q", data, e_shoff + e_shstrndx * e_shentsize + 0x18)[0]
shstr_size = struct.unpack_from("<Q", data, e_shoff + e_shstrndx * e_shentsize + 0x20)[0]

sections = {}
for i in range(e_shnum):
    sh = e_shoff + i * e_shentsize
    name_off = struct.unpack_from("<I", data, sh)[0]
    sh_type = struct.unpack_from("<I", data, sh + 4)[0]
    sh_addr = struct.unpack_from("<Q", data, sh + 0x10)[0]
    sh_offset = struct.unpack_from("<Q", data, sh + 0x18)[0]
    sh_size = struct.unpack_from("<Q", data, sh + 0x20)[0]
    sh_link = struct.unpack_from("<I", data, sh + 0x28)[0]
    sh_entsize = struct.unpack_from("<Q", data, sh + 0x38)[0]

    name_end = data.find(b'\x00', shstr_off + name_off)
    name = data[shstr_off + name_off:name_end].decode('ascii', errors='replace')
    sections[name] = {
        'type': sh_type, 'addr': sh_addr, 'offset': sh_offset,
        'size': sh_size, 'link': sh_link, 'entsize': sh_entsize
    }

# Print PLT-related sections
for name in ['.dynsym', '.dynstr', '.rela.plt', '.plt', '.got.plt', '.got']:
    if name in sections:
        s = sections[name]
        print(f"  {name}: addr=0x{s['addr']:x} offset=0x{s['offset']:x} size=0x{s['size']:x}")

# Parse .dynsym with .dynstr
dynsym = sections.get('.dynsym')
dynstr = sections.get('.dynstr')
if dynsym and dynstr:
    nsyms = dynsym['size'] // dynsym['entsize']
    print(f"\nDynamic symbols ({nsyms} total), showing imports:")
    for i in range(nsyms):
        sym_off = dynsym['offset'] + i * dynsym['entsize']
        st_name = struct.unpack_from("<I", data, sym_off)[0]
        st_info = data[sym_off + 4]
        st_shndx = struct.unpack_from("<H", data, sym_off + 6)[0]
        st_value = struct.unpack_from("<Q", data, sym_off + 8)[0]

        name_end = data.find(b'\x00', dynstr['offset'] + st_name)
        name = data[dynstr['offset'] + st_name:name_end].decode('ascii', errors='replace')

        # Show wl_ and xdg_ symbols, plus abort/assert
        if any(x in name for x in ['wl_proxy', 'xdg_', 'abort', 'assert', 'wl_display']):
            bind = st_info >> 4
            stype = st_info & 0xf
            print(f"  [{i:3d}] 0x{st_value:08x} {name} (bind={bind}, type={stype}, shndx={st_shndx})")

# Parse .rela.plt to map PLT entries to symbols
rela_plt = sections.get('.rela.plt')
if rela_plt and dynsym and dynstr:
    print(f"\nPLT relocations:")
    for i in range(rela_plt['size'] // rela_plt['entsize']):
        rel_off = rela_plt['offset'] + i * rela_plt['entsize']
        r_offset = struct.unpack_from("<Q", data, rel_off)[0]
        r_info = struct.unpack_from("<Q", data, rel_off + 8)[0]
        r_addend = struct.unpack_from("<q", data, rel_off + 16)[0]

        sym_idx = r_info >> 32
        rel_type = r_info & 0xFFFFFFFF

        sym_off = dynsym['offset'] + sym_idx * dynsym['entsize']
        st_name = struct.unpack_from("<I", data, sym_off)[0]
        name_end = data.find(b'\x00', dynstr['offset'] + st_name)
        name = data[dynstr['offset'] + st_name:name_end].decode('ascii', errors='replace')

        if any(x in name for x in ['wl_proxy', 'xdg_', 'abort', 'assert', 'wl_display', 'marshal', '__android_log']):
            print(f"  GOT[0x{r_offset:x}] -> {name} (sym={sym_idx}, type={rel_type})")

# Now find what's at PLT addresses we care about
print(f"\nKey BL targets from hwc_wayland_thread:")
targets = {
    0x66060: "0x3f184 call",
    0x66140: "0x3f188 CRASH call",
    0x66a40: "0x3f154 main loop",
    0x66610: "0x3f14c init call",
    0x664f0: "0x3f160 call"
}
plt = sections.get('.plt', {})
for addr, desc in sorted(targets.items()):
    print(f"  0x{addr:x} ({desc}):")
    # Read the PLT stub - it usually does ADRP + LDR + BR
    if addr < len(data):
        inst0 = struct.unpack_from("<I", data, addr)[0]
        inst1 = struct.unpack_from("<I", data, addr+4)[0]
        inst2 = struct.unpack_from("<I", data, addr+8)[0]
        print(f"    {inst0:08x} {inst1:08x} {inst2:08x}")
        # ADRP: bits [32:24] = 1x010000, immhi = [23:5], immlo = [30:29]
        if (inst0 >> 24) & 0x9f == 0x90:  # ADRP
            immlo = (inst0 >> 29) & 3
            immhi = (inst0 >> 5) & 0x7FFFF
            imm = ((immhi << 2) | immlo) << 12
            if imm & 0x100000000:
                imm |= ~0x1FFFFFFFF
            page = (addr & ~0xFFF) + imm
            # LDR: offset from register
            if (inst1 >> 22) & 0x3FF == 0x3E5:  # LDR Xt, [Xn, #imm]
                ldr_off = ((inst1 >> 10) & 0xFFF) << 3
                got_entry = page + ldr_off
                print(f"    -> GOT entry at 0x{got_entry:x}")
