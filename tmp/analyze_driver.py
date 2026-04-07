#!/usr/bin/env python3
"""
Analyze qca_cld3_wlan.ko ELF relocations for wlan_mon_drv_ops and wlan_drv_ops.
Find how ndo_start_xmit is referenced in wlan_drv_ops and create a similar
relocation for wlan_mon_drv_ops.
"""
import struct
import sys

KO_FILE = "/Users/xmxx/pinganhuijia/tmp/qca_cld3_wlan.ko"

# From readelf -S
RODATA_OFFSET = 0x30a598
RODATA_SIZE = 0x29bd8
RELA_RODATA_OFFSET = 0x969260
RELA_RODATA_SIZE = 0x157b0

# From readelf -s
WLAN_MON_DRV_OPS_RODATA_OFF = 0x5f10   # offset within .rodata section
WLAN_DRV_OPS_RODATA_OFF = 0x6110       # offset within .rodata section

# net_device_ops layout (aarch64, 64-bit pointers):
# See include/linux/netdevice.h in 4.19 kernel
# ndo_open = +0x00 (but after init, uninit, destructor in newer kernels)
# Actually the layout depends on kernel version. Let's discover from relocations.

def read_elf64_header(data):
    fields = struct.unpack_from('<16sHHIQQQIHHHHHH', data, 0)
    return {
        'e_ident': fields[0],
        'e_type': fields[1],
        'e_machine': fields[2],
        'e_version': fields[3],
        'e_entry': fields[4],
        'e_phoff': fields[5],
        'e_shoff': fields[6],
        'e_flags': fields[7],
        'e_ehsize': fields[8],
        'e_phentsize': fields[9],
        'e_phnum': fields[10],
        'e_shentsize': fields[11],
        'e_shnum': fields[12],
        'e_shstrndx': fields[13],
    }

def read_section_headers(data, ehdr):
    sections = []
    for i in range(ehdr['e_shnum']):
        off = ehdr['e_shoff'] + i * ehdr['e_shentsize']
        fields = struct.unpack_from('<IIQQQQIIQQQ', data, off)[:11]
        sections.append({
            'sh_name': fields[0],
            'sh_type': fields[1],
            'sh_flags': fields[2],
            'sh_addr': fields[3],
            'sh_offset': fields[4],
            'sh_size': fields[5],
            'sh_link': fields[6],
            'sh_info': fields[7],
            'sh_addralign': fields[8],
            'sh_entsize': fields[9] if len(fields) > 9 else 0,
        })
    return sections

def read_symbols(data, symtab_offset, symtab_size, strtab_offset, strtab_size):
    """Read ELF64 symbol table"""
    symbols = []
    entry_size = 24  # sizeof(Elf64_Sym)
    count = symtab_size // entry_size
    for i in range(count):
        off = symtab_offset + i * entry_size
        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from('<IBBHQQ', data, off)
        # Get name
        name = ""
        if st_name > 0 and st_name < strtab_size:
            end = data.index(b'\x00', strtab_offset + st_name)
            name = data[strtab_offset + st_name:end].decode('utf-8', errors='replace')
        symbols.append({
            'index': i,
            'name': name,
            'info': st_info,
            'other': st_other,
            'shndx': st_shndx,
            'value': st_value,
            'size': st_size,
            'bind': st_info >> 4,
            'type': st_info & 0xf,
        })
    return symbols

def get_section_name(data, shstrtab_offset, name_offset):
    end = data.index(b'\x00', shstrtab_offset + name_offset)
    return data[shstrtab_offset + name_offset:end].decode('utf-8', errors='replace')

with open(KO_FILE, 'rb') as f:
    data = f.read()

ehdr = read_elf64_header(data)
sections = read_section_headers(data, ehdr)

# Get section string table
shstrtab = sections[ehdr['e_shstrndx']]
shstrtab_offset = shstrtab['sh_offset']

# Print section names
print("=== Sections ===")
for i, sec in enumerate(sections):
    name = get_section_name(data, shstrtab_offset, sec['sh_name'])
    if name in ['.rodata', '.rela.rodata', '.symtab', '.strtab',
                '.text', '.data', '.bss']:
        print(f"  [{i:2d}] {name:20s} offset=0x{sec['sh_offset']:08x} size=0x{sec['sh_size']:08x} "
              f"link={sec['sh_link']} info={sec['sh_info']}")

# Find .rodata and .rela.rodata sections by name
rodata_sec = None
rela_rodata_sec = None
symtab_sec = None
strtab_sec = None

for i, sec in enumerate(sections):
    name = get_section_name(data, shstrtab_offset, sec['sh_name'])
    if name == '.rodata':
        rodata_sec = sec
        rodata_idx = i
    elif name == '.rela.rodata':
        rela_rodata_sec = sec
    elif name == '.symtab':
        symtab_sec = sec
    elif name == '.strtab':
        strtab_sec = sec

# Read symbol table
symbols = read_symbols(data, symtab_sec['sh_offset'], symtab_sec['sh_size'],
                        strtab_sec['sh_offset'], strtab_sec['sh_size'])

# Find key symbols
print("\n=== Key Symbols ===")
sym_map = {}
for sym in symbols:
    if sym['name'] in ['hdd_hard_start_xmit', 'hdd_mon_open', 'hdd_stop',
                        'hdd_select_queue', 'hdd_set_mac_address',
                        'wlan_hdd_change_mtu']:
        print(f"  [{sym['index']:5d}] {sym['name']:30s} value=0x{sym['value']:08x} "
              f"size={sym['size']:4d} bind={'G' if sym['bind'] else 'L'} "
              f"section={sym['shndx']}")
        sym_map[sym['name']] = sym

# Read .rela.rodata entries
print(f"\n=== .rela.rodata: {rela_rodata_sec['sh_size'] // 24} entries ===")

# Filter relocations for wlan_drv_ops range (0x6110 to 0x6310)
# and wlan_mon_drv_ops range (0x5f10 to 0x6110)
print(f"\n--- wlan_mon_drv_ops (0x5f10-0x6110) relocations ---")
mon_relocs = []
for i in range(rela_rodata_sec['sh_size'] // 24):
    off = rela_rodata_sec['sh_offset'] + i * 24
    r_offset, r_info, r_addend = struct.unpack_from('<QQq', data, off)

    if 0x5f10 <= r_offset < 0x6110:
        sym_idx = r_info >> 32
        r_type = r_info & 0xffffffff
        sym_name = symbols[sym_idx]['name'] if sym_idx < len(symbols) else '?'
        field_off = r_offset - 0x5f10
        print(f"  [rela #{i:5d}] offset=0x{r_offset:06x} (+0x{field_off:03x}) "
              f"type=0x{r_type:04x} sym=[{sym_idx}]={sym_name} "
              f"addend=0x{r_addend:x}")
        mon_relocs.append((i, r_offset, r_info, r_addend, sym_name))

print(f"\n--- wlan_drv_ops (0x6110-0x6310) relocations ---")
drv_relocs = []
for i in range(rela_rodata_sec['sh_size'] // 24):
    off = rela_rodata_sec['sh_offset'] + i * 24
    r_offset, r_info, r_addend = struct.unpack_from('<QQq', data, off)

    if 0x6110 <= r_offset < 0x6310:
        sym_idx = r_info >> 32
        r_type = r_info & 0xffffffff
        sym_name = symbols[sym_idx]['name'] if sym_idx < len(symbols) else '?'
        field_off = r_offset - 0x6110
        print(f"  [rela #{i:5d}] offset=0x{r_offset:06x} (+0x{field_off:03x}) "
              f"type=0x{r_type:04x} sym=[{sym_idx}]={sym_name} "
              f"addend=0x{r_addend:x}")
        drv_relocs.append((i, r_offset, r_info, r_addend, sym_name))

# Check what's at the ndo_start_xmit offset in wlan_mon_drv_ops
rodata_off = rodata_sec['sh_offset']
mon_xmit_file_off = rodata_off + 0x5f10 + 0x20
drv_xmit_file_off = rodata_off + 0x6110 + 0x20

print(f"\n=== Raw data at ndo_start_xmit slots ===")
mon_val = struct.unpack_from('<Q', data, mon_xmit_file_off)[0]
drv_val = struct.unpack_from('<Q', data, drv_xmit_file_off)[0]
print(f"  wlan_mon_drv_ops[+0x20] = 0x{mon_val:016x} (file offset 0x{mon_xmit_file_off:08x})")
print(f"  wlan_drv_ops[+0x20]     = 0x{drv_val:016x} (file offset 0x{drv_xmit_file_off:08x})")

# Show full structure comparison
print(f"\n=== Full ops comparison (first 320 bytes = 40 pointers) ===")
print(f"{'Offset':>8} {'mon_ops':>18} {'drv_ops':>18}  mon_sym / drv_sym")
for ptr_idx in range(40):
    ptr_off = ptr_idx * 8
    mon_file = rodata_off + 0x5f10 + ptr_off
    drv_file = rodata_off + 0x6110 + ptr_off
    mon_v = struct.unpack_from('<Q', data, mon_file)[0]
    drv_v = struct.unpack_from('<Q', data, drv_file)[0]

    # Find relocation names
    mon_sym_name = "-"
    drv_sym_name = "-"
    for _, ro, ri, ra, rn in mon_relocs:
        if ro == 0x5f10 + ptr_off:
            mon_sym_name = rn
    for _, ro, ri, ra, rn in drv_relocs:
        if ro == 0x6110 + ptr_off:
            drv_sym_name = rn

    marker = " ***" if (mon_sym_name == "-" and drv_sym_name != "-") else ""
    if mon_sym_name != "-" or drv_sym_name != "-" or mon_v != 0 or drv_v != 0:
        print(f"  +0x{ptr_off:03x}  0x{mon_v:016x}  0x{drv_v:016x}  {mon_sym_name} / {drv_sym_name}{marker}")

# Find the hdd_hard_start_xmit symbol index
xmit_sym = None
for sym in symbols:
    if sym['name'] == 'hdd_hard_start_xmit':
        xmit_sym = sym
        break

if xmit_sym:
    print(f"\n=== hdd_hard_start_xmit ===")
    print(f"  Symbol index: {xmit_sym['index']}")
    print(f"  Value: 0x{xmit_sym['value']:08x}")
    print(f"  Size: {xmit_sym['size']}")
    print(f"  Section: {xmit_sym['shndx']}")

# Find the relocation for drv_ops ndo_start_xmit to understand the pattern
print(f"\n=== Relocation pattern for drv_ops ndo_start_xmit ===")
for idx, r_off, r_info, r_addend, sym_name in drv_relocs:
    if r_off == 0x6110 + 0x20:  # ndo_start_xmit in drv_ops
        sym_idx = r_info >> 32
        r_type = r_info & 0xffffffff
        print(f"  rela entry index: {idx}")
        print(f"  r_offset: 0x{r_off:08x}")
        print(f"  r_info: 0x{r_info:016x}")
        print(f"    sym_idx: {sym_idx}")
        print(f"    type: 0x{r_type:08x} (R_AARCH64_ABS64 = 0x101)")
        print(f"  r_addend: 0x{r_addend:x}")
        print(f"  symbol: {sym_name}")
        print(f"  File offset of this rela entry: 0x{rela_rodata_sec['sh_offset'] + idx * 24:08x}")
