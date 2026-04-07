#!/usr/bin/env python3
"""Analyze relocations for wlan_drv_ops and wlan_mon_drv_ops"""
import struct

with open('/Users/xmxx/pinganhuijia/tmp/qca_cld3_wlan.ko', 'rb') as f:
    data = f.read()

e_shoff = struct.unpack_from('<Q', data, 40)[0]
e_shentsize = struct.unpack_from('<H', data, 58)[0]
e_shnum = struct.unpack_from('<H', data, 60)[0]
e_shstrndx = struct.unpack_from('<H', data, 62)[0]

shstr_sh = e_shoff + e_shstrndx * e_shentsize
shstr_off = struct.unpack_from('<Q', data, shstr_sh + 24)[0]

def get_section_name(idx):
    sh = e_shoff + idx * e_shentsize
    name_off = struct.unpack_from('<I', data, sh)[0]
    start = shstr_off + name_off
    end = data.index(b'\x00', start)
    return data[start:end].decode('ascii', errors='replace')

def get_section_info(idx):
    sh = e_shoff + idx * e_shentsize
    return {
        'name': get_section_name(idx),
        'type': struct.unpack_from('<I', data, sh + 4)[0],
        'flags': struct.unpack_from('<Q', data, sh + 8)[0],
        'addr': struct.unpack_from('<Q', data, sh + 16)[0],
        'offset': struct.unpack_from('<Q', data, sh + 24)[0],
        'size': struct.unpack_from('<Q', data, sh + 32)[0],
        'link': struct.unpack_from('<I', data, sh + 40)[0],
        'info': struct.unpack_from('<I', data, sh + 44)[0],
        'entsize': struct.unpack_from('<Q', data, sh + 56)[0],
        'idx': idx,
    }

# Build section map
sections = {}
section_list = []
for i in range(e_shnum):
    info = get_section_info(i)
    sections[info['name']] = info
    section_list.append(info)

# Symtab + strtab
symtab = sections['.symtab']
strtab = sections['.strtab']

def get_sym_name(st_name):
    start = strtab['offset'] + st_name
    end = data.index(b'\x00', start)
    return data[start:end].decode('ascii', errors='replace')

def get_sym(idx):
    off = symtab['offset'] + idx * symtab['entsize']
    st_name = struct.unpack_from('<I', data, off)[0]
    st_info = data[off + 4]
    st_other = data[off + 5]
    st_shndx = struct.unpack_from('<H', data, off + 6)[0]
    st_value = struct.unpack_from('<Q', data, off + 8)[0]
    st_size = struct.unpack_from('<Q', data, off + 16)[0]
    return {
        'name': get_sym_name(st_name),
        'info': st_info,
        'shndx': st_shndx,
        'value': st_value,
        'size': st_size,
        'idx': idx,
    }

num_syms = symtab['size'] // symtab['entsize']

# Find key symbols
target_syms = {}
for i in range(num_syms):
    sym = get_sym(i)
    if sym['name'] in ('wlan_mon_drv_ops', 'hdd_mon_open', 'hdd_stop',
                         'hdd_hard_start_xmit', 'hdd_mon_hard_start_xmit',
                         'wlan_hdd_txrx_stypes'):
        target_syms[sym['name']] = sym
        print(f"Symbol: {sym['name']}, shndx={sym['shndx']}, value=0x{sym['value']:x}, size=0x{sym['size']:x}, idx={sym['idx']}")
    if 'mon_drv_ops' in sym['name'] or 'mon_hard' in sym['name'] or 'hdd_hard_start' in sym['name']:
        if sym['name'] not in target_syms:
            target_syms[sym['name']] = sym
            print(f"Symbol: {sym['name']}, shndx={sym['shndx']}, value=0x{sym['value']:x}, size=0x{sym['size']:x}, idx={sym['idx']}")

# Find .rela.rodata section
print("\n=== Relocation Sections ===")
rela_sections = []
for s in section_list:
    if s['name'].startswith('.rela'):
        rela_sections.append(s)
        applies_to = get_section_name(s['info']) if s['info'] < e_shnum else f"idx={s['info']}"
        print(f"  {s['name']}: offset=0x{s['offset']:x}, size=0x{s['size']:x}, entsize={s['entsize']}, applies_to={applies_to}")

# wlan_mon_drv_ops is in .rodata at value 0x5f10
# So relocations in .rela.rodata targeting offset range [0x5f10, 0x5f10+0x200) are its entries
# wlan_drv_ops is in .rodata at value 0x6110
# So relocations in .rela.rodata targeting offset [0x6110, 0x6110+0x200) are its entries

# Find .rela.rodata
rela_rodata = None
for s in rela_sections:
    if s['info'] < e_shnum:
        target_sec = get_section_name(s['info'])
        if target_sec == '.rodata':
            rela_rodata = s
            break

if not rela_rodata:
    print("ERROR: No .rela.rodata found!")
    exit(1)

print(f"\n=== .rela.rodata: offset=0x{rela_rodata['offset']:x}, size=0x{rela_rodata['size']:x}, entsize={rela_rodata['entsize']} ===")

# R_AARCH64_ABS64 = 257
R_AARCH64_ABS64 = 257

# Parse relocations for wlan_mon_drv_ops and wlan_drv_ops
print(f"\n=== Relocations for wlan_mon_drv_ops (rodata 0x5f10-0x6110) ===")
mon_relas = []
num_relas = rela_rodata['size'] // rela_rodata['entsize']
print(f"  Total rela entries: {num_relas}")

for i in range(num_relas):
    roff = rela_rodata['offset'] + i * rela_rodata['entsize']
    r_offset = struct.unpack_from('<Q', data, roff)[0]
    r_info = struct.unpack_from('<Q', data, roff + 8)[0]
    r_addend = struct.unpack_from('<q', data, roff + 16)[0]  # signed

    r_sym = r_info >> 32
    r_type = r_info & 0xffffffff

    if 0x5f10 <= r_offset < 0x6110:
        sym = get_sym(r_sym)
        field_off = r_offset - 0x5f10
        print(f"  offset=0x{r_offset:x} (field +0x{field_off:x}): type={r_type}, sym={sym['name']} (idx={r_sym}), addend=0x{r_addend:x}")
        mon_relas.append({'offset': r_offset, 'sym': sym, 'r_type': r_type, 'r_addend': r_addend, 'field_off': field_off, 'rela_file_off': roff})

print(f"\n=== Relocations for wlan_drv_ops (rodata 0x6110-0x6310) ===")
drv_relas = []
for i in range(num_relas):
    roff = rela_rodata['offset'] + i * rela_rodata['entsize']
    r_offset = struct.unpack_from('<Q', data, roff)[0]
    r_info = struct.unpack_from('<Q', data, roff + 8)[0]
    r_addend = struct.unpack_from('<q', data, roff + 16)[0]

    r_sym = r_info >> 32
    r_type = r_info & 0xffffffff

    if 0x6110 <= r_offset < 0x6310:
        sym = get_sym(r_sym)
        field_off = r_offset - 0x6110
        print(f"  offset=0x{r_offset:x} (field +0x{field_off:x}): type={r_type}, sym={sym['name']} (idx={r_sym}), addend=0x{r_addend:x}")
        drv_relas.append({'offset': r_offset, 'sym': sym, 'r_type': r_type, 'r_addend': r_addend, 'field_off': field_off, 'rela_file_off': roff})

# Identify key fields
print("\n=== Key net_device_ops fields ===")
ndo_fields = {
    0x10: 'ndo_open',
    0x18: 'ndo_stop',
    0x20: 'ndo_start_xmit',
    0x30: 'ndo_select_queue',
    0x40: 'ndo_set_rx_mode',
    0x48: 'ndo_set_mac_address',
    0x68: 'ndo_do_ioctl',
    0x88: 'ndo_change_mtu',
    0xd8: 'ndo_set_features',
}

print("\nwlan_drv_ops fields:")
for r in drv_relas:
    fname = ndo_fields.get(r['field_off'], f'+0x{r["field_off"]:x}')
    print(f"  {fname}: {r['sym']['name']}")

print("\nwlan_mon_drv_ops fields:")
for r in mon_relas:
    fname = ndo_fields.get(r['field_off'], f'+0x{r["field_off"]:x}')
    print(f"  {fname}: {r['sym']['name']}")

# Find the xmit symbol idx for creating new relocation
print(f"\n=== Summary for patching ===")
xmit_rela = None
for r in drv_relas:
    if r['field_off'] == 0x20:
        xmit_rela = r
        print(f"wlan_drv_ops ndo_start_xmit relocation:")
        print(f"  rela file offset: 0x{r['rela_file_off']:x}")
        print(f"  target: offset=0x{r['offset']:x}")
        print(f"  sym: {r['sym']['name']} (idx={r['sym']['idx']})")
        print(f"  type: {r['r_type']}")
        print(f"  addend: 0x{r['r_addend']:x}")

# Check if there's a hdd_mon_hard_start_xmit
if 'hdd_mon_hard_start_xmit' in target_syms:
    s = target_syms['hdd_mon_hard_start_xmit']
    print(f"\nhdd_mon_hard_start_xmit found: idx={s['idx']}, value=0x{s['value']:x}")
