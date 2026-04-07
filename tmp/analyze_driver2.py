#!/usr/bin/env python3
"""Analyze qca_cld3_wlan.ko to find and dump wlan_hdd_txrx_stypes"""
import struct, sys

with open('/Users/xmxx/pinganhuijia/tmp/qca_cld3_wlan.ko', 'rb') as f:
    data = f.read()

# Parse ELF64 header
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
        'entsize': struct.unpack_from('<Q', data, sh + 56)[0],
    }

sections = {}
for i in range(e_shnum):
    info = get_section_info(i)
    sections[info['name']] = {**info, 'idx': i}

symtab = sections['.symtab']
strtab = sections['.strtab']

def get_sym_name(st_name):
    start = strtab['offset'] + st_name
    end = data.index(b'\x00', start)
    return data[start:end].decode('ascii', errors='replace')

num_syms = symtab['size'] // symtab['entsize']

for i in range(num_syms):
    off = symtab['offset'] + i * symtab['entsize']
    st_name = struct.unpack_from('<I', data, off)[0]
    st_info = data[off + 4]
    st_shndx = struct.unpack_from('<H', data, off + 6)[0]
    st_value = struct.unpack_from('<Q', data, off + 8)[0]
    st_size = struct.unpack_from('<Q', data, off + 16)[0]
    name = get_sym_name(st_name)

    if 'txrx_stypes' in name or 'mon_drv_ops' in name or name == 'wlan_drv_ops':
        sec_info = get_section_info(st_shndx) if st_shndx < e_shnum else None
        sec_name = sec_info['name'] if sec_info else f'shndx={st_shndx}'
        file_off = sec_info['offset'] + st_value if sec_info else 0
        print(f'Symbol: {name}')
        print(f'  section={sec_name}, value=0x{st_value:x}, size=0x{st_size:x}, file_off=0x{file_off:x}')
        if sec_info and st_size > 0 and st_size < 4096:
            sym_data = data[file_off:file_off+st_size]
            for j in range(0, st_size, 16):
                chunk = sym_data[j:j+16]
                hex_str = ' '.join(f'{b:02x}' for b in chunk)
                print(f'  0x{j:04x}: {hex_str}')
        print()

# Parse txrx_stypes array
print("=== Parsing txrx_stypes array ===")
for i in range(num_syms):
    off = symtab['offset'] + i * symtab['entsize']
    st_name_idx = struct.unpack_from('<I', data, off)[0]
    st_shndx = struct.unpack_from('<H', data, off + 6)[0]
    st_value = struct.unpack_from('<Q', data, off + 8)[0]
    st_size = struct.unpack_from('<Q', data, off + 16)[0]
    name = get_sym_name(st_name_idx)

    if name == 'wlan_hdd_txrx_stypes':
        sec_info = get_section_info(st_shndx)
        file_off = sec_info['offset'] + st_value

        iftype_names = {
            0: 'UNSPECIFIED', 1: 'ADHOC', 2: 'STATION', 3: 'AP',
            4: 'AP_VLAN', 5: 'WDS', 6: 'MONITOR', 7: 'MESH_POINT',
            8: 'P2P_CLIENT', 9: 'P2P_GO', 10: 'P2P_DEVICE',
            11: 'OCB', 12: 'NAN'
        }
        frame_subtypes = {
            0: 'AssocReq', 1: 'AssocResp', 2: 'ReassocReq', 3: 'ReassocResp',
            4: 'ProbeReq', 5: 'ProbeResp', 6: 'TimingAdv', 7: 'Beacon',
            8: 'ATIM', 9: 'Disassoc', 10: 'Auth', 11: 'Deauth',
            12: 'Action', 13: 'ActionNoAck'
        }
        num_entries = st_size // 4
        for j in range(num_entries):
            entry_off = file_off + j * 4
            tx = struct.unpack_from('<H', data, entry_off)[0]
            rx = struct.unpack_from('<H', data, entry_off + 2)[0]
            name_str = iftype_names.get(j, f'TYPE_{j}')
            tx_frames = [frame_subtypes.get(bit, f'bit{bit}') for bit in range(16) if tx & (1 << bit)]
            rx_frames = [frame_subtypes.get(bit, f'bit{bit}') for bit in range(16) if rx & (1 << bit)]
            marker = " <-- TARGET" if j == 6 else ""
            print(f'  [{j:2d}] {name_str:14s}: tx=0x{tx:04x} rx=0x{rx:04x}  file_off=0x{entry_off:x}{marker}')
            if tx_frames:
                print(f'       TX: {", ".join(tx_frames)}')
            if rx_frames:
                print(f'       RX: {", ".join(rx_frames)}')
        break

# Also find wlan_mon_drv_ops ndo_start_xmit
print("\n=== Analyzing wlan_mon_drv_ops vs wlan_drv_ops ===")
for i in range(num_syms):
    off = symtab['offset'] + i * symtab['entsize']
    st_name_idx = struct.unpack_from('<I', data, off)[0]
    st_shndx = struct.unpack_from('<H', data, off + 6)[0]
    st_value = struct.unpack_from('<Q', data, off + 8)[0]
    st_size = struct.unpack_from('<Q', data, off + 16)[0]
    name = get_sym_name(st_name_idx)

    if name in ('wlan_mon_drv_ops', 'wlan_drv_ops'):
        sec_info = get_section_info(st_shndx)
        file_off = sec_info['offset'] + st_value
        print(f'{name}: file_off=0x{file_off:x}, size=0x{st_size:x}')
        # net_device_ops: ndo_start_xmit is at offset 0x20 (64-bit pointers, 4th entry)
        # ndo_open at 0x10, ndo_stop at 0x18
        if st_size >= 0x28:
            ndo_open = struct.unpack_from('<Q', data, file_off + 0x10)[0]
            ndo_stop = struct.unpack_from('<Q', data, file_off + 0x18)[0]
            ndo_start_xmit = struct.unpack_from('<Q', data, file_off + 0x20)[0]
            print(f'  ndo_open=0x{ndo_open:x}, ndo_stop=0x{ndo_stop:x}, ndo_start_xmit=0x{ndo_start_xmit:x}')
