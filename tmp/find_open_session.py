#!/usr/bin/env python3
"""Find create_client_session and open_session in libmir1server to understand session naming"""
import struct

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

with open('/Users/xmxx/pinganhuijia/tmp/libmir1server.so', 'rb') as f:
    data = f.read()

print(f"Size: {len(data)} bytes")

# Parse ELF
e_shoff = struct.unpack_from('<Q', data, 40)[0]
e_shentsize = struct.unpack_from('<H', data, 58)[0]
e_shnum = struct.unpack_from('<H', data, 60)[0]
e_shstrndx = struct.unpack_from('<H', data, 62)[0]

sections = []
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    sh_name = struct.unpack_from('<I', data, off)[0]
    sh_type = struct.unpack_from('<I', data, off+4)[0]
    sh_addr = struct.unpack_from('<Q', data, off+16)[0]
    sh_offset = struct.unpack_from('<Q', data, off+24)[0]
    sh_size = struct.unpack_from('<Q', data, off+32)[0]
    sh_link = struct.unpack_from('<I', data, off+40)[0]
    sh_entsize = struct.unpack_from('<Q', data, off+56)[0]
    sections.append({'name_off': sh_name, 'type': sh_type, 'addr': sh_addr,
                     'offset': sh_offset, 'size': sh_size, 'link': sh_link, 'entsize': sh_entsize})

shstrtab = sections[e_shstrndx]
shstrtab_data = data[shstrtab['offset']:shstrtab['offset']+shstrtab['size']]

def get_sh_name(off):
    end = shstrtab_data.find(b'\0', off)
    return shstrtab_data[off:end].decode()

dynsym = dynstr = None
for s in sections:
    name = get_sh_name(s['name_off'])
    if name == '.dynsym': dynsym = s
    elif name == '.dynstr': dynstr = s

if dynsym and dynstr:
    dynstr_data = data[dynstr['offset']:dynstr['offset']+dynstr['size']]

    def get_dynstr(off):
        end = dynstr_data.find(b'\0', off)
        return dynstr_data[off:end].decode('ascii', errors='replace')

    entsize = dynsym['entsize'] or 24
    num_syms = dynsym['size'] // entsize

    print("\n=== Key dynamic symbols ===")
    for i in range(num_syms):
        sym_off = dynsym['offset'] + i * entsize
        st_name = struct.unpack_from('<I', data, sym_off)[0]
        st_value = struct.unpack_from('<Q', data, sym_off + 8)[0]
        st_size = struct.unpack_from('<Q', data, sym_off + 16)[0]
        name = get_dynstr(st_name)
        if st_value > 0 and any(k in name for k in ['open_session', 'create_client', 'WaylandConnector', 'wl_client_get', 'AbstractShell12open']):
            print(f"  0x{st_value:06x} [{st_size:5d}] {name}")

# Search for strings near the Wayland connector code
print("\n=== Strings related to session naming ===")
# In Mir 1.8.3 source, the Wayland connector creates sessions like:
# shell->open_session(client_pid, client_name, event_sink)
# where client_name might be empty or derived from PID
for s in [b'client_created', b'client_session', b'open_session', b'wl_client',
          b'Wayland client', b'pid:', b'@anonymous', b'', b'wayland_app']:
    if not s:
        continue
    idx = data.find(s)
    while idx >= 0 and idx < len(data):
        end = data.find(b'\0', idx)
        if end > idx:
            ctx = data[idx:min(end, idx+100)].decode('ascii', errors='replace')
            print(f"  0x{idx:06x}: {ctx}")
        idx = data.find(s, idx + 1)
        if idx > 0x250000:  # Only search in data/rodata
            break
