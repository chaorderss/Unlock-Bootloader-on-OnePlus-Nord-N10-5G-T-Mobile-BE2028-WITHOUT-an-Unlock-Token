#!/usr/bin/env python3
"""Check ELF segment permissions for code cave location"""
import struct

with open('/Users/xmxx/pinganhuijia/tmp/hwc.so', 'rb') as f:
    data = f.read()

# Parse ELF program headers (for segment permissions)
e_phoff = struct.unpack_from('<Q', data, 32)[0]
e_phentsize = struct.unpack_from('<H', data, 54)[0]
e_phnum = struct.unpack_from('<H', data, 56)[0]

print("=== ELF Program Headers (Segments) ===")
PF_X = 1
PF_W = 2
PF_R = 4

cave_addr = 0x036368
call_addr = 0x03dd18

for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type = struct.unpack_from('<I', data, off)[0]
    p_flags = struct.unpack_from('<I', data, off + 4)[0]
    p_offset = struct.unpack_from('<Q', data, off + 8)[0]
    p_vaddr = struct.unpack_from('<Q', data, off + 16)[0]
    p_paddr = struct.unpack_from('<Q', data, off + 24)[0]
    p_filesz = struct.unpack_from('<Q', data, off + 32)[0]
    p_memsz = struct.unpack_from('<Q', data, off + 40)[0]

    types = {1: 'LOAD', 2: 'DYNAMIC', 4: 'NOTE', 6: 'PHDR', 7: 'TLS',
             0x6474e550: 'GNU_EH_FRAME', 0x6474e551: 'GNU_STACK',
             0x6474e552: 'GNU_RELRO', 0x70000001: 'EXIDX'}
    tname = types.get(p_type, f'0x{p_type:x}')

    flags_str = ""
    if p_flags & PF_R: flags_str += "R"
    if p_flags & PF_W: flags_str += "W"
    if p_flags & PF_X: flags_str += "X"

    end_offset = p_offset + p_filesz

    marker = ""
    if p_offset <= cave_addr < end_offset:
        marker += " ← CAVE IS HERE"
    if p_offset <= call_addr < end_offset:
        marker += " ← CALL SITE IS HERE"

    print(f"  [{tname:15s}] offset=0x{p_offset:06x}-0x{end_offset:06x} "
          f"vaddr=0x{p_vaddr:06x} memsz=0x{p_memsz:06x} "
          f"flags={flags_str:3s}{marker}")

# Also check section mapping
e_shoff = struct.unpack_from('<Q', data, 40)[0]
e_shentsize = struct.unpack_from('<H', data, 58)[0]
e_shnum = struct.unpack_from('<H', data, 60)[0]
e_shstrndx = struct.unpack_from('<H', data, 62)[0]

shstrtab_off = e_shoff + e_shstrndx * e_shentsize
shstrtab_data_off = struct.unpack_from('<Q', data, shstrtab_off + 24)[0]
shstrtab_data_sz = struct.unpack_from('<Q', data, shstrtab_off + 32)[0]

print("\n=== Section covering code cave (0x036368) ===")
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    sh_name_off = struct.unpack_from('<I', data, off)[0]
    sh_type = struct.unpack_from('<I', data, off + 4)[0]
    sh_flags = struct.unpack_from('<Q', data, off + 8)[0]
    sh_addr = struct.unpack_from('<Q', data, off + 16)[0]
    sh_offset = struct.unpack_from('<Q', data, off + 24)[0]
    sh_size = struct.unpack_from('<Q', data, off + 32)[0]

    name_end = data.find(b'\0', shstrtab_data_off + sh_name_off)
    name = data[shstrtab_data_off + sh_name_off:name_end].decode()

    end = sh_offset + sh_size

    SHF_ALLOC = 2
    SHF_EXEC = 4
    SHF_WRITE = 1

    flags_str = ""
    if sh_flags & SHF_ALLOC: flags_str += "A"
    if sh_flags & SHF_WRITE: flags_str += "W"
    if sh_flags & SHF_EXEC: flags_str += "X"

    marker = ""
    if sh_offset <= cave_addr < end:
        marker = " ← CAVE"
    if sh_offset <= call_addr < end:
        marker += " ← CALL"

    if marker:
        print(f"  [{name:20s}] offset=0x{sh_offset:06x}-0x{end:06x} flags={flags_str:3s}{marker}")

# For context, show sections around the cave
print("\n=== All sections (sorted by offset) ===")
sec_list = []
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    sh_name_off = struct.unpack_from('<I', data, off)[0]
    sh_type = struct.unpack_from('<I', data, off + 4)[0]
    sh_flags = struct.unpack_from('<Q', data, off + 8)[0]
    sh_offset = struct.unpack_from('<Q', data, off + 24)[0]
    sh_size = struct.unpack_from('<Q', data, off + 32)[0]

    name_end = data.find(b'\0', shstrtab_data_off + sh_name_off)
    name = data[shstrtab_data_off + sh_name_off:name_end].decode()

    SHF_ALLOC = 2
    SHF_EXEC = 4
    SHF_WRITE = 1

    flags_str = ""
    if sh_flags & SHF_ALLOC: flags_str += "A"
    if sh_flags & SHF_WRITE: flags_str += "W"
    if sh_flags & SHF_EXEC: flags_str += "X"

    sec_list.append((sh_offset, sh_size, name, flags_str))

for sh_offset, sh_size, name, flags_str in sorted(sec_list):
    if sh_size > 0:
        marker = ""
        end = sh_offset + sh_size
        if sh_offset <= 0x036368 < end: marker = " <<<CAVE"
        if sh_offset <= 0x03dd18 < end: marker += " <<<CALL"
        if 0x030000 <= sh_offset <= 0x070000 or marker:
            print(f"  0x{sh_offset:06x}-0x{end:06x} {name:20s} {flags_str:3s} {sh_size:6d}{marker}")
