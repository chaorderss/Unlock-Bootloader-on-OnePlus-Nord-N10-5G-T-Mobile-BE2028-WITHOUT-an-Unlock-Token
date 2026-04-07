#!/usr/bin/env python3
"""Parse QDSP6 ELF firmware binary"""
import struct, sys

with open("wlanmdsp.mbn", "rb") as f:
    data = f.read()

print(f"File size: {len(data)} bytes ({len(data)/1024:.1f} KB)")

# ELF header
e_ident = data[:16]
e_type, e_machine = struct.unpack_from('<HH', data, 16)
e_version, e_entry, e_phoff, e_shoff, e_flags = struct.unpack_from('<IIIII', data, 20)
e_ehsize, e_phentsize, e_phnum = struct.unpack_from('<HHH', data, 40)
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', data, 46)

print(f"\n=== ELF Header ===")
print(f"Type: {e_type} ({'EXEC' if e_type==2 else 'other'})")
print(f"Machine: 0x{e_machine:x} ({'QDSP6/Hexagon' if e_machine==0xa4 else 'other'})")
print(f"Entry: 0x{e_entry:08x}")
print(f"PH offset: 0x{e_phoff:x}, entry size: {e_phentsize}, count: {e_phnum}")
print(f"Flags: 0x{e_flags:08x}")

pt_types = {0: "NULL", 1: "LOAD", 2: "DYNAMIC", 6: "PHDR", 4: "NOTE",
            0x6474e551: "GNU_STACK", 0x6474e550: "GNU_EH_FRAME"}

print(f"\n=== Program Headers ===")
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
        struct.unpack_from('<IIIIIIII', data, off)

    tname = pt_types.get(p_type, f"0x{p_type:08x}")
    prot = ""
    if p_flags & 4: prot += "R"
    if p_flags & 2: prot += "W"
    if p_flags & 1: prot += "X"

    print(f"\n  PH[{i}] type={tname}")
    print(f"    offset=0x{p_offset:08x}  filesz=0x{p_filesz:08x}")
    print(f"    vaddr=0x{p_vaddr:08x}   paddr=0x{p_paddr:08x}")
    print(f"    memsz=0x{p_memsz:08x}   flags=0x{p_flags:08x} ({prot})")
    print(f"    align=0x{p_align:x}")

    # Show first 32 bytes of segment content
    if p_filesz > 0 and p_offset + min(p_filesz, 32) <= len(data):
        preview = data[p_offset:p_offset+min(p_filesz, 32)]
        hex_str = ' '.join(f'{b:02x}' for b in preview)
        print(f"    preview: {hex_str}")

# Check for Qualcomm hash segment
print(f"\n=== Qualcomm MBN Analysis ===")
# The NULL segment with filesz=0x114 is MBN metadata (hash table header)
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
        struct.unpack_from('<IIIIIIII', data, off)
    if p_type == 1:  # LOAD segments
        end = p_offset + p_filesz
        print(f"  LOAD segment {i}: file[0x{p_offset:08x}-0x{end:08x}] -> vaddr 0x{p_vaddr:08x} ({p_filesz} bytes)")
