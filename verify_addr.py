#!/usr/bin/env python3
import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin','rb').read()

print("=== Verifying address mapping ===")
# Test which mapping is correct for the string at disasm 0x65e19
for candidate in [0x65e19, 0x66e19]:
    s = data[candidate:candidate+50]
    null_pos = s.find(b'\x00')
    if null_pos >= 0: s = s[:null_pos]
    print(f'  file[0x{candidate:x}]: {s}')

print()
print("=== PE section headers ===")
pe_sig_offset = int.from_bytes(data[0x3c:0x40], 'little')
print(f'PE signature at file offset: 0x{pe_sig_offset:x}')
print(f'PE sig: {data[pe_sig_offset:pe_sig_offset+4]}')
num_sections = int.from_bytes(data[pe_sig_offset+0x6:pe_sig_offset+0x8], 'little')
opt_header_size = int.from_bytes(data[pe_sig_offset+0x14:pe_sig_offset+0x16], 'little')
image_base = int.from_bytes(data[pe_sig_offset+0x30:pe_sig_offset+0x38], 'little')
print(f'ImageBase: 0x{image_base:x}')
section_start = pe_sig_offset + 0x18 + opt_header_size
print(f'Num sections: {num_sections}, section headers at: 0x{section_start:x}')
for i in range(num_sections):
    s = section_start + i * 40
    name = data[s:s+8].rstrip(b'\x00').decode('ascii', errors='replace')
    vsize = int.from_bytes(data[s+8:s+12], 'little')
    vaddr = int.from_bytes(data[s+12:s+16], 'little')
    raw_size = int.from_bytes(data[s+16:s+20], 'little')
    raw_off = int.from_bytes(data[s+20:s+24], 'little')
    print(f'  {name}: VAddr=0x{vaddr:x}  FileOff=0x{raw_off:x}  VSize=0x{vsize:x}  delta={raw_off-vaddr:d}')

print()
print("=== Find callers of function at file 0x49bf8 (with ANY address in data sections) ===")
# Search ALL 8-byte and 4-byte values in binary for 0x48bf8 (disasm addr)
target_disasm = 0x48bf8
target_file = 0x49bf8
count = 0
for i in range(0, len(data)-8, 4):
    v8 = struct.unpack_from('<Q', data, i)[0]
    if v8 == target_disasm or v8 == target_file:
        print(f'  8-byte ref at file 0x{i:x}: 0x{v8:x}')
        count += 1
    v4 = struct.unpack_from('<I', data, i)[0]
    if v4 == target_disasm or v4 == target_file:
        print(f'  4-byte ref at file 0x{i:x}: 0x{v4:x}')
        count += 1
print(f'Total references: {count}')
