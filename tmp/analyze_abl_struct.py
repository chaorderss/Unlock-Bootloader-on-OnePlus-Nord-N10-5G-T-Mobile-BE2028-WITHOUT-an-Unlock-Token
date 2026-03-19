#!/usr/bin/env python3
"""Analyze ABL binary structure."""
import re, struct

with open('/tmp/abl_a.bin', 'rb') as f:
    data = f.read()

print(f"ABL size: {len(data)} bytes")
print(f"First 64 bytes: {data[:64].hex()}")

# Look for common binary formats
idx = data.find(b'\x7fELF')
if idx >= 0:
    print(f"ELF header at offset 0x{idx:X}")

idx = data.find(b'MZ')
if idx >= 0:
    print(f"PE header at offset 0x{idx:X}")

for m in re.finditer(b'_FVH', data):
    print(f"_FVH at offset 0x{m.start():X}")

# Find non-zero regions
block_size = 0x1000
nz_blocks = []
for i in range(0, len(data), block_size):
    chunk = data[i:i+block_size]
    if any(b != 0 for b in chunk):
        nz_blocks.append(i)

print(f"\nNon-zero 4K blocks: {len(nz_blocks)} out of {len(data)//block_size}")
if nz_blocks:
    print(f"First at 0x{nz_blocks[0]:X}, last at 0x{nz_blocks[-1]:X}")
    # Show ranges of non-zero regions
    ranges = []
    start = nz_blocks[0]
    prev = nz_blocks[0]
    for b in nz_blocks[1:]:
        if b != prev + block_size:
            ranges.append((start, prev + block_size))
            start = b
        prev = b
    ranges.append((start, prev + block_size))
    print("Non-zero regions:")
    for s, e in ranges:
        print(f"  0x{s:06X} - 0x{e:06X} ({(e-s)//1024}KB)")

# Search for ELF in firmware
for m in re.finditer(b'\x7fELF', data):
    print(f"\nELF at 0x{m.start():X}")
    # Parse ELF header
    elf_start = m.start()
    ei_class = data[elf_start + 4]
    print(f"  Class: {'ELF64' if ei_class == 2 else 'ELF32'}")

# Search for strings in ABL related to encryption
strings_to_find = [
    b'Encrypted block',
    b'verified success',
    b'sw_proj_id',
    b'SoftwareProject',
    b'GetParam',
    b'param_key',
    b'aes_cbc',
    b'decrypt',
]

for s in strings_to_find:
    idx = data.find(s)
    if idx >= 0:
        ctx = data[max(0,idx-8):min(len(data),idx+len(s)+32)]
        display = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
        print(f"String '{s.decode()}' at 0x{idx:X}: {display}")
