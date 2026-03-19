#!/usr/bin/env python3
"""
Parse the param partition to understand its structure and check if enable_ops would work.
Cross-reference with oneplus_param.py format.
"""

import struct

param_path = '/Users/xmxx/pinganhuijia/edl_backup/lun0/param.bin'
with open(param_path, 'rb') as f:
    data = f.read()

print(f"Param partition size: {len(data)} bytes ({len(data)/1024:.0f} KB)")

# Header analysis
print(f"\n=== Param Header ===")
print(f"Magic: {data[0:8]}")
print(f"  ASCII: '{data[0:8].decode('ascii', errors='replace')}'")

# Check for the PRODUCT magic
if data[0:7] == b'PRODUCT':
    print("  ✓ PRODUCT magic found!")

# Model/project info
print(f"Data[0x14:0x1C]: {data[0x14:0x1C].hex()}")
print(f"  ASCII: '{data[0x14:0x1C].decode('ascii', errors='replace')}'")

# Dump more of the header
for off in range(0, 0x100, 16):
    hex_str = data[off:off+16].hex()
    ascii_str = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in data[off:off+16])
    print(f"  0x{off:04X}: {hex_str}  {ascii_str}")

# From oneplus_param.py, the param structure has:
# - items starting at some offset
# - each item has: SID (4 bytes), offset, length
# - items with SID > 0x100 have encrypted data

# Let's search for the encryption magic 0xA0AD646A
enc_magic = struct.pack('<I', 0xA0AD646A)
idx = data.find(enc_magic)
while idx >= 0:
    print(f"\n  Encryption magic 0xA0AD646A found at offset 0x{idx:X}")
    # Dump context
    for off in range(max(0, idx-32), min(len(data), idx+64), 16):
        hex_str = data[off:off+16].hex()
        print(f"    0x{off:04X}: {hex_str}")
    idx = data.find(enc_magic, idx + 1)

# Search for SID 0x12C (the ops enable SID) as 4-byte LE integer
sid_bytes = struct.pack('<I', 0x12C)
idx = data.find(sid_bytes)
while idx >= 0:
    print(f"\n  SID 0x12C found at offset 0x{idx:X}")
    for off in range(max(0, idx-16), min(len(data), idx+32), 16):
        hex_str = data[off:off+16].hex()
        print(f"    0x{off:04X}: {hex_str}")
    idx = data.find(sid_bytes, idx + 1)

# Check the oneplus_param.py parse logic
# The param layout typically has a table of contents with SIDs
# Let's look for patterns of SID entries

# Look for non-zero regions in the first 4KB
print(f"\n=== Non-zero regions in first 4KB ===")
last_nz = -1
for off in range(0, min(4096, len(data))):
    if data[off] != 0:
        if last_nz < off - 1:
            if last_nz >= 0:
                print(f"  ... gap ...")
        last_nz = off

# Detailed dump of non-zero areas
print(f"\n=== Detailed non-zero data ===")
for off in range(0, min(len(data), 0x10000), 16):
    chunk = data[off:off+16]
    if any(b != 0 for b in chunk):
        hex_str = chunk.hex()
        ascii_str = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk)
        print(f"  0x{off:05X}: {hex_str}  {ascii_str}")

# Check what value is at SID=0x12C target offset 0x80
# In the oneplus_param.py structure:
# The param layout from the code:
# - paramitems: list of items with SID, name, start_offset, length, offset_in_param
# - For SID >= 0x100: data is encrypted
# - For SID < 0x100: data is plaintext

# Let's also try to interpret the header using the oneplus_param.py logic
print(f"\n=== Attempting to parse as oneplus param structure ===")
# The paramtools code reads items from a table
# Let's check if there's a count at some offset

# From paramitems in the oneplus source:
# [SID, name, start, length, offset_in_param]
# The param partition likely has a directory structure

# Let's check byte 0x400 onwards (common offset for param data)
for base in [0x400, 0x800, 0x1000, 0x2000, 0x4000]:
    chunk = data[base:base+16]
    if any(b != 0 for b in chunk):
        print(f"  Data at 0x{base:04X}: {chunk.hex()}")
