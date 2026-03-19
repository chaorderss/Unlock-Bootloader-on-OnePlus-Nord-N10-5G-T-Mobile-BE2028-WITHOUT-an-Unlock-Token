#!/usr/bin/env python3
"""Search decompressed ABL for ALL AES keys and SID 0x13C encryption."""
import struct, re
from binascii import hexlify

with open('/tmp/abl_dec.bin', 'rb') as f:
    dec = f.read()

print(f"Decompressed ABL: {len(dec)} bytes")

# 1. Find ALL instances of "000OnePlus818000" and nearby keys
print("\n=== '000OnePlus818000' occurrences ===")
pos = 0
while True:
    idx = dec.find(b'000OnePlus818000', pos)
    if idx == -1:
        break
    print(f"  At 0x{idx:X}: context[-32:+48] = {hexlify(dec[max(0,idx-32):idx+48]).decode()}")
    pos = idx + 1

# 2. Find the AES IV
iv = bytes.fromhex('562E17996D093D28DDB3BA695A2E6F58')
pos = 0
while True:
    idx = dec.find(iv, pos)
    if idx == -1:
        break
    print(f"\n  AES IV at 0x{idx:X}")
    # Show surrounding context - there might be a key nearby
    print(f"  Context[-32:+48] = {hexlify(dec[max(0,idx-32):idx+48]).decode()}")
    pos = idx + 1

# Also search for reversed IV
iv_rev = iv[::-1]
idx = dec.find(iv_rev)
if idx >= 0:
    print(f"\n  Reversed AES IV at 0x{idx:X}")

# 3. Find serial derivation prefix
derive = bytes.fromhex('a9264fbf8a')
pos = 0
while True:
    idx = dec.find(derive, pos)
    if idx == -1:
        break
    print(f"\n  Derivation prefix at 0x{idx:X}: {hexlify(dec[idx:idx+20]).decode()}")
    pos = idx + 1

# 4. Search for sw_proj_id related strings to understand the flow
print("\n=== SW Project ID strings ===")
for pattern in [b'sw_proj_id', b'SoftwareProject', b'Software', b'init_param_sw',
                b'check and restore', b'RPMB', b'IsSupportParam', b'supported flag']:
    pos = 0
    while True:
        idx = dec.find(pattern, pos)
        if idx == -1:
            break
        start = idx
        while start > 0 and dec[start-1] > 0:
            start -= 1
        end = idx
        while end < len(dec) and dec[end] != 0:
            end += 1
        txt = dec[start:end].decode('utf-8', errors='replace')
        print(f"  0x{start:X}: '{txt[:150]}'")
        pos = idx + 1

# 5. Look for other 16-byte constants near the static key
# The static key is at 0x6295A
key_offset = dec.find(b'000OnePlus818000')
if key_offset >= 0:
    print(f"\n=== Context around static key (0x{key_offset:X}) ===")
    # Show -256 to +256 around the key
    region = dec[max(0, key_offset-256):key_offset+256]
    reg_start = max(0, key_offset-256)

    # Look for other 16-byte aligned non-zero blocks that could be keys
    for i in range(0, len(region)-16, 4):
        block = region[i:i+16]
        if all(b == 0 for b in block):
            continue
        # Check if it looks like a potential key (high entropy)
        unique = len(set(block))
        if unique >= 6:  # At least 6 unique bytes
            abs_off = reg_start + i
            print(f"  0x{abs_off:X}: {hexlify(block).decode()} (unique={unique})")

# 6. Look at ALL 16-byte values immediately before/after IV and key
print("\n=== Values near IV and key positions ===")
iv_offset = dec.find(iv)
if iv_offset >= 0:
    print(f"IV at 0x{iv_offset:X}")
    for off in range(-64, 80, 16):
        pos = iv_offset + off
        if 0 <= pos and pos + 16 <= len(dec):
            block = dec[pos:pos+16]
            unique = len(set(block))
            marker = " <-- IV" if off == 0 else (" <-- STATIC KEY" if off == 16 and dec[pos:pos+16] == b'000OnePlus818000' else "")
            if any(b != 0 for b in block):
                print(f"  0x{pos:06X} (+{off:+3d}): {hexlify(block).decode()}{marker}")
