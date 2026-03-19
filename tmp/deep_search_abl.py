#!/usr/bin/env python3
"""Deep search of ABL binary for encryption keys and param-related code."""
import re, struct
from binascii import hexlify

with open('/tmp/abl_a.bin', 'rb') as f:
    abl = f.read()

# Only search the non-zero region
abl = abl[:0x215000]
print(f"Searching {len(abl)} bytes of ABL")

# 1. Find all log strings related to param encryption
print("\n=== Log strings ===")
for pattern in [b'Encrypted block', b'verified', b'param', b'sw_proj', b'GetParam',
                b'SoftwareProject', b'carrier', b'decrypt', b'encrypt',
                b'init_param', b'check and restore', b'RPMB', b'block_key',
                b'enc_key', b'get_param']:
    pos = 0
    while True:
        idx = abl.find(pattern, pos)
        if idx == -1:
            break
        # Get full string context
        start = idx
        while start > 0 and abl[start-1] != 0:
            start -= 1
        end = idx
        while end < len(abl) and abl[end] != 0:
            end += 1
        s = abl[start:end]
        try:
            txt = s.decode('utf-8', errors='replace')
            print(f"  0x{start:06X}: {txt}")
        except:
            pass
        pos = idx + 1

# 2. Search for 16-byte aligned potential AES keys near param-related code
# First find "Encrypted block" string references
print("\n=== Potential AES keys near param strings ===")
for pattern in [b'Encrypted block', b'verified success', b'get_param_by_index']:
    idx = abl.find(pattern)
    if idx == -1:
        continue
    # Search +/- 0x10000 around the string for 16-byte non-zero aligned blocks
    region_start = max(0, idx - 0x10000)
    region_end = min(len(abl), idx + 0x10000)
    print(f"\nNear '{pattern.decode()}' at 0x{idx:X}:")

# 3. Search for "000OnePlus" variant strings
print("\n=== OnePlus string variants ===")
for pattern in [b'OnePlus', b'oneplus', b'ONEPLUS', b'billie', b'818']:
    pos = 0
    while True:
        idx = abl.find(pattern, pos)
        if idx == -1:
            break
        start = idx
        while start > 0 and abl[start-1] >= 0x20 and abl[start-1] < 0x7f:
            start -= 1
        end = idx
        while end < len(abl) and abl[end] >= 0x20 and abl[end] < 0x7f:
            end += 1
        s = abl[start:end].decode('ascii', errors='replace')
        if len(s) > 3:
            print(f"  0x{start:06X}: '{s}'")
        pos = idx + 1

# 4. The known IV: 562E17996D093D28DDB3BA695A2E6F58
# Since ABL needs IV too, search for it or partial matches
iv_bytes = bytes.fromhex('562E17996D093D28DDB3BA695A2E6F58')
for i in range(0, len(iv_bytes) - 3):
    chunk = iv_bytes[i:i+4]
    idx = abl.find(chunk)
    if idx >= 0:
        print(f"\nIV fragment {hexlify(chunk).decode()} found at 0x{idx:X}")
        # Show context
        print(f"  Context: {hexlify(abl[max(0,idx-16):idx+32]).decode()}")

# 5. Search for the static key bytes in any order or partial
key_bytes = bytes.fromhex('3030304F6E65506C7573383138303030')  # "000OnePlus818000"
# Check if the ASCII text appears
ascii_key = b'000OnePlus818000'
idx = abl.find(ascii_key)
if idx >= 0:
    print(f"\nASCII key found at 0x{idx:X}")
else:
    # Search for partial matches
    for i in range(0, len(key_bytes) - 3):
        chunk = key_bytes[i:i+4]
        idx = abl.find(chunk)
        if idx >= 0:
            # Check if it's part of a larger key-like sequence
            ctx = hexlify(abl[idx:idx+16]).decode()
            if not all(c in '0' for c in ctx):  # Skip obvious padding
                print(f"\nKey fragment {hexlify(chunk).decode()} at 0x{idx:X}: {ctx}")
                break
