#!/usr/bin/env python3
"""Search ABL binary for encryption keys and param-related constants."""
import struct
from binascii import hexlify

with open('/tmp/abl_a.bin', 'rb') as f:
    abl = f.read()

print(f"ABL size: {len(abl)} bytes")

# Search for known constants
patterns = {
    "static_key (000OnePlus818000)": bytes.fromhex('3030304F6E65506C7573383138303030'),
    "aes_iv": bytes.fromhex('562E17996D093D28DDB3BA695A2E6F58'),
    "magic A0AD646A": bytes.fromhex('6A64ADA0'),
    "text 000OnePlus": b'000OnePlus',
    "text OnePlus818": b'OnePlus818',
    "text 818000": b'818000',
}

for name, pattern in patterns.items():
    pos = 0
    hits = []
    while True:
        idx = abl.find(pattern, pos)
        if idx == -1:
            break
        hits.append(idx)
        pos = idx + 1
    if hits:
        print(f"\n{name}: {len(hits)} hit(s)")
        for h in hits[:5]:
            ctx_start = max(0, h - 16)
            ctx_end = min(len(abl), h + len(pattern) + 32)
            print(f"  Offset 0x{h:X}: ...{hexlify(abl[ctx_start:ctx_end]).decode()}...")
    else:
        print(f"\n{name}: NOT FOUND")

# Search for the AES key derivation prefix "a9264fbf8a"
derivation_prefix = bytes.fromhex('a9264fbf8a')
pos = 0
hits = []
while True:
    idx = abl.find(derivation_prefix, pos)
    if idx == -1:
        break
    hits.append(idx)
    pos = idx + 1
if hits:
    print(f"\nDerivation prefix a9264fbf8a: {len(hits)} hit(s)")
    for h in hits[:5]:
        print(f"  Offset 0x{h:X}: {hexlify(abl[h:h+32]).decode()}")
else:
    print(f"\nDerivation prefix a9264fbf8a: NOT FOUND in ABL")

# Search for "6b4487ea" (suffix of derivation)
suffix = bytes.fromhex('6b4487ea')
idx = abl.find(suffix)
if idx != -1:
    print(f"\nDerivation suffix 6b4487ea at 0x{idx:X}: {hexlify(abl[max(0,idx-16):idx+16]).decode()}")
else:
    print(f"\nDerivation suffix 6b4487ea: NOT FOUND")

# Look for strings that suggest encryption key handling
for s in [b'encrypt', b'decrypt', b'aes_key', b'AES', b'param_key', b'enc_key',
          b'verified success', b'verify_enc', b'block_decrypt', b'Encrypted block']:
    idx = abl.find(s)
    if idx != -1:
        ctx = abl[max(0,idx-20):idx+len(s)+40]
        # Replace non-printable chars
        display = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
        print(f"\nString '{s.decode('utf-8', errors='replace')}' at 0x{idx:X}: {display}")
