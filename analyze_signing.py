#!/usr/bin/env python3
import hashlib, struct

with open('/Users/xmxx/pinganhuijia/edl_backup/abl_b.img','rb') as f:
    d = f.read()

# Signing segment at 0x1000 (filesz=0x19a0 per 32-bit ELF PT_NULL[1])
seg = d[0x1000:0x1000+0x19a0]
print(f"Signing segment (0x1000..0x{0x1000+0x19a0:x}), {len(seg)} bytes")
print("First 128 bytes:")
for i in range(0, 128, 16):
    print(f"  {0x1000+i:#x}: {seg[i:i+16].hex()}")

# PT_LOAD at 0x3000, filesz=0x212000
pt_load = d[0x3000:0x3000+0x212000]

# Check SHA256 and SHA1 of PT_LOAD
h256 = hashlib.sha256(pt_load).digest()
h1   = hashlib.sha1(pt_load).digest()
print(f"\nSHA256(PT_LOAD): {h256.hex()}")
print(f"SHA1  (PT_LOAD): {h1.hex()}")

print(f"SHA256 in signing seg: {h256 in seg}")
print(f"SHA1   in signing seg: {h1 in seg}")

# Last non-zero in signing seg
last_nz = max((i for i, b in enumerate(seg) if b != 0), default=0)
print(f"\nLast non-zero in signing seg: offset {last_nz:#x} (file {0x1000+last_nz:#x})")
print(f"Data from last_nz-16 to end: {seg[last_nz-16:last_nz+4].hex()}")

# Try to find any cert (X.509 starts with 30 82 xx xx (DER SEQUENCE))
import re
cert_positions = [m.start() for m in re.finditer(b'\x30\x82', seg)]
print(f"\nX.509 DER SEQUENCE (30 82) positions in signing seg: {[hex(p) for p in cert_positions[:10]]}")

# Hash table: usually 20-byte SHA1 or 32-byte SHA256 entries, preceded by a known header
# Check if there are 32-byte blocks that look like hash entries
print("\nBytes at seg offset 0x90..0xd0 (typical hash table start):")
print(seg[0x90:0xd0].hex())

# Check last 512 bytes of signing seg for cert chain
print("\nLast 64 bytes of signing seg:")
print(seg[-64:].hex())

# check actual content length - how many bytes are before the trailing zeros
real_end = 0
for i in range(len(seg)-1, -1, -1):
    if seg[i] != 0:
        real_end = i+1
        break
print(f"\nReal content in signing seg ends at offset {real_end:#x} ({real_end} bytes)")
