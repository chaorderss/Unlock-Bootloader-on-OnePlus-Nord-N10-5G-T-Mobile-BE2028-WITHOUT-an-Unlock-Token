#!/usr/bin/env python3
"""Test SHA384 as the hash algorithm for Qualcomm ABL signing."""
import hashlib

with open('/Users/xmxx/pinganhuijia/edl_backup/abl_b.img','rb') as f:
    d = f.read()

seg = d[0x1000:]

# Hash table entries (56 bytes each) decoded:
# Entry[0] at seg+0x90: 24 zeros + 32 non-zero → [8 reserved][48 SHA384??]
# Entry[1] at seg+0xc8: 16 non-zero + 40 zeros  → skip/zeroed entry
# Entry[2] at seg+0x100: 8 zeros + 48 non-zero  → [8 reserved][48 SHA384??]

# Extract the 48-byte hash candidates (bytes 8..55 of each entry)
entries = []
for i in range(3):
    e = seg[0x90 + i*56 : 0x90 + (i+1)*56]
    entries.append(e)

print("Hash candidates (bytes [8:56] of each 56-byte entry):")
for i, e in enumerate(entries):
    print(f"  Entry[{i}]: {e[8:].hex()}")

print()

# Compute SHA384 of each segment and compare
pt_null0 = d[0x00:0x94]
pt_load  = d[0x3000:0x3000+0x212000]

# PT_NULL[1] signing seg with sig region zeroed
seg_arr = bytearray(seg[:0x19a0])
for i in range(0x138, 0x138+0x68):
    seg_arr[i] = 0
pt_null1 = bytes(seg_arr)

# Also try PT_NULL[1] with sig AND cert chain zeroed
seg_arr2 = bytearray(seg[:0x19a0])
for i in range(0x138, 0x1958):
    seg_arr2[i] = 0
pt_null1_full_zeroed = bytes(seg_arr2)

for name, content in [
    ("PT_NULL[0] (ELF hdr, 0x00..0x94)", pt_null0),
    ("PT_NULL[1] (signing seg, sig zeroed)", pt_null1),
    ("PT_NULL[1] (signing seg, sig+cert zeroed)", pt_null1_full_zeroed),
    ("PT_LOAD (0x3000..0x215000)", pt_load),
    ("PT_LOAD real content (0x3000..0x10b82f)", d[0x3000:0x10b82f]),
]:
    h384 = hashlib.sha384(content).digest()
    h256 = hashlib.sha256(content).digest()
    print(f"{name}:")
    print(f"  SHA384={h384.hex()}")

    # Check against entry[2][8:56] = 48 non-zero bytes
    e2_hash = entries[2][8:]
    e0_hash = entries[0][8:]
    e0_last32 = entries[0][-32:]

    match384_e2 = "*** MATCH entry[2]!" if h384 == e2_hash else ""
    match384_e0 = "*** MATCH entry[0]!" if h384 == e0_hash else ""
    matchtrunc_e2 = "*** TRUNCATED MATCH entry[2]!" if h384[:32] == entries[2][8:40] else ""
    print(f"  vs entry[2][8:56]: {match384_e2}")
    print(f"  vs entry[0][8:56]: {match384_e0}")
    print()

# Also check: what IS entry[2][8:56] as SHA384 of PT_LOAD?
e2_hash = entries[2][8:]
e0_hash = entries[0][8:]
print(f"entry[0][8:56] = {e0_hash.hex()}")
print(f"entry[2][8:56] = {e2_hash.hex()}")
print()

# Are these even valid SHA384 outputs? Check by brute-forcing if they're zeros
print(f"entry[0][8:56] has zeros: {sum(1 for b in e0_hash if b == 0)} / {len(e0_hash)}")
print(f"entry[1][8:56] has zeros: {sum(1 for b in entries[1][8:] if b == 0)} / {len(entries[1][8:])}")
print(f"entry[2][8:56] has zeros: {sum(1 for b in e2_hash if b == 0)} / {len(e2_hash)}")
