#!/usr/bin/env python3
import hashlib

with open('/Users/xmxx/pinganhuijia/edl_backup/abl_b.img','rb') as f:
    d = f.read()

seg = d[0x1000:]

# Layout confirmed:
# Header: seg+0x00..0x8f (144 bytes)
# Hash table: seg+0x90..0x137 (168 bytes = 3 × 56 bytes)
# Signature: seg+0x138..0x19f (0x68 = 104 bytes)
# Cert chain: seg+0x1a0 onwards (0x1800 = 6144 bytes)

hash_table_start = 0x90
sig_start = 0x138

print("Hash table (3 x 56-byte entries):")
for i in range(3):
    off = hash_table_start + i*56
    e = seg[off:off+56]
    print(f"  Entry[{i}] at seg+{off:#x}: {e.hex()}")
    print(f"    last32 bytes: {e[-32:].hex()}")
print()

# Segment contents
pt_null0 = d[0x00:0x94]
pt_load  = d[0x3000:0x3000+0x212000]

# PT_NULL[1] with signature region zeroed
seg_arr = bytearray(seg[:0x19a0])
for i in range(sig_start, sig_start+0x68):
    seg_arr[i] = 0
pt_null1 = bytes(seg_arr)

ht = seg[hash_table_start:hash_table_start+168]

for name, content in [("PT_NULL[0] ELF_hdr", pt_null0),
                      ("PT_NULL[1] sig-zeroed", pt_null1),
                      ("PT_LOAD", pt_load)]:
    h256 = hashlib.sha256(content).digest()
    h1   = hashlib.sha1(content).digest()
    found256 = "*** MATCH ***" if h256 in ht else "no match"
    found1   = "*** MATCH ***" if h1 in ht else "no match"
    print(f"{name}:")
    print(f"  sha256={h256.hex()} {found256}")
    print(f"  sha1  ={h1.hex()} {found1}")
print()

sig = seg[sig_start:sig_start+0x68]
print(f"Signature ({len(sig)} bytes):")
for i in range(0, len(sig), 16):
    print(f"  {sig[i:i+16].hex()}")
