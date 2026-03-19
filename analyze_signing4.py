#!/usr/bin/env python3
"""Precisely decode the Qualcomm ELF signing segment structure and verify all hashes."""
import hashlib, struct, re

with open('/Users/xmxx/pinganhuijia/edl_backup/abl_b.img','rb') as f:
    d = f.read()

seg = d[0x1000:]

# We know:
# - Hash table at seg+0x90 (size=0x90 from header field)
# - Cert chain at seg+0x1a0 (confirmed: ONEPLUS cert found there)
# - Between 0x90 and 0x1a0 = 0x110 = 272 bytes total (hash table + signature)
# - Signature size = 0x68 = 104 bytes (from header)
# - So hash table size = 272 - 104 = 168 bytes
# - Hash table ends at seg+0x90+168 = seg+0x138
# - Signature: seg+0x138 to seg+0x19f

hash_table_start = 0x90
hash_table_end   = 0x138  # 168 bytes
sig_start        = 0x138
sig_end          = 0x138 + 0x68  # = 0x1a0
cert_start       = 0x1a0

print(f"Hash table: seg+{hash_table_start:#x} to seg+{hash_table_end:#x} ({hash_table_end-hash_table_start} bytes)")
print(f"Signature:  seg+{sig_start:#x} to seg+{sig_end:#x} ({sig_end-sig_start} bytes)")
print(f"Cert chain: seg+{cert_start:#x} onwards")
print()

# Hash table is 168 bytes. For 3 segments:
# 168 / 3 = 56 bytes per entry
# 56 = 24 (reserved) + 32 (SHA256)? Or 36 (reserved) + 20 (SHA1)?
print("=== Hash table (168 bytes = 3 x 56 byte entries?) ===")
for i in range(3):
    e = seg[hash_table_start + i*56 : hash_table_start + (i+1)*56]
    print(f"Entry[{i}] ({56}B): {e.hex()}")
    # Try: last 32 bytes = SHA256
    candidate_sha256 = e[-32:]
    # Try: last 20 bytes = SHA1
    candidate_sha1 = e[-20:]
    # Try: bytes 4..36 = SHA256
    candidate_sha256_alt = e[4:36]
    print(f"  Last 32 (SHA256?): {candidate_sha256.hex()}")

print()
print("=== Segment hashes to test ===")
# PT_NULL[0]: ELF headers = d[0x00:0x94]
# PT_NULL[1]: signing seg = d[0x1000:0x29a0], but with signature ZEROED OUT
# PT_LOAD:    d[0x3000:0x3000+0x212000]

pt_null0 = d[0x00:0x94]
pt_load  = d[0x3000:0x3000+0x212000]

# For PT_NULL[1], zero out the signature portion
import bytearray as BA
seg_for_hash = bytearray(seg[0:0x19a0])
for i in range(sig_start, sig_end):
    seg_for_hash[i] = 0
pt_null1 = bytes(seg_for_hash)

segs = [
    ("PT_NULL[0] (ELF hdr)", pt_null0),
    ("PT_NULL[1] (signing seg, sig zeroed)", pt_null1),
    ("PT_LOAD   (0x3000..0x215000)", pt_load),
]

for name, content in segs:
    h256 = hashlib.sha256(content).digest()
    h1   = hashlib.sha1(content).digest()
    print(f"  SHA256({name}): {h256.hex()}")
    print(f"  SHA1  ({name}): {h1.hex()}")

    # Check if this hash appears in the hash table region
    ht = seg[hash_table_start:hash_table_end]
    found256 = h256 in ht
    found1   = h1 in ht
    if found256: print(f"    *** SHA256 FOUND in hash table at +{ht.index(h256):#x}")
    if found1:   print(f"    *** SHA1   FOUND in hash table at +{ht.index(h1):#x}")
    print()

print("=== Signature bytes (first 16) ===")
print(f"  {seg[sig_start:sig_start+16].hex()}")
print(f"  {seg[sig_start+16:sig_start+32].hex()}")

print()
print("=== First cert CommonName ===")
cert_data = seg[cert_start:cert_start+0x800]
cn_pos = cert_data.find(b'\x55\x04\x03')
if cn_pos >= 0:
    data_type = cert_data[cn_pos+2]
    cn_len = cert_data[cn_pos+3]
    cn = cert_data[cn_pos+4:cn_pos+4+cn_len]
    print(f"  CN: {cn}")
