#!/usr/bin/env python3
"""Decode Qualcomm MBN-style signing header and find hash table entries."""
import hashlib, struct

with open('/Users/xmxx/pinganhuijia/edl_backup/abl_b.img','rb') as f:
    d = f.read()

seg = d[0x1000:0x1000+0x19a0]

# Parse the header (Qualcomm hash-segment/MBN header)
# Format (little-endian 32-bit words):
print("=== Signing Segment Header (0x1000) ===")
fields = struct.unpack_from('<' + 'I'*24, seg, 0)
labels = [
    "version", "image_id", "flash_addr", "dest?",
    "total_size", "hash_table_offset", "sig_addr?", "sig_size",
    "cert_addr?", "cert_chain_size", "code_size?", "unk_2c",
    "unk_30", "unk_34", "unk_38", "unk_3c",
    "unk_40", "device_model_hi?", "device_model", "unk_4c",
    "unk_50", "unk_54", "unk_58", "unk_5c",
]
for i, (lbl, val) in enumerate(zip(labels, fields)):
    if val:
        print(f"  [{i*4:#04x}] {lbl:<25} = {val:#010x}  ({val})")

print()
hash_table_off = fields[5]  # 0x90 relative to seg start
sig_size       = fields[7]  # 0x68 = 104 bytes
cert_size      = fields[9]  # 0x1800 = 6144 bytes

print(f"Hash table at seg+{hash_table_off:#x} (file {0x1000+hash_table_off:#x})")
print(f"Signature size: {sig_size:#x} ({sig_size})")
print(f"Cert chain size: {cert_size:#x} ({cert_size})")

# Read hash table
print(f"\n=== Hash Table (starting at seg+{hash_table_off:#x}) ===")
ht = seg[hash_table_off:]
# In standard format: 3 entries for 3 segments (PT_NULL[0], PT_NULL[1], PT_LOAD)
# Each entry is SHA256 (32 bytes) — total 96 bytes
for i in range(8):  # check up to 8 entries
    entry = ht[i*32:(i+1)*32]
    if all(b == 0 for b in entry):
        status = "[ZERO - skipped/not verified]"
    else:
        status = ""
    print(f"  Entry[{i}]: {entry.hex()}  {status}")

# Now verify: does entry[2] match PT_LOAD SHA256?
print("\n=== Segment Hash Verification ===")
pt_null0 = d[0x0000:0x0094]       # PT_NULL[0]: ELF header area
pt_null1 = d[0x1000:0x1000+0x19a0]  # PT_NULL[1]: signing seg itself (zeroed in hash)
pt_load  = d[0x3000:0x3000+0x212000]

# Standard: signing seg is hashed with sig/cert zeroed out
print(f"SHA256(PT_NULL[0]): {hashlib.sha256(pt_null0).hexdigest()}")
print(f"SHA256(PT_LOAD   ): {hashlib.sha256(pt_load).hexdigest()}")

# Which hash table entry matches?
for i in range(6):
    candidate = ht[i*32:(i+1)*32].hex()
    if candidate == hashlib.sha256(pt_null0).hexdigest():
        print(f"  Entry[{i}] matches PT_NULL[0]!")
    if candidate == hashlib.sha256(pt_load).hexdigest():
        print(f"  Entry[{i}] matches PT_LOAD!")

# Show where sig and certs start
sig_start = 0x1000 + hash_table_off + 96  # assume 3*32 hash table
print(f"\nAssumed sig start: {sig_start:#x} ({sig_size} bytes)")
print(f"Sig bytes: {d[sig_start:sig_start+sig_size].hex()}")
cert_start = sig_start + sig_size
print(f"Cert start: {cert_start:#x}")
print(f"Cert[0] first 32: {d[cert_start:cert_start+32].hex()}")
