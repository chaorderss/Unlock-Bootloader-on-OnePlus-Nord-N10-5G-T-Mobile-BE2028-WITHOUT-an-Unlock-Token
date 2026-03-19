#!/usr/bin/env python3
"""Try different hash interpretations to understand signing format."""
import hashlib, struct

with open('/Users/xmxx/pinganhuijia/edl_backup/abl_b.img','rb') as f:
    d = f.read()

seg = d[0x1000:0x1000+0x19a0]
ht_start = 0x90  # hash table starts at seg+0x90

# Print full 256 bytes of hash table region in 32-byte rows
print("=== Raw hash table region (seg+0x90 to seg+0x190) ===")
for row in range(8):
    off = ht_start + row*32
    print(f"  seg+{off:#05x}: {seg[off:off+32].hex()}")

print()
# Try 48-byte entries (20=SHA1 padded to 48, or 32=SHA256 + 16 reserved)
print("=== As 48-byte entries ===")
for i in range(4):
    off = ht_start + i*48
    entry = seg[off:off+48]
    sha1_part = entry[0:20]
    sha256_part = entry[0:32]
    alt_sha1 = entry[16:36]
    alt_sha256 = entry[16:48]
    print(f"  Entry[{i}]: {entry.hex()}")

print()
# The key question: does ANY hash-of-PT_LOAD match any 20-or-32 byte window in seg?
pt_load = d[0x3000:0x3000+0x212000]
sha1_ptload  = hashlib.sha1(pt_load).digest()
sha256_ptload = hashlib.sha256(pt_load).digest()
sha384_ptload = hashlib.sha384(pt_load).digest()

print(f"SHA1  (PT_LOAD 0x3000..0x215000): {sha1_ptload.hex()}")
print(f"SHA256(PT_LOAD 0x3000..0x215000): {sha256_ptload.hex()}")

# Try hashing only the actual content (up to last non-0xFF)
last_real = 0x10b82e - 0x3000 + 1
pt_load_real = d[0x3000:0x3000+last_real]
sha1_real  = hashlib.sha1(pt_load_real).digest()
sha256_real = hashlib.sha256(pt_load_real).digest()
print(f"\nSHA1  (PT_LOAD real content, {last_real:#x} bytes): {sha1_real.hex()}")
print(f"SHA256(PT_LOAD real content):                           {sha256_real.hex()}")

for h, name in [(sha1_ptload, "SHA1(PT_LOAD full)"), (sha256_ptload, "SHA256(PT_LOAD full)"),
                (sha1_real, "SHA1(PT_LOAD real)"), (sha256_real, "SHA256(PT_LOAD real)")]:
    if h in seg:
        print(f"  *** {name} FOUND in signing segment at {seg.index(h):#x}")
    else:
        print(f"  --- {name} NOT in signing segment")

# Try SHA256 of page-aligned chunks of PT_LOAD
print("\n=== Page-aligned chunk hashes (checking if any appear in seg) ===")
page = 4096
for page_idx in range(min(5, len(pt_load)//page)):
    chunk = pt_load[page_idx*page:(page_idx+1)*page]
    h = hashlib.sha256(chunk).digest()
    if h in seg:
        print(f"  SHA256(page[{page_idx}]) FOUND in signing seg!")
    # also try SHA1
    h_sha1 = hashlib.sha1(chunk).digest()
    if h_sha1 in seg:
        print(f"  SHA1(page[{page_idx}]) FOUND in signing seg!")

# Try SHA256 of the ELF header (first seg)
elf_hdr = d[0:0x94]
sha256_elf = hashlib.sha256(elf_hdr).digest()
sha1_elf = hashlib.sha1(elf_hdr).digest()
print(f"\nSHA256(ELF hdr 0..0x94): {sha256_elf.hex()}")
print(f"  In seg: {sha256_elf in seg}")
print(f"SHA1(ELF hdr 0..0x94): {sha1_elf.hex()}")
print(f"  In seg: {sha1_elf in seg}")

# Also check SHA256 of the SIGNING SEGMENT with sig/cert zeroed
import copy
seg_zeroed = bytearray(seg)
# Zero out from hash_table + code_size to end of real data (sig + certs)
# According to header: hash_table_offset=0x90, sig_size=0x68, cert_size=0x1800
# Hash table itself: 0x90 bytes
# Then sig starts at 0x90+0x90=0x120? No...
# Let me try: hash_table ends at 0x90+total_hash_size, then sig, then certs
# There are likely 3 hash entries (one per PT segment): 3*32=96=0x60 bytes
# sig starts at seg+0x90+0x60=0xf0, size=0x68
# certs start at seg+0xf0+0x68=0x158, size=0x1800
# Total: 0x158+0x1800=0x1958 which is close to 0x19a0 (accounting for alignment)

sig_offset_in_seg  = 0x90 + 3*32  # = 0xf0
cert_offset_in_seg = sig_offset_in_seg + 0x68  # = 0x158
print(f"\nAssumed structure:")
print(f"  Hash table: seg+0x90 to seg+{sig_offset_in_seg:#x}")
print(f"  Signature:  seg+{sig_offset_in_seg:#x} to seg+{cert_offset_in_seg:#x}")
print(f"  Certs:      seg+{cert_offset_in_seg:#x} to seg+{cert_offset_in_seg+0x1800:#x}")
print(f"  Ends at:    {cert_offset_in_seg+0x1800:#x} (available: {0x19a0:#x})")

for i in range(sig_offset_in_seg, cert_offset_in_seg):
    seg_zeroed[i] = 0
sha256_signing_zeroed = hashlib.sha256(bytes(seg_zeroed)).digest()
print(f"SHA256(signing_seg with sig zeroed): {sha256_signing_zeroed.hex()}")

# Check if our 3 hash entries match
print(f"\nHash table entry[0] (for ELF header segment): {seg[0x90:0xb0].hex()}")
print(f"Hash table entry[1] (for signing segment):    {seg[0xb0:0xd0].hex()}")
print(f"Hash table entry[2] (for PT_LOAD):            {seg[0xd0:0xf0].hex()}")
print(f"\nSHA256(ELF hdr): {sha256_elf.hex()}")
print(f"SHA256(signing seg w/ sig zeroed): {sha256_signing_zeroed.hex()}")
print(f"SHA256(PT_LOAD): {sha256_ptload.hex()}")

if seg[0x90:0xb0] == sha256_elf + b'\x00'*16:
    print("  NOTE: entry[0] = SHA256(ELF_hdr) + 16 zero bytes!")
if seg[0xd0:0xf0] == sha256_ptload + b'\x00'*16:
    print("  NOTE: entry[2] = SHA256(PT_LOAD) + 16 zero bytes!")
if sha256_ptload in seg[0xd0:0xf0]:
    print("  SHA256(PT_LOAD) found within entry[2]!")
