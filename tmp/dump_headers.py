#!/usr/bin/env python3
"""Hex dump raw SID block headers and compare with original backup."""
import subprocess, struct, hashlib

def dump_header(data, offset, label):
    block = data[offset:offset+0x1000]
    print(f"\n=== {label} at offset 0x{offset:06X} ===")
    print(f"Header (first 32 bytes): {block[:32].hex()}")
    hv = block[0]
    cv = block[1]
    uc = struct.unpack_from('<H', block, 2)[0]
    outer_md5 = block[4:20]
    print(f"  hv={hv} cv={cv} uc={uc}")
    print(f"  Outer MD5 stored: {outer_md5.hex()}")

    enc_data = block[0x400:0x400+0xC00]
    comp_outer = hashlib.md5(enc_data).digest()
    print(f"  Outer MD5 computed: {comp_outer.hex()}")
    print(f"  Outer MD5 match: {outer_md5 == comp_outer}")

    # Show first 32 bytes of encrypted data
    print(f"  Enc[0:32]: {enc_data[:32].hex()}")

    return block

# Read current param
result = subprocess.run(['adb', 'shell', 'dd if=/dev/block/sda6 2>/dev/null'],
                       capture_output=True)
current = result.stdout
print(f"Current param size: {len(current)}")

# Read original backup
with open('edl_backup/pre_convert/param.bin', 'rb') as f:
    original = f.read()
print(f"Original param size: {len(original)}")

# Compare SID 0x13C
print("\n" + "="*60)
print("CURRENT DEVICE STATE")
print("="*60)
cur_blk = dump_header(current, 0x13C * 0x400, 'SID 0x13C current')
dump_header(current, 0x33C * 0x400, 'SID 0x33C current')

print("\n" + "="*60)
print("ORIGINAL BACKUP (pre-convert)")
print("="*60)
orig_blk = dump_header(original, 0x13C * 0x400, 'SID 0x13C original')
dump_header(original, 0x33C * 0x400, 'SID 0x33C original')

# Compare blocks byte by byte
if cur_blk == orig_blk:
    print("\n>>> SID 0x13C: CURRENT == ORIGINAL (ABL fully restored!)")
else:
    diff_count = sum(1 for a, b in zip(cur_blk, orig_blk) if a != b)
    print(f"\n>>> SID 0x13C: {diff_count} bytes differ")
    # Find first diff
    for i in range(min(len(cur_blk), len(orig_blk))):
        if cur_blk[i] != orig_blk[i]:
            print(f"  First diff at block offset 0x{i:04X}: cur=0x{cur_blk[i]:02X} orig=0x{orig_blk[i]:02X}")
            break

# Also check SID 0x12C (intranet/boottype)
print("\n" + "="*60)
print("SID 0x12C COMPARISON")
print("="*60)
dump_header(current, 0x12C * 0x400, 'SID 0x12C current')
dump_header(original, 0x12C * 0x400, 'SID 0x12C original')
