#!/usr/bin/env python3
"""Extract and analyze the embedded X.509 certificate from PE32 binary."""
import struct, subprocess, os

with open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb') as f:
    data = f.read()

# The certificate structure:
# 0x61916: outer SEQUENCE (861 bytes) = CMS wrapper or cert chain
# 0x6191a: inner cert (581 bytes)
# 0x619eb: inner subjectPublicKeyInfo or similar

# Extract certificates
cert1_off = 0x61916
cert1_len = 4 + 0x35d  # tag+length+value = 4 + 861 = 865 bytes
cert1_data = data[cert1_off:cert1_off + cert1_len]

cert2_off = 0x6191a
cert2_len = 4 + 0x245  # 4 + 581 = 585 bytes
cert2_data = data[cert2_off:cert2_off + cert2_len]

# Write to files
with open('/tmp/token_outer.der', 'wb') as f:
    f.write(cert1_data)
with open('/tmp/token_cert.der', 'wb') as f:
    f.write(cert2_data)

print(f"Wrote {len(cert1_data)} bytes to /tmp/token_outer.der")
print(f"Wrote {len(cert2_data)} bytes to /tmp/token_cert.der")

# Parse outer structure manually
print("\n=== Outer DER structure at 0x61916 ===")
off = cert1_off
tag = data[off]; off += 1
# length
lb = data[off]; off += 1
if lb & 0x80:
    n_len_bytes = lb & 0x7f
    total_len = int.from_bytes(data[off:off+n_len_bytes], 'big')
    off += n_len_bytes
else:
    total_len = lb
print(f"  tag=0x{tag:02x}, total_len={total_len}")

# Walk inner structures
def parse_tlv(d, offset, depth=0):
    if offset >= len(d): return
    indent = "  " * depth
    tag = d[offset]; offset += 1
    lb = d[offset]; offset += 1
    if lb & 0x80:
        n = lb & 0x7f
        length = int.from_bytes(d[offset:offset+n], 'big')
        offset += n
    else:
        length = lb

    tag_names = {0x30:'SEQUENCE', 0x31:'SET', 0x02:'INTEGER', 0x06:'OID',
                 0x13:'PrintableString', 0x14:'T61String', 0x16:'IA5String',
                 0x17:'UTCTime', 0x18:'GeneralizedTime', 0x03:'BITSTRING',
                 0x04:'OCTETSTRING', 0x05:'NULL', 0x86:'URI', 0xa0:'[0]EXPLICIT',
                 0xa1:'[1]EXPLICIT', 0xa3:'[3]EXPLICIT'}
    tname = tag_names.get(tag, f'TAG_{tag:02x}')

    val = d[offset:offset+min(length, 32)]
    val_hex = val.hex()
    val_str = ''
    if tag in (0x13, 0x14, 0x16, 0x0c, 0x1a):
        try: val_str = ' = ' + d[offset:offset+length].decode('ascii', errors='replace')
        except: pass
    elif tag == 0x02:
        val_str = f' = {int.from_bytes(d[offset:offset+min(length,8)], "big"):x}...'

    print(f"{indent}[{tname}] len={length} {val_hex[:40]}{val_str}")

    if tag in (0x30, 0x31, 0xa0, 0xa1, 0xa2, 0xa3):
        end = offset + length
        pos = offset
        while pos < end and depth < 5:
            next_pos = parse_tlv(d, pos, depth+1)
            if next_pos is None or next_pos <= pos:
                break
            pos = next_pos

    return offset + length

parse_tlv(data, cert1_off)

print("\n=== Inner certificate structure ===")
parse_tlv(data, cert2_off)
