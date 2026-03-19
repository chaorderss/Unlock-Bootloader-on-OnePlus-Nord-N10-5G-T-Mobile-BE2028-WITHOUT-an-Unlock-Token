import struct, hashlib

def find_der_certs_in_data(data):
    """Find DER SEQUENCE encoded X.509 certs by scanning for 0x30 0x82."""
    certs = []
    pos = 0
    while pos < len(data) - 10:
        if data[pos] == 0x30 and data[pos+1] == 0x82:
            # 2-byte length
            cert_len = struct.unpack_from('>H', data, pos+2)[0] + 4
            if pos + cert_len <= len(data):
                cert = data[pos:pos+cert_len]
                certs.append((pos, cert))
                pos += cert_len
                continue
        pos += 1
    return certs

def get_hash_segment(filename):
    with open(filename,'rb') as f:
        data = f.read()
    # Hash segment at PH[1]: type=0x0, flags=0x2200000, at offset 0x1000
    hs = data[0x1000:0x1000+0x19a0]
    return hs, data

import os
os.chdir('/Users/xmxx/pinganhuijia')

print("=== T-Mobile ABL ===")
tmo_hs, _ = get_hash_segment('edl_backup/abl_b.img')
tmo_certs = find_der_certs_in_data(tmo_hs)
print(f"Found {len(tmo_certs)} certs:")
for pos, c in tmo_certs:
    print(f"  offset 0x{pos:x}: {len(c)} bytes, sha256={hashlib.sha256(c).hexdigest()[:40]}...")

print()
print("=== Global ABL ===")
glo_hs, _ = get_hash_segment('global_abl_raw.img')
glo_certs = find_der_certs_in_data(glo_hs)
print(f"Found {len(glo_certs)} certs:")
for pos, c in glo_certs:
    print(f"  offset 0x{pos:x}: {len(c)} bytes, sha256={hashlib.sha256(c).hexdigest()[:40]}...")

print()
if tmo_certs and glo_certs:
    print("=== Comparison ===")
    n = min(len(tmo_certs), len(glo_certs))
    for i in range(n):
        _, tc = tmo_certs[i]
        _, gc = glo_certs[i]
        match = "IDENTICAL" if tc == gc else "DIFFERS"
        print(f"  Cert {i+1} (last={i==n-1}): {match}  ({len(tc)}B vs {len(gc)}B)")

    # Root cert is typically the last one
    if len(tmo_certs) > 0 and len(glo_certs) > 0:
        _, tmo_root = tmo_certs[-1]
        _, glo_root = glo_certs[-1]
        if tmo_root == glo_root:
            print("\n✓ ROOT/LAST CERT IDENTICAL - same root key, Global ABL should pass XBL verification!")
        else:
            print("\n✗ Last cert differs")

# Also look at raw bytes around the cert area
print()
print("T-Mobile hash segment non-zero range:")
last_nz = len(tmo_hs)
while last_nz > 0 and tmo_hs[last_nz-1] == 0:
    last_nz -= 1
print(f"  Non-zero: 0x000 to 0x{last_nz:x} ({last_nz} bytes)")

# Show first few bytes of potential cert area
print(f"  Bytes at 0x100-0x120: {tmo_hs[0x100:0x120].hex()}")
print(f"  Bytes at 0x150-0x160: {tmo_hs[0x150:0x160].hex()}")
print(f"  Bytes at 0x180-0x196: {tmo_hs[0x180:0x196].hex()}")
