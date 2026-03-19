import struct, hashlib

def parse_certs_from_chain(cert_chain):
    """Split DER cert chain into individual certs."""
    certs = []
    pos = 0
    while pos < len(cert_chain):
        if cert_chain[pos] != 0x30:
            break
        # Read DER SEQUENCE length
        if cert_chain[pos+1] & 0x80:
            # Long form
            len_bytes = cert_chain[pos+1] & 0x7f
            cert_len = int.from_bytes(cert_chain[pos+2:pos+2+len_bytes], 'big') + 2 + len_bytes
        else:
            cert_len = cert_chain[pos+1] + 2
        cert = cert_chain[pos:pos+cert_len]
        certs.append(cert)
        pos += cert_len
        if pos >= len(cert_chain) - 4:
            break
    return certs

def get_cert_chain_from_abl(filename):
    with open(filename,'rb') as f:
        data = f.read()
    hs = data[0x1000:0x1000+0x19a0]
    sig_size = struct.unpack_from('<I', hs, 0x1c)[0]
    cert_chain_size = struct.unpack_from('<I', hs, 0x24)[0]
    code_size = struct.unpack_from('<I', hs, 0x14)[0]
    cert_start = 0x90 + code_size + sig_size
    return hs[cert_start:cert_start+cert_chain_size]

import os
os.chdir('/Users/xmxx/pinganhuijia')

tmo_chain = get_cert_chain_from_abl('edl_backup/abl_b.img')
glo_chain = get_cert_chain_from_abl('global_abl_raw.img')

tmo_certs = parse_certs_from_chain(tmo_chain)
glo_certs = parse_certs_from_chain(glo_chain)

print(f"T-Mobile cert chain: {len(tmo_certs)} certificates")
for i, c in enumerate(tmo_certs):
    print(f"  cert[{i}]: {len(c)} bytes, sha256={hashlib.sha256(c).hexdigest()[:32]}...")

print(f"\nGlobal cert chain: {len(glo_certs)} certificates")
for i, c in enumerate(glo_certs):
    print(f"  cert[{i}]: {len(c)} bytes, sha256={hashlib.sha256(c).hexdigest()[:32]}...")

# Compare cert by cert (root cert is typically the LAST one)
print()
max_certs = max(len(tmo_certs), len(glo_certs))
for i in range(max_certs):
    if i < len(tmo_certs) and i < len(glo_certs):
        match = "MATCH" if tmo_certs[i] == glo_certs[i] else "DIFFER"
        # For root cert comparison (last cert usually)
        label = "ROOT?" if i == max_certs-1 else f"cert[{i}]"
        print(f"  {label} ({len(tmo_certs[i-max_certs])}B vs {len(glo_certs[i-max_certs])}B): {match}")
    elif i < len(tmo_certs):
        print(f"  cert[{i}] only in T-Mobile chain")
    else:
        print(f"  cert[{i}] only in Global chain")

# Show last cert (root) first bytes for both - if it starts with 3082 it's DER
if tmo_certs and glo_certs:
    print(f"\nT-Mobile LAST cert (likely root): {tmo_certs[-1][:30].hex()}")
    print(f"Global   LAST cert (likely root): {glo_certs[-1][:30].hex()}")
    if tmo_certs[-1] == glo_certs[-1]:
        print("\n✓ ROOT CERTS ARE IDENTICAL! Global ABL should pass XBL on T-Mobile!")
    else:
        print("\n✗ Root certs differ - may or may not pass XBL on T-Mobile")
