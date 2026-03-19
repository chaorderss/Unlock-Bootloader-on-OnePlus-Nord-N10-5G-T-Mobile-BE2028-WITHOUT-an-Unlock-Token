import struct, hashlib

def get_cert_chain(filename):
    with open(filename,'rb') as f:
        data = f.read()
    # Hash segment at 0x1000, size 0x19a0
    hs = data[0x1000:0x1000+0x19a0]
    # cert chain size is at 0x24
    cert_chain_size = struct.unpack_from('<I', hs, 0x24)[0]  # 0x1800 = 6144
    sig_size = struct.unpack_from('<I', hs, 0x1c)[0]  # 0x68 = 104
    # the hash segment layout after the MBN header:
    # header (40+? bytes) | code hashes | signature | cert_chain
    # Total hash segment = header + code_size + sig_size + cert_chain_size
    code_size = struct.unpack_from('<I', hs, 0x14)[0]  # from field at 0x14
    # Header is 0x90 bytes (code_size value itself from earlier analysis)
    # Wait - header size varies. Let me try to find cert chain by offset from end
    # cert_chain is the last cert_chain_size bytes of the non-zero hash segment
    actual_hs_size = struct.unpack_from('<I', hs, 0x10)[0]  # image_size field
    print(f'  {filename}: actual_hs_size=0x{actual_hs_size:x} ({actual_hs_size}), '
          f'code_size=0x{code_size:x}, sig_size={sig_size}, cert_chain_size={cert_chain_size}')
    # cert_chain starts after: header(0x90) + code_hashes(code_size=0x90) + sig(0x68)
    # = 0x90 + 0x90 + 0x68 = 0x128 = 296 bytes from start of hash segment
    cert_start = 0x90 + code_size + sig_size
    cert_end = cert_start + cert_chain_size
    print(f'  cert_chain at hs[0x{cert_start:x}:0x{cert_end:x}]')
    cert = hs[cert_start:cert_end]
    md5 = hashlib.md5(cert).hexdigest()
    sha256 = hashlib.sha256(cert).hexdigest()
    print(f'  cert_chain MD5: {md5}')
    print(f'  cert_chain SHA256: {sha256[:32]}...')
    # Show first cert header
    print(f'  First cert bytes: {cert[:20].hex()}')
    return cert

import os
os.chdir('/Users/xmxx/pinganhuijia')
print("=== T-Mobile ABL cert chain ===")
tmo_cert = get_cert_chain('edl_backup/abl_b.img')
print()
print("=== Global ABL cert chain ===")
glo_cert = get_cert_chain('global_abl_raw.img')
print()
if tmo_cert == glo_cert:
    print("✓ CERT CHAINS ARE IDENTICAL - same OnePlus signing key!")
elif hashlib.md5(tmo_cert).hexdigest() != hashlib.md5(glo_cert).hexdigest():
    print("✗ cert chains differ")
    # Show diff area
    for i in range(0, min(len(tmo_cert), len(glo_cert)), 1):
        if tmo_cert[i] != glo_cert[i]:
            print(f"  First diff at 0x{i:x}")
            break
