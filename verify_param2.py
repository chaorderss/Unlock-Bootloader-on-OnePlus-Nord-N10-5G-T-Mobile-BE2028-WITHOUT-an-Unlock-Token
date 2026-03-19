#!/usr/bin/env python3
"""
Corrected param decryption verification.
The enchash at 0x80 is MD5(encdata), NOT MD5(decdata).
After decryption: decdata[0:16] = MD5(itemdata), decdata[16:] = itemdata.
"""
import struct, hashlib
from Cryptodome.Cipher import AES

PARAM_BIN = '/Users/xmxx/pinganhuijia/edl_backup/param.bin'
IV = bytes.fromhex('562E17996D093D28DDB3BA695A2E6F58')

with open(PARAM_BIN, 'rb') as f:
    orig = f.read()

# Test all 5 encrypted blocks
ENC_MAGIC = 0xA0AD646A
enc_offsets = []
for offset in range(0, len(orig) - 4, 0x400):
    if struct.unpack_from('<I', orig, offset)[0] == ENC_MAGIC:
        enc_offsets.append(offset)

print(f"Found {len(enc_offsets)} encrypted blocks: {[hex(o) for o in enc_offsets]}")

def try_decrypt_block(data_bytes, blk_offset, key, label):
    blk = data_bytes[blk_offset:blk_offset+0x1000]
    enchash = blk[0x80:0x90]
    encdata = blk[0x400:0x400+0xC00]

    # First check: MD5(encdata) == enchash
    gen_enc_md5 = hashlib.md5(encdata).digest()
    enc_ok = (gen_enc_md5 == enchash)

    if not enc_ok:
        print(f"  [{label}] enchash mismatch (data integrity fail)")
        return False

    # Decrypt
    cipher = AES.new(key, AES.MODE_CBC, IV)
    decdata = cipher.decrypt(encdata)
    inner_hash = decdata[:16]
    itemdata = decdata[16:]
    computed_inner = hashlib.md5(itemdata).digest()
    dec_ok = (inner_hash == computed_inner)

    if dec_ok:
        print(f"  [{label}] SUCCESS!")
        for i in range(0, min(0x100, len(itemdata)), 4):
            v = struct.unpack_from('<I', itemdata, i)[0]
            if v:
                print(f"    itemdata[0x{i:02x}] = {v:#010x}")
    else:
        print(f"  [{label}] inner hash mismatch (wrong key)")
    return dec_ok

# Key candidates
default_key = bytes.fromhex('3030304F6E65506C7573383138303030')  # 000OnePlus818000

def make_serial_key(serial_int):
    raw = bytes.fromhex('a9264fbf8a' + ('%08x' % serial_int) + '6b4487ea')
    return hashlib.sha256(raw[:0x1a]).digest()[:16]

print("\n=== Block 0x4b000 (SID 0x12C/ENC_SECRECY area) ===")

# First verify enchash integrity
blk = orig[0x4b000:0x4b000+0x1000]
enchash = blk[0x80:0x90]
encdata = blk[0x400:0x400+0xC00]
gen_enc_md5 = hashlib.md5(encdata).digest()
print(f"stored enchash: {enchash.hex()}")
print(f"md5(encdata):   {gen_enc_md5.hex()}")
print(f"enchash integrity: {'OK' if enchash == gen_enc_md5 else 'FAIL'}")

print("\nTrying keys:")
try_decrypt_block(orig, 0x4b000, default_key, 'default 000OnePlus818000')

serials_to_try = {
    'androidboot.serialno (db0c1e4b)': 0xdb0c1e4b,
    'EDL chip serial (75655d5b=1969577307)': 0x75655d5b,
    'reversed (4b1e0cdb)': 0x4b1e0cdb,
    'default (123456)': 123456,
}
for name, s in serials_to_try.items():
    k = make_serial_key(s)
    try_decrypt_block(orig, 0x4b000, k, f'{name} key={k.hex()[:16]}...')

print("\n=== Checking if enchash fix needed: raw MD5 of encdata ===")
for off in enc_offsets[:3]:
    blk2 = orig[off:off+0x1000]
    enchash2 = blk2[0x80:0x90]
    encdata2 = blk2[0x400:0x400+0xC00]
    gen2 = hashlib.md5(encdata2).digest()
    print(f"Block 0x{off:x}: stored={enchash2.hex()} md5_enc={gen2.hex()} match={enchash2==gen2}")
