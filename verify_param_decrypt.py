#!/usr/bin/env python3
"""
验证 param AES key 是否正确，并解密 SID 0x12C (ENC_SECRECY) 内容
显示 intranet 字段和其他加密 SID 的全部内容
"""
import hashlib, struct, sys
from Cryptodome.Cipher import AES

PARAM_BIN = '/Users/xmxx/pinganhuijia/edl_backup/param.bin'
PARAM_PATCHED = '/Users/xmxx/pinganhuijia/edl_backup/param.bin.patched'

serial = 0xdb0c1e4b
raw = bytes.fromhex('a9264fbf8a' + ('%08x' % serial) + '6b4487ea')
print(f'raw ({len(raw)} bytes): {raw.hex()}')
key = hashlib.sha256(raw[:0x1a]).digest()[:16]
print(f'AES key: {key.hex()}')

IV = bytes.fromhex('562E17996D093D28DDB3BA695A2E6F58')

def decrypt_block(data, offset):
    block = data[offset:offset+0x1000]
    magic = struct.unpack_from('<I', block, 0)[0]
    hv = block[4]; cv = block[5]
    upd = block[0x10]
    stored_md5 = block[0x80:0x90]
    encdata = block[0x400:0x1000]

    cipher = AES.new(key, AES.MODE_CBC, IV)
    dec = cipher.decrypt(encdata)
    computed_md5 = hashlib.md5(dec).digest()
    ok = (stored_md5 == computed_md5)
    return ok, hv, cv, upd, stored_md5, computed_md5, dec

# SID names for encrypted blocks
SID_NAMES = {
    0x12C: 'ENC_SECRECY',
    0x12D: 'ENC_CARRIER',
    0x130: 'ENC_CARRIER2',
    0x134: 'ENC_MOBID',
    0x138: 'ENC_CVE',
}

# Known field offsets within decrypted data
ENC_SECRECY_FIELDS = {
    0x00: 'intranet',       # offset 0x80 in block → 0x00 in dec data
    0x04: 'devkmsg_enable', # 0x84
    0x08: 'field_0x88',
}

# The enc SIDs start at offset 0x4b000 in param.bin
# Each encrypted block is 0x1000 bytes (4 SIDs × 0x400)
# But looking at the actual file structure, let's scan

print('\n=== Original param.bin ===')
with open(PARAM_BIN, 'rb') as f:
    orig = f.read()

# Find encrypted blocks by magic 0xA0AD646A
ENC_MAGIC = 0xA0AD646A
for offset in range(0, len(orig) - 4, 0x400):
    magic = struct.unpack_from('<I', orig, offset)[0]
    if magic == ENC_MAGIC:
        print(f'\nFound enc block at offset 0x{offset:x}')
        ok, hv, cv, upd, stored_md5, computed_md5, dec = decrypt_block(orig, offset)
        print(f'  hv={hv}, cv={cv}, update_counter={upd}')
        print(f'  stored MD5:   {stored_md5.hex()}')
        print(f'  computed MD5: {computed_md5.hex()}')
        print(f'  Decryption {"SUCCESS ✓" if ok else "FAILED ✗ (wrong serial?)"}')
        if ok:
            # Print first 0x100 bytes decoded
            print(f'  First 32 bytes decrypted: {dec[:0x20].hex()}')
            # Check intranet value (offset 0x80 in block → offset 0 in dec)
            intranet = struct.unpack_from('<I', dec, 0)[0]
            print(f'  intranet (offset 0x80 in block): {intranet:#x} ({intranet})')
            # Print all non-zero 4-byte values
            for i in range(0, min(0x200, len(dec)), 4):
                val = struct.unpack_from('<I', dec, i)[0]
                if val != 0:
                    print(f'  dec[0x{i:02x}] = {val:#010x}')

print('\n=== Patched param.bin ===')
with open(PARAM_PATCHED, 'rb') as f:
    patched = f.read()

for offset in range(0, len(patched) - 4, 0x400):
    magic = struct.unpack_from('<I', patched, offset)[0]
    if magic == ENC_MAGIC:
        print(f'\nFound enc block at offset 0x{offset:x}')
        ok, hv, cv, upd, stored_md5, computed_md5, dec = decrypt_block(patched, offset)
        print(f'  hv={hv}, cv={cv}, update_counter={upd}')
        print(f'  Decryption {"SUCCESS ✓" if ok else "FAILED ✗"}')
        if ok:
            intranet = struct.unpack_from('<I', dec, 0)[0]
            print(f'  intranet (offset 0x80 in block): {intranet:#x} ({intranet})')
            for i in range(0, min(0x200, len(dec)), 4):
                val = struct.unpack_from('<I', dec, i)[0]
                if val != 0:
                    print(f'  dec[0x{i:02x}] = {val:#010x}')

# Also check plaintext changes
print('\n=== Plaintext changes (SID 0xC DOWNLOAD intranet_3t @ 0x1A4) ===')
off = 0x3000 + 0x1a4
print(f'  original[0x{off:x}]: {orig[off]:#x}')
print(f'  patched[0x{off:x}]:  {patched[off]:#x}')
