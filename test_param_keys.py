#!/usr/bin/env python3
"""
测试不同 key 解密 param 加密块
"""
import struct, hashlib
from Cryptodome.Cipher import AES

PARAM_BIN = '/Users/xmxx/pinganhuijia/edl_backup/param.bin'
PARAM_PATCHED = '/Users/xmxx/pinganhuijia/edl_backup/param.bin.patched'

IV = bytes.fromhex('562E17996D093D28DDB3BA695A2E6F58')

def try_key(data, offset, key, label):
    enc_block = data[offset:offset+0x1000]
    stored_md5 = enc_block[0x80:0x90]
    encdata = enc_block[0x400:0x1000]
    cipher = AES.new(key, AES.MODE_CBC, IV)
    dec = cipher.decrypt(encdata)
    computed_md5 = hashlib.md5(dec).digest()
    ok = (stored_md5 == computed_md5)
    print(f'  [{label}] stored={stored_md5.hex()} computed={computed_md5.hex()} match={ok}')
    if ok:
        for i in range(0, min(0x100, len(dec)), 4):
            v = struct.unpack_from('<I', dec, i)[0]
            if v:
                print(f'    dec[0x{i:02x}] = {v:#010x}')
    return ok, dec

with open(PARAM_BIN, 'rb') as f:
    orig = f.read()
with open(PARAM_PATCHED, 'rb') as f:
    patched = f.read()

# Key candidates
default_key = bytes.fromhex('3030304F6E65506C7573383138303030')  # 000OnePlus818000

# Serial-derived keys - try various serial candidates
serials = {
    'androidboot.serialno (db0c1e4b)': 0xdb0c1e4b,
    'default (123456)': 123456,
    'PCBA-embedded (0B281324)': 0x0B281324,
    'pcba hex 002088880B28132410AA0KP0 bytes': int.from_bytes(b'002088880B28132410AA0K', 'big') & 0xFFFFFFFF,
}

def make_serial_key(serial_int):
    raw = bytes.fromhex('a9264fbf8a' + ('%08x' % serial_int) + '6b4487ea')
    return hashlib.sha256(raw[:0x1a]).digest()[:16]

print('=== Testing original param.bin block at 0x4b000 ===')

# Test default key
print('Testing default key (000OnePlus818000):')
ok, dec = try_key(orig, 0x4b000, default_key, 'default key')

# Test serial-derived keys
for name, serial_int in serials.items():
    key = make_serial_key(serial_int)
    print(f'Testing serial {name} ({serial_int:#x}) → key={key.hex()}:')
    ok, dec = try_key(orig, 0x4b000, key, name)

print('\n=== Testing patched param.bin block at 0x4b000 ===')
print('Testing default key on patched:')
ok, dec = try_key(patched, 0x4b000, default_key, 'default key patched')

# Try all 5 blocks in original
print('\n=== All encrypted blocks with default key ===')
ENC_MAGIC = 0xA0AD646A
for offset in range(0, len(orig) - 4, 0x400):
    magic = struct.unpack_from('<I', orig, offset)[0]
    if magic == ENC_MAGIC:
        ok, dec = try_key(orig, offset, default_key, f'0x{offset:x}')
        if ok:
            print(f'  SUCCESS at 0x{offset:x}!')
        break  # Only first block for quick test
