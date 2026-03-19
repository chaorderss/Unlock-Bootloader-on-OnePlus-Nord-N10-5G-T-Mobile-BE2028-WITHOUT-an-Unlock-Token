#!/usr/bin/env python3
"""
Exhaustive search for correct AES key derivation for param.bin
EDL chip serial = 0x75655d5b = 1969577307
"""
import struct, hashlib, itertools
from Cryptodome.Cipher import AES

PARAM_BIN = '/Users/xmxx/pinganhuijia/edl_backup/param.bin'
IV = bytes.fromhex('562E17996D093D28DDB3BA695A2E6F58')

with open(PARAM_BIN, 'rb') as f:
    orig = f.read()

blk = orig[0x4b000:0x4b000+0x1000]
encdata = blk[0x400:0x400+0xC00]

def check_key(key, label):
    if len(key) != 16:
        return False
    try:
        cipher = AES.new(key, AES.MODE_CBC, IV)
        decdata = cipher.decrypt(encdata)
        # CORRECT: itemdata = decdata[-0xB80:] = decdata[0x80:] for 0xC00 length
        inner_hash = decdata[:16]
        itemdata = decdata[-0xB80:]  # 0xC00 - 0xB80 = 0x80 offset
        computed = hashlib.md5(itemdata).digest()
        if inner_hash == computed:
            print(f"SUCCESS [{label}]: key={key.hex()}")
            for i in range(0, min(0x100, len(itemdata)), 4):
                v = struct.unpack_from('<I', itemdata, i)[0]
                if v:
                    print(f"  [{i:#04x}] {v:#010x}")
            return True
    except:
        pass
    return False

# Known serials
serials = {
    0x75655d5b: 'EDL chip serial',
    0xdb0c1e4b: 'androidboot.serialno',
    0x5b5d6575: 'BE of EDL serial',
    0x4b1e0cdb: 'BE of androidboot',
    1969577307: 'EDL serial decimal',
    0: 'zero',
}

def try_derivation(serial_int, label):
    # Original formula
    raw = bytes.fromhex('a9264fbf8a' + ('%08x' % serial_int) + '6b4487ea')
    key1 = hashlib.sha256(raw[:0x1a]).digest()[:16]
    check_key(key1, f'{label} | sha256([0x1a])')

    # Without truncation
    key2 = hashlib.sha256(raw).digest()[:16]
    check_key(key2, f'{label} | sha256(full)')

    # Different prefix/suffix ordering
    raw3 = bytes.fromhex('6b4487ea' + ('%08x' % serial_int) + 'a9264fbf8a')
    key3 = hashlib.sha256(raw3[:0x1a]).digest()[:16]
    check_key(key3, f'{label} | reversed prefix/suffix')

    # SHA256 of just the serial
    raw4 = struct.pack('<I', serial_int)
    key4 = hashlib.sha256(raw4).digest()[:16]
    check_key(key4, f'{label} | sha256(serial LE)')

    # MD5 derivation
    key5 = hashlib.md5(raw).digest()
    check_key(key5, f'{label} | md5(full)')

    # Direct raw as key (if 16 bytes) - nah, raw is 13 bytes

    # SHA1
    key6 = hashlib.sha1(raw).digest()[:16]
    check_key(key6, f'{label} | sha1(full)[:16]')

for serial_int, name in serials.items():
    try_derivation(serial_int, name)

# Try treating serial as decimal string in the hex formula
serial_decimal_str = str(1969577307)  # "1969577307"
serial_decimal_hex = serial_decimal_str.encode().hex()  # hex of ASCII bytes
print(f'\nSerial as ASCII hex: {serial_decimal_hex}')
raw_dec = bytes.fromhex('a9264fbf8a' + serial_decimal_hex[:8] + '6b4487ea')[:0x1a]
check_key(hashlib.sha256(raw_dec).digest()[:16], 'decimal_str_hex[:8]')

# Try with "androidboot.serialno" as a decimal string
# db0c1e4b as decimal = 3674081355
serial2_dec = str(0xdb0c1e4b)
serial2_hex = serial2_dec.encode().hex()
raw_dec2 = bytes.fromhex('a9264fbf8a' + serial2_hex[:8] + '6b4487ea')[:0x1a]
check_key(hashlib.sha256(raw_dec2).digest()[:16], 'androidboot decimal_str_hex[:8]')

# PCBA number as key input
pcba = b'002088880B28132410AA0KP0'
raw_pcba = bytes.fromhex('a9264fbf8a') + pcba[:4] + bytes.fromhex('6b4487ea')
check_key(hashlib.sha256(raw_pcba[:0x1a]).digest()[:16], 'PCBA number')

# The ENC_SECRECY block structure: maybe SID 0x12C is at offset 4 × 0x400 from enc start
# Actually: 0x12C * 0x400 = 0x4b000. Correct.
# But wait - maybe the wrong block is being tested. Let me check all blocks with correct serial.
print('\n=== Trying all blocks with EDL serial ===')
ENC_MAGIC = 0xA0AD646A
correct_serial = 0x75655d5b
raw_s = bytes.fromhex('a9264fbf8a' + ('%08x' % correct_serial) + '6b4487ea')
correct_key = hashlib.sha256(raw_s[:0x1a]).digest()[:16]
print(f'Key for EDL serial: {correct_key.hex()}')

for offset in range(0, len(orig) - 4, 0x400):
    if struct.unpack_from('<I', orig, offset)[0] == ENC_MAGIC:
        blk2 = orig[offset:offset+0x1000]
        enc2 = blk2[0x400:0x400+0xC00]
        enc_hash = blk2[0x80:0x90]
        # Check MD5(enc) matches
        if hashlib.md5(enc2).digest() != enc_hash:
            print(f'Block 0x{offset:x}: enc md5 mismatch')
            continue
        cipher2 = AES.new(correct_key, AES.MODE_CBC, IV)
        dec2 = cipher2.decrypt(enc2)
        inner = dec2[:16]
        item = dec2[-0xB80:]  # FIXED: decdata[-0xB80:]
        computed = hashlib.md5(item).digest()
        if inner == computed:
            print(f'Block 0x{offset:x}: DECRYPTED with EDL serial key!')
            break
        else:
            print(f'Block 0x{offset:x}: wrong key (inner hash mismatch)')
            break  # All same data
