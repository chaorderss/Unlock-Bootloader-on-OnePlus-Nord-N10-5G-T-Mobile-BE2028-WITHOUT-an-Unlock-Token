#!/usr/bin/env python3
"""Analyze param partition encryption to debug key derivation."""
import hashlib
from binascii import hexlify
from struct import unpack

# Read param backup
with open('/Users/xmxx/pinganhuijia/edl_backup/pre_convert/param.bin', 'rb') as f:
    data = f.read()

print(f'Param size: {len(data)} bytes')

# SID 0x12C encrypted section
sid = 0x12C
offset = sid * 0x400
print(f'SID 0x12C at offset: 0x{offset:X} ({offset})')
print(f'SID data (first 32 bytes): {hexlify(data[offset:offset+32]).decode()}')

# Check magic at beginning
magic = unpack('<I', data[offset:offset+4])[0]
print(f'Magic: 0x{magic:08X} (expected 0xA0AD646A)')

if magic != 0xA0AD646A:
    print("MAGIC MISMATCH! This SID might not be encrypted or wrong offset.")
    # Search for the magic in the entire file
    target = b'\x6a\x64\xad\xa0'  # little-endian
    pos = 0
    found = []
    while True:
        pos = data.find(target, pos)
        if pos == -1:
            break
        found.append(pos)
        pos += 1
    print(f"Found magic 0xA0AD646A at offsets: {[hex(p) for p in found]}")
    if found:
        # Use the first match
        offset = found[0]
        sid = offset // 0x400
        print(f"Using first match: offset=0x{offset:X}, SID=0x{sid:X}")
else:
    print("Magic matches!")

# Header: magic(4) + hv(1) + cv(1)
hv = data[offset+4]
cv = data[offset+5]
print(f"Header version: hv={hv}, cv={cv}")

# Encrypted hash at 0x80
enchash = data[offset+0x80:offset+0x90]
print(f'\nStored MD5 of encrypted blob: {hexlify(enchash).decode()}')

# Encrypted blob at 0x400 within the 0x1000 block
encdata = data[offset+0x400:offset+0x400+0xC00]
computed_md5 = hashlib.md5(encdata).digest()
print(f'Computed MD5 of encrypted blob: {hexlify(computed_md5).decode()}')
print(f'Ciphertext MD5 match: {enchash == computed_md5}')

if enchash != computed_md5:
    print("WARNING: Ciphertext integrity check failed!")
    import sys
    sys.exit(1)

# Trial decryption with different keys
from Crypto.Cipher import AES

iv = bytes.fromhex('562E17996D093D28DDB3BA695A2E6F58')

# Key 1: serial-derived (param_mode=1)
serial = 1969577307
derivedkey = bytes.fromhex('a9264fbf8a' + ('%08x' % serial) + '6b4487ea')
aes_key1 = hashlib.sha256(derivedkey).digest()[:16]
print(f'\n--- Key 1: serial-derived (serial=0x{serial:08x}) ---')
print(f'Input hex: a9264fbf8a{serial:08x}6b4487ea')
print(f'AES key: {hexlify(aes_key1).decode()}')

cipher1 = AES.new(aes_key1, AES.MODE_CBC, iv)
dec1 = cipher1.decrypt(encdata)
dechash1 = dec1[:16]
item1 = dec1[-0xB80:]
comp1 = hashlib.md5(item1).digest()
print(f'Stored plaintext MD5: {hexlify(dechash1).decode()}')
print(f'Computed plaintext MD5: {hexlify(comp1).decode()}')
print(f'Match: {dechash1 == comp1}')

# Key 2: static key (param_mode=0)
static_key = bytes.fromhex('3030304F6E65506C7573383138303030')
print(f'\n--- Key 2: static key (param_mode=0) ---')
print(f'AES key: {hexlify(static_key).decode()} ("000OnePlus818000")')

cipher2 = AES.new(static_key, AES.MODE_CBC, iv)
dec2 = cipher2.decrypt(encdata)
dechash2 = dec2[:16]
item2 = dec2[-0xB80:]
comp2 = hashlib.md5(item2).digest()
print(f'Stored plaintext MD5: {hexlify(dechash2).decode()}')
print(f'Computed plaintext MD5: {hexlify(comp2).decode()}')
print(f'Match: {dechash2 == comp2}')

# Key 3: Try with Android serial (db0c1e4b as int)
android_serial = int("db0c1e4b", 16)
derivedkey3 = bytes.fromhex('a9264fbf8a' + ('%08x' % android_serial) + '6b4487ea')
aes_key3 = hashlib.sha256(derivedkey3).digest()[:16]
print(f'\n--- Key 3: Android serial (0x{android_serial:08x}) ---')
print(f'AES key: {hexlify(aes_key3).decode()}')

cipher3 = AES.new(aes_key3, AES.MODE_CBC, iv)
dec3 = cipher3.decrypt(encdata)
dechash3 = dec3[:16]
item3 = dec3[-0xB80:]
comp3 = hashlib.md5(item3).digest()
print(f'Stored plaintext MD5: {hexlify(dechash3).decode()}')
print(f'Computed plaintext MD5: {hexlify(comp3).decode()}')
print(f'Match: {dechash3 == comp3}')

# Key 4: Try raw serial bytes without hex conversion
# Maybe the serial is packed differently
print(f'\n--- Key 4: Trying alternate serial formats ---')
for fmt_name, serial_str in [
    ("LE bytes", hexlify(serial.to_bytes(4, 'little')).decode()),
    ("BE bytes", hexlify(serial.to_bytes(4, 'big')).decode()),
    ("decimal string", hexlify(str(serial).encode()).decode()),
]:
    try:
        hex_input = 'a9264fbf8a' + serial_str[:8] + '6b4487ea'
        dk = bytes.fromhex(hex_input.ljust(26*2, '0')[:26*2])[:26]
        ak = hashlib.sha256(dk).digest()[:16]
        ci = AES.new(ak, AES.MODE_CBC, iv)
        dc = ci.decrypt(encdata)
        dh = dc[:16]
        itm = dc[-0xB80:]
        cm = hashlib.md5(itm).digest()
        match = dh == cm
        if match:
            print(f'  {fmt_name}: MATCH! key={hexlify(ak).decode()}')
        else:
            print(f'  {fmt_name}: no match')
    except Exception as e:
        print(f'  {fmt_name}: error: {e}')

# Also try no serial at all (zeros)
dk0 = bytes.fromhex('a9264fbf8a' + '00000000' + '6b4487ea')
ak0 = hashlib.sha256(dk0).digest()[:16]
ci0 = AES.new(ak0, AES.MODE_CBC, iv)
dc0 = ci0.decrypt(encdata)
dh0 = dc0[:16]
itm0 = dc0[-0xB80:]
cm0 = hashlib.md5(itm0).digest()
print(f'  zero serial: {"MATCH!" if dh0 == cm0 else "no match"}')
