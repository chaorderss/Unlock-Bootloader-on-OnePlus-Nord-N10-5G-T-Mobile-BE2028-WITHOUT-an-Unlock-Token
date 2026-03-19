#!/usr/bin/env python3
"""Verify the correct data layout and offset mapping for SID 0x13C."""
import hashlib, struct
from Crypto.Cipher import AES

IV = bytes.fromhex('562E17996D093D28DDB3BA695A2E6F58')
key = hashlib.sha256(b'a9264fbf8a75655d5b6b4487ea').digest()[:16]

with open('/tmp/param_after_boot.bin', 'rb') as f:
    data = f.read()

offset = 0x13C * 0x400
block = data[offset:offset+0x1000]
enc = block[0x400:0x400+0xC00]
cipher = AES.new(key, AES.MODE_CBC, IV)
dec = cipher.decrypt(enc)

# Hex dump first 0x110 bytes of decrypted block
print('=== Decrypted block hex dump ===')
for i in range(0, 0x110, 16):
    hexb = dec[i:i+16].hex()
    asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in dec[i:i+16])
    print(f'  dec[0x{i:03X}]: {hexb}  {asc}')

# itemdata = last 0xB80 bytes = dec[0x80:]
itemdata = dec[-0xB80:]

print('\n=== Key offset comparisons ===')
print(f'dec[0x80:0x84] = itemdata[0x00:0x04] = {struct.unpack("<I", dec[0x80:0x84])[0]}')
print(f'dec[0x84:0x88] = itemdata[0x04:0x08] = 0x{struct.unpack("<I", dec[0x84:0x88])[0]:08X}')
print(f'dec[0x88:0x8C] = itemdata[0x08:0x0C] = {struct.unpack("<I", dec[0x88:0x8C])[0]}')
print()
print(f'dec[0x100:0x104] = itemdata[0x80:0x84] = {struct.unpack("<I", dec[0x100:0x104])[0]}')
print(f'dec[0x104:0x108] = itemdata[0x84:0x88] = 0x{struct.unpack("<I", dec[0x104:0x108])[0]:08X}')
print(f'dec[0x108:0x10C] = itemdata[0x88:0x8C] = {struct.unpack("<I", dec[0x108:0x10C])[0]}')

print('\n=== ABL ReadParam offsets mapping ===')
print('ABL: ReadParam(0x13C, 0x80) -> supported_flag')
print('ABL: ReadParam(0x13C, 0x84) -> SoftwareProjectID')
print('ABL: ReadParam(0x13C, 0x88) -> sw_proj_id_proc')
print()
print('If offset is into DECRYPTED BLOCK (dec[offset]):')
print(f'  dec[0x80] = {struct.unpack("<I", dec[0x80:0x84])[0]} (supported_flag?)')
print(f'  dec[0x84] = 0x{struct.unpack("<I", dec[0x84:0x88])[0]:08X} (SoftwareProjectID?)')
print(f'  dec[0x88] = {struct.unpack("<I", dec[0x88:0x8C])[0]} (sw_proj_id_proc?)')
print()
print('If offset is into ITEMDATA (itemdata[offset]):')
print(f'  itemdata[0x80] = {struct.unpack("<I", itemdata[0x80:0x84])[0]}')
print(f'  itemdata[0x84] = 0x{struct.unpack("<I", itemdata[0x84:0x88])[0]:08X}')
print(f'  itemdata[0x88] = {struct.unpack("<I", itemdata[0x88:0x8C])[0]}')

# Check the MD5
dechash = dec[:16]
computed_md5 = hashlib.md5(itemdata).digest()
print(f'\nMD5 stored:   {dechash.hex()}')
print(f'MD5 computed: {computed_md5.hex()}')
print(f'MD5 match: {dechash == computed_md5}')

# Also check the ORIGINAL backup for comparison
print('\n=== Original param backup comparison ===')
try:
    with open('/Users/xmxx/pinganhuijia/edl_backup/pre_convert/param.bin', 'rb') as f:
        orig = f.read()

    oblock = orig[offset:offset+0x1000]
    oenc = oblock[0x400:0x400+0xC00]
    ocipher = AES.new(key, AES.MODE_CBC, IV)
    odec = ocipher.decrypt(oenc)
    oitemdata = odec[-0xB80:]

    print(f'Original dec[0x80:0x84] = {struct.unpack("<I", odec[0x80:0x84])[0]}')
    print(f'Original dec[0x84:0x88] = 0x{struct.unpack("<I", odec[0x84:0x88])[0]:08X}')
    print(f'Original dec[0x88:0x8C] = {struct.unpack("<I", odec[0x88:0x8C])[0]}')
    print()
    print(f'Original itemdata[0x80:0x84] = {struct.unpack("<I", oitemdata[0x80:0x84])[0]}')
    print(f'Original itemdata[0x84:0x88] = 0x{struct.unpack("<I", oitemdata[0x84:0x88])[0]:08X}')
    print(f'Original itemdata[0x88:0x8C] = {struct.unpack("<I", oitemdata[0x88:0x8C])[0]}')

    # Find all non-zero dwords in the first 0x100 bytes of itemdata
    print('\n=== Non-zero dwords in first 0x100 bytes of original itemdata ===')
    for i in range(0, 0x100, 4):
        val = struct.unpack("<I", oitemdata[i:i+4])[0]
        if val != 0:
            print(f'  itemdata[0x{i:03X}] = {val} (0x{val:08X})')
except Exception as e:
    print(f'Error reading original: {e}')
