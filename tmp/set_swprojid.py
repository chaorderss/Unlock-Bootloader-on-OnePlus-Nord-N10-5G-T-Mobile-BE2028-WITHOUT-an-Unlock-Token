#!/usr/bin/env python3
"""
Modify SID 0x13C in param partition to set SoftwareProjectID.
ABL reads from SID 0x13C (316), NOT 0x12C:
  - offset 0x84 (itemdata[4]): SoftwareProjectID
  - offset 0x88 (itemdata[8]): sw_proj_id_proc (activation flag)
"""
import hashlib
import sys
from binascii import hexlify
from struct import unpack, pack
from Crypto.Cipher import AES

AES_KEY = bytes.fromhex('3030304F6E65506C7573383138303030')  # static key
AES_IV = bytes.fromhex('562E17996D093D28DDB3BA695A2E6F58')

TARGET_SWID = 20886  # Global model
ACTIVATION = 1       # sw_proj_id_proc activation flag

def decrypt_sid(data, sid):
    offset = sid * 0x400
    block = data[offset:offset + 0x1000]

    magic = unpack('<I', block[:4])[0]
    if magic != 0xA0AD646A:
        print(f"  SID 0x{sid:X}: Magic 0x{magic:08X} != 0xA0AD646A")
        return None, None, None, None

    hv = block[4]
    cv = block[5]
    updatecounter = unpack('<I', block[8:0xC])[0]

    enchash = block[0x80:0x90]
    encdata = block[0x400:0x400 + 0xC00]

    if hashlib.md5(encdata).digest() != enchash:
        print("  Ciphertext MD5 mismatch!")
        return None, None, None, None

    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    decdata = cipher.decrypt(encdata)

    dechash = decdata[:16]
    itemdata = decdata[-0xB80:]

    if hashlib.md5(itemdata).digest() != dechash:
        print("  Plaintext MD5 mismatch!")
        return None, None, None, None

    return bytearray(itemdata), hv, cv, updatecounter

def encrypt_sid(itemdata, hv, cv, updatecounter):
    updatecounter += 1
    dechash = hashlib.md5(bytes(itemdata)).digest()
    padding = b'\x00' * (0xC00 - 0xB80 - 16)
    decdata = dechash + padding + bytes(itemdata)

    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    encdata = cipher.encrypt(decdata)
    enchash = hashlib.md5(encdata).digest()

    mdata = bytearray(0x1000)
    mdata[:4] = pack("<I", 0xA0AD646A)
    mdata[4] = hv
    mdata[5] = cv
    mdata[8:0xC] = pack("<I", updatecounter)
    mdata[0x80:0x90] = enchash
    mdata[0x400:0x400 + 0xC00] = encdata
    return mdata

# Read param from device
import subprocess
print("Reading param partition from device...")
result = subprocess.run(['adb', 'shell', 'dd if=/dev/block/sda6 2>/dev/null'],
                       capture_output=True, timeout=30)
data = bytearray(result.stdout)
print(f"  Read {len(data)} bytes")

# Check SID 0x13C
sid = 0x13C
print(f"\n== Decrypting SID 0x{sid:X} ({sid}) ==")
itemdata, hv, cv, counter = decrypt_sid(data, sid)
if itemdata is None:
    print("ERROR: Failed to decrypt SID 0x13C!")
    sys.exit(1)

print(f"  hv={hv}, cv={cv}, updatecounter={counter}")
print(f"  First 32 bytes: {hexlify(itemdata[:32]).decode()}")

# Read current values
# offset 0x84 → itemdata[0x84-0x80] = itemdata[4]
# offset 0x88 → itemdata[0x88-0x80] = itemdata[8]
current_swid = unpack('<I', itemdata[4:8])[0]
current_proc = unpack('<I', itemdata[8:12])[0]
print(f"\n  Current SoftwareProjectID (offset 0x84): {current_swid}")
print(f"  Current sw_proj_id_proc (offset 0x88): {current_proc}")

# Set new values
print(f"\n  Setting SoftwareProjectID = {TARGET_SWID}")
print(f"  Setting sw_proj_id_proc = {ACTIVATION}")
itemdata[4:8] = pack('<I', TARGET_SWID)
itemdata[8:12] = pack('<I', ACTIVATION)

# Verify
new_swid = unpack('<I', itemdata[4:8])[0]
new_proc = unpack('<I', itemdata[8:12])[0]
print(f"  Verify: SoftwareProjectID = {new_swid}, sw_proj_id_proc = {new_proc}")

# Re-encrypt
mdata = encrypt_sid(itemdata, hv, cv, counter)

# Write back to param
offset = sid * 0x400
data[offset:offset + 0x1000] = mdata

# Verify round-trip
itemdata2, _, _, _ = decrypt_sid(data, sid)
if itemdata2 is not None:
    rt_swid = unpack('<I', itemdata2[4:8])[0]
    rt_proc = unpack('<I', itemdata2[8:12])[0]
    print(f"\n  Round-trip verify: SWID={rt_swid}, proc={rt_proc}")
    if rt_swid != TARGET_SWID or rt_proc != ACTIVATION:
        print("  ERROR: Round-trip verification failed!")
        sys.exit(1)
else:
    print("  ERROR: Round-trip decryption failed!")
    sys.exit(1)

# Write modified param to file
outfile = '/Users/xmxx/pinganhuijia/tmp/param_modified.bin'
with open(outfile, 'wb') as f:
    f.write(data)
print(f"\n  Modified param saved to: {outfile}")

# Push to device
print("\nWriting modified param to device...")
# Write via adb (from Android with root)
subprocess.run(['adb', 'push', outfile, '/data/local/tmp/param_modified.bin'], check=True, timeout=30)
result = subprocess.run(['adb', 'shell',
    'dd if=/data/local/tmp/param_modified.bin of=/dev/block/sda6 2>&1'],
    capture_output=True, text=True, timeout=30)
print(f"  dd output: {result.stdout.strip()}")

# Verify write
print("\nVerifying write...")
result2 = subprocess.run(['adb', 'shell', 'dd if=/dev/block/sda6 2>/dev/null'],
                        capture_output=True, timeout=30)
written = bytearray(result2.stdout)
block_orig = data[offset:offset + 0x1000]
block_written = written[offset:offset + 0x1000]
if block_orig == block_written:
    print("  VERIFIED: SID 0x13C written correctly!")
else:
    print("  WARNING: Written data doesn't match!")
    print(f"  Expected: {hexlify(block_orig[:32]).decode()}")
    print(f"  Got:      {hexlify(block_written[:32]).decode()}")

print("\nDone! Reboot to bootloader and try: fastboot oem unlock")
