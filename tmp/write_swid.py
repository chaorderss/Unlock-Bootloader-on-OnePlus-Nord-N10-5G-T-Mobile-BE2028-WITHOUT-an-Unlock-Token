#!/usr/bin/env python3
"""
Write SoftwareProjectID=20886 and sw_proj_id_proc=1 to SID 0x13C.
Uses the correct ASCII-derived key for cv=2 encryption.
Also restores carrier_id in SID 0x130 to original values.
"""
import hashlib
import subprocess
import sys
from binascii import hexlify
from struct import pack, unpack
from Crypto.Cipher import AES

# Key derivation: SHA-256 of ASCII string (not hex-decoded bytes!)
SERIAL_SOC = 1969577307  # 0x75655d5b
ascii_derivation = ("a9264fbf8a" + ("%08x" % SERIAL_SOC) + "6b4487ea").encode('ascii')
KEY_13C = hashlib.sha256(ascii_derivation).digest()[:16]
print(f"SID 0x13C key: {hexlify(KEY_13C).decode()}")

# Static key for SID 0x130 (mode=0)
KEY_STATIC = bytes.fromhex('3030304F6E65506C7573383138303030')

IV = bytes.fromhex('562E17996D093D28DDB3BA695A2E6F58')
MAGIC = 0xA0AD646A

def decrypt_sid(block, key):
    magic = unpack('<I', block[:4])[0]
    if magic != MAGIC:
        return None
    hv, cv = block[4], block[5]
    update_counter = block[0x10]

    enchash = block[0x80:0x90]
    encdata = block[0x400:0x400 + 0xC00]
    if hashlib.md5(encdata).digest() != enchash:
        print("  Ciphertext MD5 mismatch!")
        return None

    cipher = AES.new(key, AES.MODE_CBC, IV)
    dec = cipher.decrypt(encdata)
    dechash = dec[:16]
    itemdata = bytearray(dec[-0xB80:])
    if hashlib.md5(bytes(itemdata)).digest() != dechash:
        print("  Plaintext MD5 mismatch!")
        return None

    return itemdata, hv, cv, update_counter

def encrypt_sid(itemdata, hv, cv, update_counter, key):
    siddata = bytearray(0x1000)
    siddata[:6] = pack('<IBB', MAGIC, hv, cv)
    siddata[0x10] = (update_counter + 1) & 0xFF

    header = bytearray(0x80)
    header[:16] = hashlib.md5(bytes(itemdata)).digest()
    plaintext = bytes(header) + bytes(itemdata)

    cipher = AES.new(key, AES.MODE_CBC, IV)
    encdata = cipher.encrypt(plaintext)

    siddata[0x80:0x90] = hashlib.md5(encdata).digest()
    siddata[0x400:0x400 + 0xC00] = encdata
    return bytes(siddata)

# Read current param
print("\nReading param partition...")
result = subprocess.run(['adb', 'shell', 'dd if=/dev/block/sda6 2>/dev/null'],
                       capture_output=True, timeout=30)
param = bytearray(result.stdout)
print(f"Param size: {len(param)}")

# ===== Restore SID 0x13C from original backup first =====
backup_path = '/Users/xmxx/pinganhuijia/edl_backup/pre_convert/param.bin'
with open(backup_path, 'rb') as f:
    orig_param = f.read()

sid_13c_offset = 0x13C * 0x400
orig_block_13c = orig_param[sid_13c_offset:sid_13c_offset + 0x1000]
param[sid_13c_offset:sid_13c_offset + 0x1000] = orig_block_13c

# Also restore backup SID 0x33C
sid_33c_offset = 0x33C * 0x400
orig_block_33c = orig_param[sid_33c_offset:sid_33c_offset + 0x1000]
param[sid_33c_offset:sid_33c_offset + 0x1000] = orig_block_33c
print("Restored original SID 0x13C and 0x33C from backup")

# ===== Restore SID 0x130 (carrier) from original backup =====
sid_130_offset = 0x130 * 0x400
orig_block_130 = orig_param[sid_130_offset:sid_130_offset + 0x1000]
param[sid_130_offset:sid_130_offset + 0x1000] = orig_block_130

sid_330_offset = 0x330 * 0x400
orig_block_330 = orig_param[sid_330_offset:sid_330_offset + 0x1000]
param[sid_330_offset:sid_330_offset + 0x1000] = orig_block_330
print("Restored original SID 0x130 and 0x330 from backup")

# ===== Now decrypt and modify SID 0x13C =====
print("\n=== Modifying SID 0x13C ===")
block_13c = param[sid_13c_offset:sid_13c_offset + 0x1000]
result_13c = decrypt_sid(block_13c, KEY_13C)
if result_13c is None:
    print("ERROR: Cannot decrypt SID 0x13C!")
    sys.exit(1)

itemdata, hv, cv, update_counter = result_13c
print(f"Current SID 0x13C: hv={hv}, cv={cv}, update_counter={update_counter}")

# Dump current values
supported = unpack('<I', itemdata[0:4])[0]  # offset 0x80
swid = unpack('<I', itemdata[4:8])[0]       # offset 0x84
proc = unpack('<I', itemdata[8:12])[0]      # offset 0x88
print(f"  supported_flag (0x80): {supported}")
print(f"  SoftwareProjectID (0x84): {swid} (0x{swid:08X})")
print(f"  sw_proj_id_proc (0x88): {proc}")

# Set new values
TARGET_SWID = 20886  # 0x5196 = Global model
itemdata[4:8] = pack('<I', TARGET_SWID)
itemdata[8:12] = pack('<I', 1)  # sw_proj_id_proc = 1 (activated)
print(f"\nNew values: SoftwareProjectID={TARGET_SWID}, sw_proj_id_proc=1")

# Re-encrypt with correct key and keep cv=2
new_block_13c = encrypt_sid(itemdata, hv, cv, update_counter, KEY_13C)

# Verify
verify = decrypt_sid(new_block_13c, KEY_13C)
if verify is None:
    print("ERROR: Verification failed!")
    sys.exit(1)
v_swid = unpack('<I', verify[0][4:8])[0]
v_proc = unpack('<I', verify[0][8:12])[0]
print(f"Verified: SWID={v_swid}, proc={v_proc}")

# Write to primary and backup
param[sid_13c_offset:sid_13c_offset + 0x1000] = new_block_13c
param[sid_33c_offset:sid_33c_offset + 0x1000] = encrypt_sid(itemdata, hv, cv, update_counter, KEY_13C)
print("Written to SID 0x13C and backup 0x33C")

# ===== Write param =====
print("\nWriting modified param partition...")
with open('/tmp/param_swid.bin', 'wb') as f:
    f.write(param)

result = subprocess.run(['adb', 'push', '/tmp/param_swid.bin', '/data/local/tmp/param_mod.bin'],
                       capture_output=True, timeout=30)
print(f"Push: {result.stdout.decode().strip()}")

result = subprocess.run(['adb', 'shell',
    'dd if=/data/local/tmp/param_mod.bin of=/dev/block/sda6 2>&1'],
                       capture_output=True, timeout=30)
print(f"Write: {result.stdout.decode().strip()}")

# ===== Verify write =====
print("\nVerifying write...")
result = subprocess.run(['adb', 'shell', 'dd if=/dev/block/sda6 2>/dev/null'],
                       capture_output=True, timeout=30)
verify_param = result.stdout
v_block = verify_param[sid_13c_offset:sid_13c_offset + 0x1000]
v_result = decrypt_sid(v_block, KEY_13C)
if v_result:
    v_swid = unpack('<I', v_result[0][4:8])[0]
    v_proc = unpack('<I', v_result[0][8:12])[0]
    print(f"Readback verified: SWID={v_swid}, proc={v_proc}")
else:
    print("WARNING: Readback verification failed!")

print("\n=== SUCCESS ===")
print("SoftwareProjectID set to 20886 (Global)")
print("sw_proj_id_proc set to 1 (activated)")
print("\nReboot to bootloader to test:")
print("  adb reboot bootloader")
print("  fastboot oem device-info")
print("  fastboot oem unlock")
