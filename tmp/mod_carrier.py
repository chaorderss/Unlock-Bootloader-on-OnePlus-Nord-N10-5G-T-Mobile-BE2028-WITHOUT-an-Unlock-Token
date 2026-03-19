#!/usr/bin/env python3
"""
Read and modify SID 0x130 (ENC_CARRIER).
Change carrier_id to 0 (non-TMO) and carrier_init_flag to 0.
Also restore SID 0x13C to its original cv=2 data from backup.
"""
import hashlib
import subprocess
import sys
from binascii import hexlify
from struct import pack, unpack
from Crypto.Cipher import AES

AES_KEY = bytes.fromhex('3030304F6E65506C7573383138303030')
AES_IV  = bytes.fromhex('562E17996D093D28DDB3BA695A2E6F58')
MAGIC = 0xA0AD646A

def decrypt_sid(block):
    """Decrypt a SID block. Returns (itemdata, hv, cv, update_counter) or None."""
    magic = unpack('<I', block[:4])[0]
    if magic != MAGIC:
        return None
    hv = block[4]
    cv = block[5]
    update_counter = block[0x10]

    enchash = block[0x80:0x90]
    encdata = block[0x400:0x400 + 0xC00]
    if hashlib.md5(encdata).digest() != enchash:
        print("  Ciphertext MD5 mismatch!")
        return None

    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    dec = cipher.decrypt(encdata)
    dechash = dec[:16]
    itemdata = bytearray(dec[-0xB80:])
    if hashlib.md5(bytes(itemdata)).digest() != dechash:
        print("  Plaintext MD5 mismatch!")
        return None

    return itemdata, hv, cv, update_counter

def encrypt_sid(itemdata, hv, cv, update_counter):
    """Encrypt itemdata into a full 0x1000 SID block."""
    siddata = bytearray(0x1000)
    siddata[:6] = pack('<IBB', MAGIC, hv, cv)
    siddata[0x10] = (update_counter + 1) & 0xFF

    header = bytearray(0x80)
    header[:16] = hashlib.md5(bytes(itemdata)).digest()
    plaintext = bytes(header) + bytes(itemdata)

    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    encdata = cipher.encrypt(plaintext)

    siddata[0x80:0x90] = hashlib.md5(encdata).digest()
    siddata[0x400:0x400 + 0xC00] = encdata
    return bytes(siddata)

# Read current param
print("Reading param partition...")
result = subprocess.run(['adb', 'shell', 'dd if=/dev/block/sda6 2>/dev/null'],
                       capture_output=True, timeout=30)
param = bytearray(result.stdout)
print(f"Param size: {len(param)}")

# ---- Restore SID 0x13C from backup ----
print("\n=== Restoring SID 0x13C from backup ===")
backup_path = '/Users/xmxx/pinganhuijia/edl_backup/pre_convert/param.bin'
try:
    with open(backup_path, 'rb') as f:
        orig_param = f.read()

    sid_13c_offset = 0x13C * 0x400
    sid_33c_offset = 0x33C * 0x400
    orig_block = orig_param[sid_13c_offset:sid_13c_offset + 0x1000]
    orig_backup = orig_param[sid_33c_offset:sid_33c_offset + 0x1000]

    print(f"Original SID 0x13C: cv={orig_block[5]}, update_counter={orig_block[0x10]}")
    param[sid_13c_offset:sid_13c_offset + 0x1000] = orig_block
    param[sid_33c_offset:sid_33c_offset + 0x1000] = orig_backup
    print("Restored original SID 0x13C and backup 0x33C")
except Exception as e:
    print(f"Warning: Could not restore SID 0x13C from backup: {e}")

# ---- Decode SID 0x130 (ENC_CARRIER) ----
print("\n=== Decoding SID 0x130 (ENC_CARRIER) ===")
sid_130_offset = 0x130 * 0x400
block_130 = param[sid_130_offset:sid_130_offset + 0x1000]
result_130 = decrypt_sid(block_130)

if result_130 is None:
    print("ERROR: Cannot decrypt SID 0x130!")
    sys.exit(1)

itemdata, hv, cv, update_counter = result_130
print(f"SID 0x130: hv={hv}, cv={cv}, update_counter={update_counter}")

# Parse fields (offsets relative to 0x80 in SID, but in itemdata: offset - 0x80)
fields = {
    0xA0: "CustFlag",
    0xA4: "CustFlagMigration",
    0xA8: "carrier_id",
    0xAC: "carrier_init_flag",
}

for offset, name in fields.items():
    idx = offset - 0x80
    val = unpack('<I', itemdata[idx:idx+4])[0]
    print(f"  {name} (0x{offset:X}): {val}")

# Also dump non-zero values in first 256 bytes
print("\nNon-zero values in itemdata:")
for i in range(0, min(256, len(itemdata)), 4):
    val = unpack('<I', itemdata[i:i+4])[0]
    if val != 0:
        print(f"  offset 0x{i+0x80:X} (itemdata[{i}]): {val} (0x{val:X})")

# ---- Modify carrier fields ----
print("\n=== Modifying SID 0x130 ===")
# Set carrier_id = 0 (was 1 = TMO)
itemdata[0xA8 - 0x80:0xA8 - 0x80 + 4] = pack('<I', 0)
# Set carrier_init_flag = 0 (force re-init?)
itemdata[0xAC - 0x80:0xAC - 0x80 + 4] = pack('<I', 0)
print("Set carrier_id=0, carrier_init_flag=0")

# Re-encrypt
new_block = encrypt_sid(itemdata, hv, cv, update_counter)

# Also update backup at SID 0x330
param[sid_130_offset:sid_130_offset + 0x1000] = new_block
backup_offset = 0x330 * 0x400
param[backup_offset:backup_offset + 0x1000] = encrypt_sid(itemdata, hv, cv, update_counter)
print("Written to primary SID 0x130 and backup SID 0x330")

# Verify
cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
dec = cipher.decrypt(new_block[0x400:0x400 + 0xC00])
verify_item = dec[-0xB80:]
carrier_id_v = unpack('<I', verify_item[0xA8-0x80:0xAC-0x80])[0]
carrier_init_v = unpack('<I', verify_item[0xAC-0x80:0xB0-0x80])[0]
print(f"Verify: carrier_id={carrier_id_v}, carrier_init_flag={carrier_init_v}")

# ---- Write param ----
print("\nWriting modified param...")
with open('/tmp/param_carrier_mod.bin', 'wb') as f:
    f.write(param)

result = subprocess.run(['adb', 'push', '/tmp/param_carrier_mod.bin', '/data/local/tmp/param_mod.bin'],
                       capture_output=True, timeout=30)
print(f"Push: {result.stdout.decode().strip()}")

result = subprocess.run(['adb', 'shell',
    'dd if=/data/local/tmp/param_mod.bin of=/dev/block/sda6 2>&1'],
                       capture_output=True, timeout=30)
print(f"Write: {result.stdout.decode().strip()}")

print("\nDone! Reboot to test carrier behavior.")
