#!/usr/bin/env python3
"""
Rewrite SID 0x13C with cv=1 encryption (static key) instead of cv=2.

Theory: ABL selects decryption key based on cv field:
  cv=1 → static key "000OnePlus818000"
  cv=2 → unknown key (currently blocking us)

By rewriting with cv=1, ABL should decrypt using the static key.
Sets SoftwareProjectID=20886 and sw_proj_id_proc=1.
Also rewrites backup SID 0x33C.
"""
import hashlib
import subprocess
import sys
from binascii import hexlify
from struct import pack, unpack
from Crypto.Cipher import AES

AES_KEY = bytes.fromhex('3030304F6E65506C7573383138303030')  # "000OnePlus818000"
AES_IV  = bytes.fromhex('562E17996D093D28DDB3BA695A2E6F58')
MAGIC = 0xA0AD646A

TARGET_SWID = 20886  # 0x5196 = Global model
TARGET_PROC = 1      # sw_proj_id_proc = 1 (activated)

def encrypt_sid(itemdata, hv, cv, update_counter):
    """Encrypt itemdata into a full 0x1000 SID block."""
    siddata = bytearray(0x1000)
    siddata[:6] = pack('<IBB', MAGIC, hv, cv)
    siddata[0x10] = (update_counter + 1) & 0xFF

    # Build plaintext: 0x80 byte header + 0xB80 itemdata = 0xC00
    header = bytearray(0x80)
    header[:16] = hashlib.md5(itemdata).digest()
    plaintext = bytes(header) + bytes(itemdata)
    assert len(plaintext) == 0xC00, f"Plaintext size {len(plaintext)} != 0xC00"

    # Encrypt
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    encdata = cipher.encrypt(plaintext)

    # Store encrypted data and its hash
    siddata[0x80:0x90] = hashlib.md5(encdata).digest()
    siddata[0x400:0x400 + 0xC00] = encdata
    return bytes(siddata)

def verify_block(block, label=""):
    """Verify a SID block can be decrypted with static key."""
    magic = unpack('<I', block[:4])[0]
    if magic != MAGIC:
        print(f"  {label} Verify: bad magic 0x{magic:08X}")
        return False

    enchash = block[0x80:0x90]
    encdata = block[0x400:0x400 + 0xC00]
    if hashlib.md5(encdata).digest() != enchash:
        print(f"  {label} Verify: ciphertext MD5 mismatch")
        return False

    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    dec = cipher.decrypt(encdata)
    dechash = dec[:16]
    itemdata = dec[-0xB80:]
    if hashlib.md5(itemdata).digest() != dechash:
        print(f"  {label} Verify: plaintext MD5 mismatch")
        return False

    print(f"  {label} Verify: OK! SWID={unpack('<I', itemdata[4:8])[0]}, proc={unpack('<I', itemdata[8:12])[0]}")
    return True

# ---- Step 1: Read current param ----
print("Reading param partition...")
result = subprocess.run(['adb', 'shell', 'dd if=/dev/block/sda6 2>/dev/null'],
                       capture_output=True, timeout=30)
param = bytearray(result.stdout)
print(f"Param size: {len(param)} bytes")

if len(param) != 1048576:
    print("ERROR: Unexpected param size!")
    sys.exit(1)

# ---- Step 2: Read current SID 0x13C ----
sid_offset = 0x13C * 0x400  # = 0x4F000
current_block = param[sid_offset:sid_offset + 0x1000]
magic = unpack('<I', current_block[:4])[0]
hv = current_block[4]
cv = current_block[5]
update_counter = current_block[0x10]
print(f"\nCurrent SID 0x13C: magic=0x{magic:08X} hv={hv} cv={cv} update_counter={update_counter}")

# ---- Step 3: Try to decrypt current block (should fail with static key) ----
print("Attempting decrypt of current SID 0x13C with static key...")
enchash = current_block[0x80:0x90]
encdata = current_block[0x400:0x400 + 0xC00]
cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
dec = cipher.decrypt(encdata)
dechash = dec[:16]
itemdata_raw = dec[-0xB80:]
current_dec_ok = (hashlib.md5(itemdata_raw).digest() == dechash)
print(f"  Decrypt with static key: {'OK' if current_dec_ok else 'FAILED (expected)'}")

# ---- Step 4: Build new itemdata ----
# Start from zeros (clean slate)
itemdata = bytearray(0xB80)

# Set SoftwareProjectID at offset 0x84 - 0x80 = 0x04
itemdata[4:8] = pack('<I', TARGET_SWID)

# Set sw_proj_id_proc at offset 0x88 - 0x80 = 0x08
itemdata[8:12] = pack('<I', TARGET_PROC)

print(f"\nNew itemdata: SWID={TARGET_SWID} (0x{TARGET_SWID:04X}), proc={TARGET_PROC}")

# ---- Step 5: Encrypt with cv=1 and static key ----
new_block = encrypt_sid(itemdata, hv=1, cv=1, update_counter=update_counter)
print(f"New block: hv=1 cv=1 update_counter={update_counter+1}")

# Verify our new block
print("\nVerifying new block...")
if not verify_block(new_block, "Primary"):
    print("ERROR: Self-verification failed!")
    sys.exit(1)

# ---- Step 6: Build backup block for SID 0x33C ----
backup_offset = 0x33C * 0x400  # = 0xCF000
backup_block = encrypt_sid(itemdata, hv=1, cv=1, update_counter=update_counter)
print("\nVerifying backup block...")
if not verify_block(backup_block, "Backup"):
    print("ERROR: Backup self-verification failed!")
    sys.exit(1)

# ---- Step 7: Write to param ----
param[sid_offset:sid_offset + 0x1000] = new_block
param[backup_offset:backup_offset + 0x1000] = backup_block

# Write via adb
print("\nWriting modified param partition...")
with open('/tmp/param_modified_13c.bin', 'wb') as f:
    f.write(param)

result = subprocess.run(['adb', 'push', '/tmp/param_modified_13c.bin', '/data/local/tmp/param_mod.bin'],
                       capture_output=True, timeout=30)
print(f"Push: {result.stdout.decode().strip()}")

result = subprocess.run(['adb', 'shell',
    'dd if=/data/local/tmp/param_mod.bin of=/dev/block/sda6 2>&1'],
                       capture_output=True, timeout=30)
print(f"Write: {result.stdout.decode().strip()}")

# ---- Step 8: Verify write ----
print("\nVerifying write...")
result = subprocess.run(['adb', 'shell', 'dd if=/dev/block/sda6 2>/dev/null'],
                       capture_output=True, timeout=30)
verify_param = result.stdout
v_block = verify_param[sid_offset:sid_offset + 0x1000]
v_magic = unpack('<I', v_block[:4])[0]
v_cv = v_block[5]
print(f"Read back SID 0x13C: magic=0x{v_magic:08X} cv={v_cv}")
verify_block(v_block, "Readback")

v_backup = verify_param[backup_offset:backup_offset + 0x1000]
v_b_magic = unpack('<I', v_backup[:4])[0]
print(f"Read back SID 0x33C: magic=0x{v_b_magic:08X} cv={v_backup[5]}")

print("\nDone! Reboot to bootloader to test: adb reboot bootloader")
print("Then check: fastboot oem device-info")
print("And try: fastboot oem unlock")
