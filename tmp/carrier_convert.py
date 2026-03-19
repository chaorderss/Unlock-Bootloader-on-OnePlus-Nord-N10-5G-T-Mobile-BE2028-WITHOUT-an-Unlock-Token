#!/usr/bin/env python3
"""
OnePlus Nord N10 5G T-Mobile -> Global Carrier Conversion Plan

This script:
1. Validates token generation locally
2. Generates the EDL commands needed
3. Documents the procedure

Device: OnePlus Nord N10 5G (BE2028), model 20888 (TMO), codename billie8t
Target: Convert to model 20886 (Global, billie8) to bypass T-Mobile carrier check
"""
import sys
import os
import time
import hashlib
from struct import pack
from binascii import hexlify, unhexlify

# Use pycryptodome directly (avoid cffi version mismatch)
try:
    from Crypto.Cipher import AES as _AES
except ImportError:
    from Cryptodome.Cipher import AES as _AES

def aes_cbc_encrypt(key, iv, data):
    cipher = _AES.new(key, _AES.MODE_CBC, iv)
    return cipher.encrypt(data)

def aes_cbc_decrypt(key, iv, data):
    cipher = _AES.new(key, _AES.MODE_CBC, iv)
    return cipher.decrypt(data)

def sha256(data):
    return hashlib.sha256(data).digest()

# Device config from oneplus.py
DEVICE_CONFIGS = {
    "20885": {"cm": "3a403a71", "name": "OP N10 5G Metro"},
    "20886": {"cm": "b8bd9e39", "name": "OP N10 5G Global"},
    "20888": {"cm": "142f1bd7", "name": "OP N10 5G TMO (current)"},
    "20889": {"cm": "f2056ae1", "name": "OP N10 5G Europe"},
}

# Hardcoded crypto parameters from edl oneplus.py
PRODKEY = "7016147d58e8c038"
RANDOM_POSTFIX = "c75oVnz8yUgLZObh"
VERSION = "billie8_14_E.01_201028"
HASH_SUFFIX = "8f7359c8a2951e8c"

AES_IV = b"\xDC\x91\x0D\x88\xE3\xC6\xEE\x65\xF0\xC7\x44\xB4\x02\x30\xCE\x40"
AES_KEY_PREFIX = b"\x46\xA5\x97\x30\xBB\x0D\x41\xE8"

# Device serial (from edl_config.json)
DEVICE_SERIAL = 1969577307

def generate_token(target_projid, serial, device_timestamp, pk_str):
    """Generate setswprojmodel token for carrier conversion."""
    cm = DEVICE_CONFIGS[target_projid]["cm"]

    timestamp = str(int(time.time()))

    # Hash chain
    h1 = PRODKEY + cm + RANDOM_POSTFIX
    model_verify_hash = hexlify(sha256(bytes(h1, 'utf-8'))).decode('utf-8').upper()

    h2 = PRODKEY + cm + str(serial) + VERSION + timestamp + model_verify_hash + HASH_SUFFIX
    secret = hexlify(sha256(bytes(h2, 'utf-8'))).decode('utf-8').upper()

    device_id = str(int(cm, 16))
    ato_build = "0"
    flash_mode = "0"

    items = [cm, RANDOM_POSTFIX, model_verify_hash, ato_build,
             flash_mode, VERSION, str(serial), device_id, timestamp, secret]

    data = ",".join(items)

    # Pad to 0x200 bytes
    while len(data) < 0x200:
        data += "\x00"

    # AES-CBC encrypt
    aes_key = AES_KEY_PREFIX + bytes(pk_str, 'utf-8') + pack("<Q", device_timestamp)
    pdata = bytes(data, 'utf-8')
    result = aes_cbc_encrypt(aes_key, AES_IV, pdata)
    token = hexlify(result).upper().decode('utf-8')

    return pk_str, token

def verify_token(target_projid, serial, device_timestamp, pk_str, token):
    """Verify a generated token by decrypting and checking hashes."""
    cm = DEVICE_CONFIGS[target_projid]["cm"]

    # Decrypt
    aes_key = AES_KEY_PREFIX + bytes(pk_str, 'utf-8') + pack("<Q", device_timestamp)
    cdata = unhexlify(token)
    result = aes_cbc_decrypt(aes_key, AES_IV, cdata)
    result = result.rstrip(b'\x00')
    items = result.decode('utf-8').split(',')

    print(f"\nDecrypted token items ({len(items)} total):")
    labels = ["CM", "random_postfix", "ModelVerifyHash", "ato_build",
              "flash_mode", "Version", "soc_sn", "device_id", "timestamp", "secret"]
    for i, item in enumerate(items):
        label = labels[i] if i < len(labels) else f"item[{i}]"
        print(f"  {label} = {item[:60]}{'...' if len(item) > 60 else ''}")

    # Verify hash chain
    h1 = PRODKEY + items[0] + items[1]
    expected_hash = hexlify(sha256(bytes(h1, 'utf-8'))).decode('utf-8').upper()
    hash_ok = items[2] == expected_hash

    h2 = PRODKEY + items[0] + items[6] + items[5] + items[8] + items[2] + HASH_SUFFIX
    expected_secret = hexlify(sha256(bytes(h2, 'utf-8'))).decode('utf-8').upper()
    secret_ok = items[9] == expected_secret

    print(f"\n  Hash verification: {'PASS' if hash_ok else 'FAIL'}")
    print(f"  Secret verification: {'PASS' if secret_ok else 'FAIL'}")

    return hash_ok and secret_ok

def main():
    print("=" * 60)
    print("OnePlus N10 5G Carrier Conversion Token Generator")
    print("=" * 60)

    # Target: Global (20886) - bypasses T-Mobile carrier check
    target = "20886"
    serial = DEVICE_SERIAL

    # Simulate device_timestamp (this would come from setprocstart in EDL)
    fake_timestamp = 2507003650  # from edl test code

    # Generate random pk (16 chars)
    import random
    import string
    pk = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

    print(f"\nCurrent model: 20888 ({DEVICE_CONFIGS['20888']['name']})")
    print(f"Target model:  {target} ({DEVICE_CONFIGS[target]['name']})")
    print(f"Serial: {serial}")
    print(f"Test timestamp: {fake_timestamp}")
    print(f"Random PK: {pk}")

    # Generate token
    pk_out, token = generate_token(target, serial, fake_timestamp, pk)
    print(f"\nGenerated token (first 80 chars): {token[:80]}...")
    print(f"Token length: {len(token)} hex chars ({len(token)//2} bytes)")

    # Verify
    print("\n--- Token Verification ---")
    ok = verify_token(target, serial, fake_timestamp, pk, token)

    if ok:
        print("\n✅ Token generation and verification SUCCESSFUL!")
        print("\n" + "=" * 60)
        print("EDL CONVERSION PROCEDURE")
        print("=" * 60)
        print("""
STEP 0: BACKUP (do this BEFORE EDL)
  # From Android (while device is still on):
  adb shell dd if=/dev/block/sda6 of=/data/local/tmp/param_backup.bin
  adb pull /data/local/tmp/param_backup.bin .

STEP 1: Boot to EDL mode
  adb reboot edl
  # Wait for Qualcomm 9008 device to appear

STEP 2: Run carrier conversion
  # Option A: Full conversion with edl modules
  edl modules ops enable --devicemodel=20886 --loader=auto

  # Option B: Manual steps
  # 2a. Get device timestamp:
  edl rawxml "<?xml version=\\"1.0\\" ?><data><setprocstart /></data>" --devicemodel=20888
  # Response: device_timestamp="XXXXXX"

  # 2b. Generate and send setswprojmodel:
  # (The edl tool does this automatically with --devicemodel=20886)

  # 2c. Write param partition with ops enabled:
  # (Also done automatically by edl modules ops enable)

STEP 3: Reboot to bootloader
  edl reset --resetmode=bootloader
  # OR: unplug USB, hold Vol Down + Power

STEP 4: Test unlock
  fastboot oem device-info
  fastboot oem unlock

RECOVERY (if something goes wrong):
  # Boot to EDL again
  adb reboot edl  (or hold Vol Up + Vol Down while connecting USB)

  # Restore param partition
  edl w param param_backup.bin --devicemodel=20888

  # Restore original model
  edl modules ops enable --devicemodel=20888
""")
    else:
        print("\n❌ Token verification FAILED!")

    # Also show available target models
    print("\nAvailable target models:")
    for pid, info in DEVICE_CONFIGS.items():
        marker = " ← CURRENT" if pid == "20888" else ""
        marker = " ← TARGET" if pid == target else marker
        print(f"  {pid}: {info['name']} (cm={info['cm']}){marker}")

if __name__ == "__main__":
    main()
