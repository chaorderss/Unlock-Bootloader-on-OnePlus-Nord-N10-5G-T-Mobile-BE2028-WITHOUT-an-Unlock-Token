#!/usr/bin/env python3
"""
Direct carrier conversion via setswprojmodel only.
Bypasses param partition modification (which needs device-specific encryption key).
Only sends setprocstart + setswprojmodel to change the SW project model.
"""
import sys
import os
import time
import hashlib
import random
import string
from struct import pack
from binascii import hexlify, unhexlify

# Fix cffi version mismatch: force correct python path
sys.path.insert(0, "/Library/Frameworks/Python.framework/Versions/3.14/lib/python3.14/site-packages")
# Remove conflicting homebrew paths
sys.path = [p for p in sys.path if 'homebrew' not in p.lower() or 'site-packages' not in p]

from edlclient.Library.sahara import sahara
from edlclient.Library.firehose import firehose
from edlclient.Library.Connection.usblib import usb_class
from edlclient.Library.utils import LogBase

# Target model config
TARGET_PROJID = "20886"  # Global
TARGET_CM = "b8bd9e39"   # CM for Global model
PRODKEY = "7016147d58e8c038"
RANDOM_POSTFIX = "c75oVnz8yUgLZObh"
VERSION = "billie8_14_E.01_201028"
HASH_SUFFIX = "8f7359c8a2951e8c"

AES_KEY_PREFIX = b"\x46\xA5\x97\x30\xBB\x0D\x41\xE8"
AES_IV = b"\xDC\x91\x0D\x88\xE3\xC6\xEE\x65\xF0\xC7\x44\xB4\x02\x30\xCE\x40"

def aes_cbc_encrypt(key, iv, data):
    from Cryptodome.Cipher import AES
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(data)

def sha256(data):
    return hashlib.sha256(data).digest()

def generate_token(serial, device_timestamp):
    """Generate setswprojmodel authentication token for Global model."""
    pk = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

    timestamp = str(int(time.time()))

    # Hash chain
    h1 = PRODKEY + TARGET_CM + RANDOM_POSTFIX
    model_verify_hash = hexlify(sha256(h1.encode())).decode().upper()

    device_id = str(int(TARGET_CM, 16))

    h2 = (PRODKEY + TARGET_CM + str(serial) + VERSION + timestamp +
          model_verify_hash + HASH_SUFFIX)
    secret = hexlify(sha256(h2.encode())).decode().upper()

    items = [TARGET_CM, RANDOM_POSTFIX, model_verify_hash, "0", "0",
             VERSION, str(serial), device_id, timestamp, secret]
    data = ",".join(items)

    # Pad to 0x200
    while len(data) < 0x200:
        data += "\x00"

    # AES-CBC encrypt
    aes_key = AES_KEY_PREFIX + pk.encode() + pack("<Q", device_timestamp)
    token = hexlify(aes_cbc_encrypt(aes_key, AES_IV, data.encode())).upper().decode()

    return pk, token

def main():
    print("=" * 60)
    print("OnePlus N10 5G: TMO -> Global Carrier Conversion")
    print("setswprojmodel only (no param modification)")
    print("=" * 60)

    # Read serial from config
    import json
    config_path = "/Users/xmxx/pinganhuijia/edl_config.json"
    if os.path.exists(config_path):
        with open(config_path) as f:
            config = json.load(f)
        serial = config.get("serial", 0)
        print(f"Serial from config: {serial} (0x{serial:08x})")
    else:
        print("ERROR: edl_config.json not found")
        return False

    print(f"Target model: {TARGET_PROJID} (Global, CM={TARGET_CM})")
    print()

    # Connect via edl tool's rawxml
    # We'll use subprocess to call edl commands
    import subprocess

    # Step 1: setprocstart to get device_timestamp
    print("[1/2] Sending setprocstart...")
    cmd = [
        sys.executable, "-m", "edlclient.edl",
        "rawxml", '<?xml version="1.0" ?><data><setprocstart /></data>'
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                          cwd="/Users/xmxx/pinganhuijia")

    output = result.stdout + result.stderr
    print(f"Output:\n{output}")

    # Parse device_timestamp
    if "device_timestamp" not in output:
        print("ERROR: setprocstart failed - no device_timestamp in response")
        print("Full output:", output)
        return False

    # Extract timestamp
    import re
    match = re.search(r'device_timestamp="(\d+)"', output)
    if not match:
        match = re.search(r'device_timestamp[=:][\s"]*(\d+)', output)
    if not match:
        print("ERROR: Could not parse device_timestamp")
        return False

    device_timestamp = int(match.group(1))
    print(f"Got device_timestamp: {device_timestamp}")

    # Step 2: Generate and send setswprojmodel
    print(f"\n[2/2] Generating token and sending setswprojmodel...")
    pk, token = generate_token(serial, device_timestamp)
    print(f"PK: {pk}")
    print(f"Token (first 40): {token[:40]}...")

    xml = f'<?xml version="1.0" ?><data><setswprojmodel token="{token}" pk="{pk}" /></data>'

    cmd = [
        sys.executable, "-m", "edlclient.edl",
        "rawxml", xml
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                          cwd="/Users/xmxx/pinganhuijia")

    output = result.stdout + result.stderr
    print(f"Output:\n{output}")

    if 'model_check="0"' in output and 'auth_token_verify="0"' in output:
        print("\n" + "=" * 60)
        print("SUCCESS! Model converted to Global (20886)")
        print("=" * 60)
        print("\nNext steps:")
        print("  1. Reboot to bootloader: edl reset")
        print("  2. Check: fastboot oem device-info")
        print("  3. Unlock: fastboot oem unlock")
        return True
    else:
        print("\nsetswprojmodel FAILED")
        if "model_check" in output:
            print("model_check present in response")
        if "auth_token_verify" in output:
            print("auth_token_verify present in response")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
