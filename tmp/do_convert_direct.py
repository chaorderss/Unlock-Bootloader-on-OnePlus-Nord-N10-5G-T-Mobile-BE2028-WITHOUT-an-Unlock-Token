#!/usr/bin/env python3
"""
Direct carrier conversion: OnePlus N10 5G TMO -> Global
Uses edl library directly in a single session to send setprocstart + setswprojmodel.
"""
import sys
import os
import time
import hashlib
import random
import string
import json
import logging
from struct import pack
from binascii import hexlify

# Fix import paths - edl's pycryptodome before homebrew's
os.environ.pop('PYTHONPATH', None)
sys.path = [p for p in sys.path if '/opt/homebrew/' not in p]
sys.path.insert(0, "/Library/Frameworks/Python.framework/Versions/3.14/lib/python3.14/site-packages")

from Cryptodome.Cipher import AES as CryptoAES
from edlclient.Library.Connection.usblib import usb_class
from edlclient.Library.sahara import sahara as sahara_class
from edlclient.Library.firehose import firehose
from edlclient.Library.xmlparser import xmlparser

# ===== Configuration =====
TARGET_CM = "b8bd9e39"        # Global (20886)
PRODKEY = "7016147d58e8c038"
RANDOM_POSTFIX = "c75oVnz8yUgLZObh"
VERSION = "billie8_14_E.01_201028"
HASH_SUFFIX = "8f7359c8a2951e8c"
AES_KEY_PREFIX = b"\x46\xA5\x97\x30\xBB\x0D\x41\xE8"
AES_IV = b"\xDC\x91\x0D\x88\xE3\xC6\xEE\x65\xF0\xC7\x44\xB4\x02\x30\xCE\x40"

FIREHOSE_PATH = "/Library/Frameworks/Python.framework/Versions/3.14/lib/python3.14/site-packages/Loaders/oneplus/0013f0e100515198_2354228eebcbc203_fhprg_op_n10.bin"


def sha256(data):
    return hashlib.sha256(data).digest()

def generate_token(serial, device_timestamp):
    pk = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    timestamp_str = str(int(time.time()))

    h1 = PRODKEY + TARGET_CM + RANDOM_POSTFIX
    model_hash = hexlify(sha256(h1.encode())).decode().upper()

    device_id = str(int(TARGET_CM, 16))
    h2 = PRODKEY + TARGET_CM + str(serial) + VERSION + timestamp_str + model_hash + HASH_SUFFIX
    secret = hexlify(sha256(h2.encode())).decode().upper()

    items = [TARGET_CM, RANDOM_POSTFIX, model_hash, "0", "0",
             VERSION, str(serial), device_id, timestamp_str, secret]
    data = ",".join(items)
    while len(data) < 0x200:
        data += "\x00"

    aes_key = AES_KEY_PREFIX + pk.encode() + pack("<Q", device_timestamp)
    cipher = CryptoAES.new(aes_key, CryptoAES.MODE_CBC, AES_IV)
    token = hexlify(cipher.encrypt(data.encode())).upper().decode()
    return pk, token


def main():
    print("=" * 60)
    print("OnePlus N10 5G: TMO → Global via setswprojmodel")
    print("=" * 60)

    # Read config
    config_path = os.path.join(os.path.dirname(__file__), "..", "edl_config.json")
    config_path = os.path.normpath(config_path)
    with open(config_path) as f:
        config = json.load(f)
    serial = config["serial"]
    print(f"Serial: {serial} (0x{serial:08x})")
    print(f"Target: Global (CM={TARGET_CM})")
    print()

    # Step 1: Connect USB
    print("[1/4] Connecting to USB device...")
    cdc = usb_class(loglevel=logging.INFO, portconfig=None, devclass=10)
    if not cdc.connect():
        print("ERROR: USB connection failed. Is device in EDL mode?")
        return False
    print("  USB connected")

    # Step 2: Sahara handshake
    print("[2/4] Sahara handshake...")
    sh = sahara_class(cdc, loglevel=logging.INFO)

    # Check if already in firehose mode
    v = cdc.read(timeout=1000)
    if v and len(v) > 0:
        mode = sh.init(v)
    else:
        mode = "firehose"

    if mode == "sahara":
        print("  Uploading firehose loader...")
        sh.programmer = FIREHOSE_PATH
        if not sh.upload_loader():
            print("ERROR: Loader upload failed")
            return False
        print("  Loader uploaded")
    elif mode == "firehose":
        print("  Already in firehose mode")
    else:
        print(f"  Mode: {mode}")
        # Try to proceed anyway

    # Step 3: Configure firehose
    print("[3/4] Configuring firehose...")

    cfg = type('cfg', (), {
        'MemoryName': 'UFS',
        'MaxPayloadSizeToTargetInBytes': 16384,
        'SECTOR_SIZE_IN_BYTES': 4096,
        'MaxPayloadSizeToTargetInBytesSupported': 16384,
        'TargetName': '',
        'bit64': True,
        'total_blocks': 0,
        'num_physical': 0,
        'block_size': 0,
        'UNSPARSE_FILE_SIZE': 1048576,
        'maxlun': 6,
        'programmer': FIREHOSE_PATH,
        'PAGES_PER_BLOCK': 0,
        'ZlpAwareHost': 1,
    })()

    xp = xmlparser()
    fh = firehose(cdc=cdc, xml=xp, cfg=cfg, loglevel=logging.INFO, devicemodel="20886",
                  serial=serial, skipresponse=False, luns=[0])

    # Configure the firehose connection
    if not fh.configure(0):
        print("  WARNING: Configure returned False, trying anyway...")

    # Step 4: setprocstart + setswprojmodel
    print("[4/4] Executing setswprojmodel...")

    # Send setprocstart
    print("  Sending setprocstart...")
    data = '<?xml version="1.0" ?><data>\n<setprocstart /></data>'
    val = fh.xmlsend(data)

    resp_text = ""
    if val.resp:
        if isinstance(val.data, bytes):
            resp_text = val.data.decode('utf-8', errors='replace')
        else:
            resp_text = str(val.data)
    if val.error:
        if isinstance(val.error, bytes):
            resp_text += val.error.decode('utf-8', errors='replace')
        else:
            resp_text += str(val.error)

    print(f"  Response: {resp_text[:200]}")

    # Parse device_timestamp from response
    import re
    match = re.search(r'device_timestamp="(\d+)"', resp_text)
    if not match:
        # Also check the raw log
        resp2 = fh.cmd_send("setprocstart")
        if isinstance(resp2, bytes):
            resp_text = resp2.decode('utf-8', errors='replace')
        elif isinstance(resp2, str):
            resp_text = resp2
        match = re.search(r'device_timestamp="(\d+)"', resp_text)

    if not match:
        print("ERROR: Could not get device_timestamp from setprocstart")
        print(f"  Raw response: {resp_text}")
        return False

    device_timestamp = int(match.group(1))
    print(f"  device_timestamp = {device_timestamp}")

    # Generate token
    pk, token = generate_token(serial, device_timestamp)
    print(f"  PK: {pk}")
    print(f"  Token: {token[:40]}... ({len(token)} chars)")

    # Send setswprojmodel
    print("  Sending setswprojmodel...")
    data2 = f'<?xml version="1.0" ?><data>\n<setswprojmodel token="{token}" pk="{pk}" /></data>'
    val2 = fh.xmlsend(data2)

    resp_text2 = ""
    if val2.resp:
        if isinstance(val2.data, bytes):
            resp_text2 = val2.data.decode('utf-8', errors='replace')
        else:
            resp_text2 = str(val2.data)
    if val2.error:
        if isinstance(val2.error, bytes):
            resp_text2 += val2.error.decode('utf-8', errors='replace')
        else:
            resp_text2 += str(val2.error)

    print(f"  Response: {resp_text2[:300]}")

    # Check result
    if 'model_check="0"' in resp_text2 and 'auth_token_verify="0"' in resp_text2:
        print("\n" + "=" * 60)
        print("✅ SUCCESS! Model changed to Global (20886)")
        print("=" * 60)

        # Reset device
        print("\nResetting device...")
        fh.cmd_reset()
        return True
    else:
        print("\n❌ setswprojmodel FAILED")
        if 'model_check' in resp_text2:
            mc = re.search(r'model_check="([^"]*)"', resp_text2)
            if mc:
                print(f"  model_check = {mc.group(1)}")
        if 'auth_token_verify' in resp_text2:
            av = re.search(r'auth_token_verify="([^"]*)"', resp_text2)
            if av:
                print(f"  auth_token_verify = {av.group(1)}")
        return False

if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
