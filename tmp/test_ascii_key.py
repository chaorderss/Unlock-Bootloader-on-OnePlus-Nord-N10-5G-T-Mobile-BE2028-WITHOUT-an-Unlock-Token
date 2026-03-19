#!/usr/bin/env python3
"""Test ASCII vs hex-decoded key derivation for SID 0x13C."""
import hashlib
import subprocess
from binascii import hexlify
from struct import unpack
from Crypto.Cipher import AES

IV = bytes.fromhex('562E17996D093D28DDB3BA695A2E6F58')
SERIAL_SOC = 1969577307  # 0x75655d5b

# Read param
result = subprocess.run(['adb', 'shell', 'dd if=/dev/block/sda6 2>/dev/null'],
                       capture_output=True, timeout=30)
data = result.stdout

sid_val = 0x13C
offset = sid_val * 0x400
block = data[offset:offset + 0x1000]
encdata = block[0x400:0x400 + 0xC00]

def try_decrypt(key, name):
    cipher = AES.new(key, AES.MODE_CBC, IV)
    dec = cipher.decrypt(encdata)
    dechash = dec[:16]
    itemdata = dec[-0xB80:]
    comp = hashlib.md5(itemdata).digest()
    if dechash == comp:
        print(f"*** MATCH: {name} ***")
        print(f"  Key: {hexlify(key).decode()}")
        val_84 = unpack('<I', itemdata[4:8])[0]
        val_88 = unpack('<I', itemdata[8:12])[0]
        print(f"  SoftwareProjectID (0x84): {val_84}")
        print(f"  sw_proj_id_proc  (0x88): {val_88}")
        print(f"  First 32B: {hexlify(itemdata[:32]).decode()}")
        return True
    return False

# Key approach: ABL uses AsciiSPrint("%a%08x%a", prefix, serial, suffix)
# This produces ASCII string, then SHA-256 of the ASCII bytes (not hex-decoded)

for serial_name, serial in [("SOC 0x75655d5b", SERIAL_SOC), ("Android db0c1e4b", int("db0c1e4b", 16))]:
    # Method A: edl tool's way (hex decode then hash)
    hex_str = "a9264fbf8a" + ("%08x" % serial) + "6b4487ea"
    raw_bytes = bytes.fromhex(hex_str)
    key_a = hashlib.sha256(raw_bytes).digest()[:16]
    result_a = try_decrypt(key_a, f"{serial_name} - hex decoded ({len(raw_bytes)}B)")

    # Method B: ABL's way (hash the ASCII string directly)
    ascii_str = hex_str.encode('ascii')  # 26 ASCII bytes
    key_b = hashlib.sha256(ascii_str).digest()[:16]
    result_b = try_decrypt(key_b, f"{serial_name} - ASCII string ({len(ascii_str)}B)")

    # Method C: ASCII string with uppercase hex
    ascii_upper = ("a9264fbf8a" + ("%08X" % serial) + "6b4487ea").encode('ascii')
    key_c = hashlib.sha256(ascii_upper).digest()[:16]
    try_decrypt(key_c, f"{serial_name} - ASCII upper ({ascii_upper.decode()})")

    # Method D: With null terminator
    ascii_null = hex_str.encode('ascii') + b'\x00'
    key_d = hashlib.sha256(ascii_null).digest()[:16]
    try_decrypt(key_d, f"{serial_name} - ASCII+null ({len(ascii_null)}B)")

# Also try static key as ASCII
static_ascii = b'000OnePlus818000'
key_e = hashlib.sha256(static_ascii).digest()[:16]
try_decrypt(key_e, f"SHA256(static_ascii)")

# Try MD5 of ASCII derivation
for serial_name, serial in [("SOC", SERIAL_SOC), ("Android", int("db0c1e4b", 16))]:
    hex_str = "a9264fbf8a" + ("%08x" % serial) + "6b4487ea"
    ascii_str = hex_str.encode('ascii')
    key_f = hashlib.md5(ascii_str).digest()
    try_decrypt(key_f, f"{serial_name} - MD5(ASCII)")

print("\nDone.")
