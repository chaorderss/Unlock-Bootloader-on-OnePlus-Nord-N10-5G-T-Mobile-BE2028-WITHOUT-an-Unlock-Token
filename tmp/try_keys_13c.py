#!/usr/bin/env python3
"""Try all possible keys for SID 0x13C decryption."""
import hashlib
from binascii import hexlify
from struct import unpack
from Crypto.Cipher import AES

IV = bytes.fromhex('562E17996D093D28DDB3BA695A2E6F58')
SERIAL = 1969577307  # 0x75655d5b

# Read param
import subprocess
result = subprocess.run(['adb', 'shell', 'dd if=/dev/block/sda6 2>/dev/null'],
                       capture_output=True, timeout=30)
data = result.stdout

sid = 0x13C
offset = sid * 0x400
block = data[offset:offset + 0x1000]
magic = unpack('<I', block[:4])[0]
print(f"SID 0x{sid:X} magic: 0x{magic:08X}")

enchash = block[0x80:0x90]
encdata = block[0x400:0x400 + 0xC00]
print(f"Ciphertext MD5 stored:   {hexlify(enchash).decode()}")
print(f"Ciphertext MD5 computed: {hexlify(hashlib.md5(encdata).digest()).decode()}")
print(f"Ciphertext check: {enchash == hashlib.md5(encdata).digest()}")

# Try multiple keys
keys = {
    "static (000OnePlus818000)": bytes.fromhex('3030304F6E65506C7573383138303030'),
    "serial-derived (0x75655d5b)": hashlib.sha256(
        bytes.fromhex('a9264fbf8a' + ('%08x' % SERIAL) + '6b4487ea')
    ).digest()[:16],
    "zeros": bytes(16),
}

# Also try variations of serial format
for serial_val in [SERIAL, int("db0c1e4b", 16)]:
    for prefix, suffix in [
        ("a9264fbf8a", "6b4487ea"),
        ("a9264fbf", "8a6b4487ea"),
        ("", ""),
    ]:
        hex_str = f"{prefix}{serial_val:08x}{suffix}"
        try:
            raw = bytes.fromhex(hex_str)
            key = hashlib.sha256(raw).digest()[:16]
            name = f"sha256({hex_str})"
            keys[name] = key
        except:
            pass

# Try raw serial as key
keys["raw serial LE padded"] = SERIAL.to_bytes(4, 'little').ljust(16, b'\x00')
keys["raw serial BE padded"] = SERIAL.to_bytes(4, 'big').ljust(16, b'\x00')

for name, key in keys.items():
    cipher = AES.new(key, AES.MODE_CBC, IV)
    dec = cipher.decrypt(encdata)
    dechash = dec[:16]
    itemdata = dec[-0xB80:]
    comp = hashlib.md5(itemdata).digest()
    match = (dechash == comp)
    if match:
        print(f"\n*** MATCH: {name} ***")
        print(f"  Key: {hexlify(key).decode()}")
        print(f"  First 32 bytes of plaintext: {hexlify(itemdata[:32]).decode()}")
        # Read fields
        val_84 = unpack('<I', itemdata[4:8])[0]
        val_88 = unpack('<I', itemdata[8:12])[0]
        print(f"  offset 0x84 (SWID): {val_84}")
        print(f"  offset 0x88 (proc): {val_88}")
    else:
        if "static" in name or "serial" in name:
            print(f"  {name}: no match (stored={hexlify(dechash).decode()[:16]}... computed={hexlify(comp).decode()[:16]}...)")
