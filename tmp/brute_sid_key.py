#!/usr/bin/env python3
"""Exhaustive key search for SID 0x13C (cv=2)."""
import hashlib
import subprocess
from binascii import hexlify
from struct import unpack, pack
from Crypto.Cipher import AES

IV = bytes.fromhex('562E17996D093D28DDB3BA695A2E6F58')
STATIC_KEY = bytes.fromhex('3030304F6E65506C7573383138303030')
SERIAL_SOC = 1969577307  # 0x75655d5b
SERIAL_ANDROID = int("db0c1e4b", 16)  # 3674776139

result = subprocess.run(['adb', 'shell', 'dd if=/dev/block/sda6 2>/dev/null'],
                       capture_output=True, timeout=30)
data = result.stdout

sid_val = 0x13C
offset = sid_val * 0x400
block = data[offset:offset + 0x1000]
encdata = block[0x400:0x400 + 0xC00]

def try_key(key, iv, name):
    """Try decrypting with given key/iv, return True if match."""
    try:
        if len(key) == 16:
            cipher = AES.new(key, AES.MODE_CBC, iv)
        elif len(key) == 32:
            cipher = AES.new(key, AES.MODE_CBC, iv)
        else:
            return False
        dec = cipher.decrypt(encdata)
        dechash = dec[:16]
        itemdata = dec[-0xB80:]
        comp = hashlib.md5(itemdata).digest()
        if dechash == comp:
            print(f"\n*** MATCH: {name} ***")
            print(f"  Key ({len(key)}B): {hexlify(key).decode()}")
            print(f"  IV: {hexlify(iv).decode()}")
            val_84 = unpack('<I', itemdata[4:8])[0]
            val_88 = unpack('<I', itemdata[8:12])[0]
            print(f"  SWID (offset 0x84): {val_84}")
            print(f"  proc (offset 0x88): {val_88}")
            print(f"  First 64B: {hexlify(itemdata[:64]).decode()}")
            return True
    except Exception as e:
        pass
    return False

found = False
keys_tried = 0

# === Standard keys with standard IV ===
candidates = {}

# 1. Static key variations
candidates["static"] = STATIC_KEY
candidates["static_reversed"] = STATIC_KEY[::-1]

# 2. Serial-derived keys (both serials)
for sname, serial in [("soc", SERIAL_SOC), ("android", SERIAL_ANDROID)]:
    raw = bytes.fromhex("a9264fbf8a" + ("%08x" % serial) + "6b4487ea")
    candidates[f"serial_{sname}_sha256_16"] = hashlib.sha256(raw).digest()[:16]
    candidates[f"serial_{sname}_sha256_32"] = hashlib.sha256(raw).digest()
    candidates[f"serial_{sname}_md5"] = hashlib.md5(raw).digest()

# 3. Key derived from SID index
for prefix in [b"", STATIC_KEY, b"000OnePlus818000"]:
    for sid_bytes in [pack('<I', 0x13C), pack('>I', 0x13C), b"\x3c\x01", bytes([0x13C & 0xFF])]:
        raw = prefix + sid_bytes
        candidates[f"sha256({hexlify(raw).decode()})_16"] = hashlib.sha256(raw).digest()[:16]
        candidates[f"md5({hexlify(raw).decode()})"] = hashlib.md5(raw).digest()

# 4. Static key + serial combinations
for sname, serial in [("soc", SERIAL_SOC), ("android", SERIAL_ANDROID)]:
    sbytes = pack('<I', serial)
    candidates[f"sha256(static+{sname})_16"] = hashlib.sha256(STATIC_KEY + sbytes).digest()[:16]
    candidates[f"sha256({sname}+static)_16"] = hashlib.sha256(sbytes + STATIC_KEY).digest()[:16]

# 5. Key XOR with cv=2
cv_mask = bytes([2] + [0]*15)
candidates["static_xor_cv2"] = bytes(a ^ b for a, b in zip(STATIC_KEY, cv_mask))

# 6. Different static strings
for s in [b"000OnePlus818000", b"OnePlus818000000", b"000OnePlus000000",
          b"OnePlusOnePlus00", b"billie8t00000000", b"0000billie8t0000",
          b"000OnePlus818002", b"000OnePlus818001"]:
    if len(s) == 16:
        candidates[f"static_str({s.decode('utf-8', errors='replace')})"] = s

# 7. SHA256 of various strings
for s in [b"OnePlus", b"oneplus", b"billie8t", b"N10", b"param", b"20888",
          b"000OnePlus818000", b"000OnePlus818002"]:
    candidates[f"sha256({s.decode()})_16"] = hashlib.sha256(s).digest()[:16]

# 8. Key from prodkey
prodkey = b"7016147d58e8c038"
candidates["prodkey_raw"] = prodkey[:16]
candidates["sha256(prodkey)_16"] = hashlib.sha256(prodkey).digest()[:16]
candidates["md5(prodkey)"] = hashlib.md5(prodkey).digest()

# 9. All zeros / all ones
candidates["zeros_16"] = bytes(16)
candidates["ones_16"] = bytes([0xFF]*16)

# 10. Try the AES IV as key
candidates["iv_as_key"] = IV

# 11. Derived from cv value
for cv in [1, 2]:
    raw = STATIC_KEY + pack('<I', cv)
    candidates[f"sha256(static+cv{cv})_16"] = hashlib.sha256(raw).digest()[:16]
    raw = pack('<I', cv) + STATIC_KEY
    candidates[f"sha256(cv{cv}+static)_16"] = hashlib.sha256(raw).digest()[:16]

# 12. Try serial as 10-char decimal string
for sname, serial in [("soc", SERIAL_SOC), ("android", SERIAL_ANDROID)]:
    s = str(serial).encode()
    candidates[f"sha256(str_{sname})_16"] = hashlib.sha256(s).digest()[:16]
    if len(s) <= 16:
        candidates[f"str_{sname}_padded"] = s.ljust(16, b'\x00')

# Try all with standard IV
print(f"Testing {len(candidates)} key candidates with standard IV...")
for name, key in candidates.items():
    keys_tried += 1
    if try_key(key, IV, name):
        found = True
        break

if not found:
    # Try some keys with different IVs
    alt_ivs = {
        "zeros_iv": bytes(16),
        "ones_iv": bytes([0xFF]*16),
        "key_as_iv": STATIC_KEY,
        "sid_derived_iv": hashlib.md5(pack('<I', 0x13C)).digest(),
    }

    important_keys = [
        ("static", STATIC_KEY),
        ("serial_soc", hashlib.sha256(bytes.fromhex("a9264fbf8a75655d5b6b4487ea")).digest()[:16]),
    ]

    print(f"\nTesting important keys with {len(alt_ivs)} alternate IVs...")
    for iv_name, alt_iv in alt_ivs.items():
        for key_name, key in important_keys:
            keys_tried += 1
            if try_key(key, alt_iv, f"{key_name} + {iv_name}"):
                found = True
                break
        if found:
            break

if not found:
    # Try AES-256 with full SHA-256 keys
    print(f"\nTesting AES-256 keys...")
    for sname, serial in [("soc", SERIAL_SOC), ("android", SERIAL_ANDROID)]:
        raw = bytes.fromhex("a9264fbf8a" + ("%08x" % serial) + "6b4487ea")
        key32 = hashlib.sha256(raw).digest()
        keys_tried += 1
        if try_key(key32, IV, f"AES256_serial_{sname}"):
            found = True
            break

    if not found:
        key32 = hashlib.sha256(STATIC_KEY).digest()
        keys_tried += 1
        if try_key(key32, IV, "AES256_sha256(static)"):
            found = True

print(f"\nTotal keys tried: {keys_tried}")
if not found:
    print("No match found. The key may be device-specific or use a completely different derivation.")
