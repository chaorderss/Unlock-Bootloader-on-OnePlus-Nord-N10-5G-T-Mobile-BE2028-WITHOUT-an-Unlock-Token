#!/usr/bin/env python3
"""Modify param partition: set intranet=3 and boottype=0xA9E (sdebug) in SID 0x12C
Self-contained implementation without edlclient dependency."""
import hashlib
import struct
from binascii import hexlify

# AES-CBC implementation using PyCryptodome or fallback
try:
    from Crypto.Cipher import AES as _AES
    def aes_cbc(key, iv, data, decrypt=True):
        cipher = _AES.new(key, _AES.MODE_CBC, iv)
        return cipher.decrypt(data) if decrypt else cipher.encrypt(data)
except ImportError:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        def aes_cbc(key, iv, data, decrypt=True):
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            op = cipher.decryptor() if decrypt else cipher.encryptor()
            return op.update(data) + op.finalize()
    except ImportError:
        import subprocess, tempfile, os
        def aes_cbc(key, iv, data, decrypt=True):
            """Fallback using openssl command"""
            with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
                f.write(data)
                infile = f.name
            outfile = infile + '.out'
            op = '-d' if decrypt else '-e'
            cmd = ['openssl', 'enc', '-aes-128-cbc', op, '-nopad',
                   '-K', key.hex(), '-iv', iv.hex(),
                   '-in', infile, '-out', outfile]
            subprocess.run(cmd, check=True, capture_output=True)
            with open(outfile, 'rb') as f:
                result = f.read()
            os.unlink(infile)
            os.unlink(outfile)
            return result

def md5(data):
    return hashlib.md5(data).digest()

# Param encryption parameters
AES_IV = bytes.fromhex("562E17996D093D28DDB3BA695A2E6F58")

PARAM_PATH = "/Users/xmxx/pinganhuijia/edl_backup/lun0/param.bin"
OUTPUT_PATH = "/Users/xmxx/pinganhuijia/tmp/param_modified.bin"

with open(PARAM_PATH, "rb") as f:
    param_data = bytearray(f.read())

print(f"Param size: {len(param_data)} bytes")

# SID 0x12C at offset 0x4B000
SID = 0x12C
sid_offset = SID * 0x400
print(f"SID 0x12C at offset 0x{sid_offset:X}")

sid_data = param_data[sid_offset:sid_offset + 0x1000]
magic_val = struct.unpack_from('<I', sid_data, 0)[0]
print(f"Magic: 0x{magic_val:08X} {'OK' if magic_val == 0xA0AD646A else 'BAD!'}")

hv = sid_data[4]
cv = sid_data[5]
updatecounter = sid_data[0x10]
print(f"hv={hv}, cv={cv}, update_counter={updatecounter}")

enchash = sid_data[0x80:0x90]
encdata = bytes(sid_data[0x400:0x400 + 0xC00])
print(f"Encrypted hash: {enchash.hex()}")
print(f"Encrypted data size: {len(encdata)}")

# Verify encrypted hash
gen_enchash = md5(encdata)
if gen_enchash == enchash:
    print("Encrypted hash MATCHES")
else:
    print(f"Encrypted hash MISMATCH!")
    print(f"  Expected: {enchash.hex()}")
    print(f"  Got:      {gen_enchash.hex()}")

# Try different keys
# Device serial: db0c1e4b = 3674988107
serials = [
    (0xdb0c1e4b, "0xdb0c1e4b"),
    (123456, "123456"),
    (0, "0"),
]

working_key = None
working_serial = None

for serial, desc in serials:
    # Mode 1 key derivation
    hexserial = "%08x" % (serial & 0xFFFFFFFF)
    derivedkey_hex = "a9264fbf8a" + hexserial + "6b4487ea"
    derivedkey_bytes = bytes.fromhex(derivedkey_hex)
    aes_key = hashlib.sha256(derivedkey_bytes).digest()[:16]

    print(f"\nTrying serial={desc}, key={aes_key.hex()}")

    try:
        decdata = aes_cbc(aes_key, AES_IV, encdata, decrypt=True)
        dechash = decdata[:16]
        itemdata = decdata[-0xB80:]
        gendechash = md5(itemdata)

        if gendechash == dechash:
            print(f"  DECRYPTION SUCCESS! Hash matches!")
            working_key = aes_key
            working_serial = desc
            break
        else:
            print(f"  Hash mismatch after decrypt")
    except Exception as e:
        print(f"  Error: {e}")

# Also try default key (mode=0)
if working_key is None:
    default_key = bytes.fromhex("3030304F6E65506C7573383138303030")
    print(f"\nTrying default key (mode=0): {default_key.hex()}")
    try:
        decdata = aes_cbc(default_key, AES_IV, encdata, decrypt=True)
        dechash = decdata[:16]
        itemdata = decdata[-0xB80:]
        gendechash = md5(itemdata)

        if gendechash == dechash:
            print(f"  DECRYPTION SUCCESS with default key!")
            working_key = default_key
            working_serial = "default"
        else:
            print(f"  Hash mismatch")
    except Exception as e:
        print(f"  Error: {e}")

if working_key is None:
    print("\n!!! FAILED to decrypt with any key !!!")
    print("Need correct device serial number for key derivation.")

    # Try to find serial from param partition itself
    # Project name at SID 0 (PRODUCT section), offset 0x18
    proj_data = param_data[0x18:0x26]
    proj_name = proj_data.rstrip(b'\x00')
    print(f"Project name from param: {proj_name}")

    # Try reading serial from different areas
    for off in [0x14, 0x38, 0x3C]:
        val = struct.unpack_from('<I', param_data, off)[0]
        if val != 0:
            print(f"  param[0x{off:X}] = 0x{val:08X} ({val})")

    import sys
    sys.exit(1)

print(f"\n=== DECRYPTED SID 0x12C (serial={working_serial}) ===")

# Show current values
itemdata = bytearray(itemdata)
boottypes = {0: "normal", 0xA0: "auto", 0xB7: "debug", 0xA9E: "sdebug"}

fields = [
    (0x00, "intranet (0x80)"),
    (0x04, "boottype (0x84)"),
    (0x08, "ONLINE_CFG_TEST_ENV (0x88)"),
    (0x0C, "TargetSWID (0x8C)"),
    (0x10, "AgingFlag (0x90)"),
]
for off, name in fields:
    val = struct.unpack_from('<I', itemdata, off)[0]
    extra = ""
    if "boottype" in name:
        extra = f" = {boottypes.get(val, 'unknown')}"
    elif "intranet" in name:
        extra = f" ({'enabled' if val else 'disabled'})"
    print(f"  {name}: {val} (0x{val:X}){extra}")

# Show all non-zero
print(f"\n  All non-zero values:")
for i in range(0, len(itemdata), 4):
    val = struct.unpack_from('<I', itemdata, i)[0]
    if val != 0:
        print(f"    offset 0x{i+0x80:X}: 0x{val:08X} ({val})")

# === MODIFY ===
print(f"\n=== MODIFYING PARAM ===")
print(f"  Setting intranet (0x80) = 3 (enable ops)")
print(f"  Setting boottype (0x84) = 0xA9E (sdebug)")

struct.pack_into('<I', itemdata, 0x00, 3)       # intranet = 3
struct.pack_into('<I', itemdata, 0x04, 0xA9E)   # boottype = sdebug (0xA9E = 2718)

# Re-encrypt
# Build the full 0xC00 decrypted block: 0x80 header + 0xB80 itemdata
header = bytearray(0x80)
header[0:16] = md5(bytes(itemdata))
dec_full = bytes(header) + bytes(itemdata)

enc_new = aes_cbc(working_key, AES_IV, dec_full, decrypt=False)
enc_new_hash = md5(enc_new)

# Build new SID block
new_sid = bytearray(0x1000)
new_sid[:6] = struct.pack('<IBB', 0xA0AD646A, hv, cv)
new_sid[0x10] = updatecounter + 1  # bump counter
new_sid[0x80:0x90] = enc_new_hash
new_sid[0x400:0x400 + 0xC00] = enc_new

# Verify by decrypting
verify_dec = aes_cbc(working_key, AES_IV, bytes(enc_new), decrypt=True)
verify_hash = verify_dec[:16]
verify_items = verify_dec[-0xB80:]
if md5(verify_items) == verify_hash:
    v_intranet = struct.unpack_from('<I', verify_items, 0)[0]
    v_boottype = struct.unpack_from('<I', verify_items, 4)[0]
    print(f"\n  Verification: intranet={v_intranet}, boottype=0x{v_boottype:X}")
    if v_intranet == 3 and v_boottype == 0xA9E:
        print(f"  VERIFIED OK!")
    else:
        print(f"  VERIFICATION FAILED!")
        import sys; sys.exit(1)
else:
    print(f"  VERIFICATION HASH MISMATCH!")
    import sys; sys.exit(1)

# Write modified param
param_modified = bytearray(param_data)
param_modified[sid_offset:sid_offset + 0x1000] = new_sid

with open(OUTPUT_PATH, "wb") as f:
    f.write(param_modified)
print(f"\n  Written modified param to: {OUTPUT_PATH}")
print(f"  Size: {len(param_modified)} bytes")

# Also check if we need to update duplicate SID (some devices have backup at sid+0x200)
dup_offset = (SID + 0x200) * 0x400
if dup_offset + 0x1000 <= len(param_data):
    dup_magic = struct.unpack_from('<I', param_data, dup_offset)[0]
    if dup_magic == 0xA0AD646A:
        print(f"\n  Found duplicate SID at 0x{dup_offset:X}, updating too...")
        param_modified[dup_offset:dup_offset + 0x1000] = new_sid
        with open(OUTPUT_PATH, "wb") as f:
            f.write(param_modified)
        print(f"  Updated duplicate SID")
    else:
        print(f"\n  No duplicate SID at 0x{dup_offset:X} (magic=0x{dup_magic:08X})")
