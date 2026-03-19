#!/usr/bin/env python3
"""Check current param with CORRECT block structure from edl tool.

Block structure (0x1000 bytes per SID):
  data[0:4]   = magic 0xA0AD646A
  data[4]     = hv (hw_version)
  data[5]     = cv (crypto_version)
  data[0x10]  = updatecounter
  data[0x80:0x90] = outer MD5 (MD5 of encrypted data)
  data[0x400:0xC00+0x400] = encrypted data (0xC00 bytes)

Decrypted:
  dec[0:16]   = inner MD5 (MD5 of itemdata)
  dec[16:128] = zeros/padding (0x70 bytes)
  dec[128:]   = itemdata (0xB80 bytes)
"""
import hashlib, struct, subprocess
from Crypto.Cipher import AES

MAGIC = 0xA0AD646A
IV = bytes.fromhex('562E17996D093D28DDB3BA695A2E6F58')
STATIC_KEY = bytes.fromhex('3030304F6E65506C7573383138303030')

# SOC serial 0x75655d5b
serial = 0x75655d5b
derived_seed = bytes.fromhex("a9264fbf8a" + ("%08x" % serial) + "6b4487ea")[:0x1A]
DERIVED_KEY = hashlib.sha256(derived_seed).digest()[:16]

def try_decrypt(block, label):
    magic = struct.unpack_from('<I', block, 0)[0]
    hv = block[4]
    cv = block[5]
    uc = block[0x10]
    outer_md5_stored = block[0x80:0x90]
    enc = block[0x400:0x400+0xC00]
    outer_md5_computed = hashlib.md5(enc).digest()

    print(f"\n=== {label} ===")
    print(f"  Magic: 0x{magic:08X} ({'OK' if magic == MAGIC else 'BAD'})")
    print(f"  hv={hv} cv={cv} uc={uc}")
    print(f"  Outer MD5 stored:   {outer_md5_stored.hex()}")
    print(f"  Outer MD5 computed: {outer_md5_computed.hex()}")
    print(f"  Outer MD5 match: {outer_md5_stored == outer_md5_computed}")

    # Try both keys
    for key_name, key in [("derived", DERIVED_KEY), ("static", STATIC_KEY)]:
        cipher = AES.new(key, AES.MODE_CBC, IV)
        dec = cipher.decrypt(enc)
        inner_md5_stored = dec[:16]
        itemdata = dec[-0xB80:]
        inner_md5_computed = hashlib.md5(itemdata).digest()
        match = inner_md5_stored == inner_md5_computed

        if match:
            print(f"\n  *** KEY: {key_name} ({key.hex()}) -> Inner MD5 MATCH! ***")
            sf = struct.unpack('<I', itemdata[0:4])[0]
            swid = struct.unpack('<I', itemdata[4:8])[0]
            proc = struct.unpack('<I', itemdata[8:12])[0]
            print(f"  supported_flag = {sf}")
            print(f"  SWID = 0x{swid:08X}")
            print(f"  proc = 0x{proc:08X}")
            # Also show as ReadParam offsets
            print(f"  (ReadParam 0x80 = {sf}, 0x84 = 0x{swid:08X}, 0x88 = 0x{proc:08X})")
            return itemdata, key_name
        else:
            if key_name == "derived":
                print(f"  Key '{key_name}': Inner MD5 mismatch")

    print(f"  Neither key decrypts correctly!")
    print(f"  Enc first 32: {enc[:32].hex()}")
    return None, None

# Read current param
result = subprocess.run(['adb', 'shell', 'dd if=/dev/block/sda6 2>/dev/null'],
                       capture_output=True)
data = result.stdout
print(f"Param size: {len(data)}")

# Also read original
with open('edl_backup/pre_convert/param.bin', 'rb') as f:
    orig = f.read()

print("\n" + "="*60)
print("CURRENT DEVICE")
print("="*60)
for sid_val, name in [(0x13C, 'SPI primary'), (0x33C, 'SPI backup')]:
    blk = data[sid_val*0x400 : sid_val*0x400 + 0x1000]
    try_decrypt(blk, f"SID 0x{sid_val:X} ({name})")

print("\n" + "="*60)
print("ORIGINAL BACKUP")
print("="*60)
for sid_val, name in [(0x13C, 'SPI primary'), (0x33C, 'SPI backup')]:
    blk = orig[sid_val*0x400 : sid_val*0x400 + 0x1000]
    try_decrypt(blk, f"SID 0x{sid_val:X} ({name})")

# Also check SID 0x12C for comparison
print("\n" + "="*60)
print("SID 0x12C (secrecy) current vs original")
print("="*60)
for label, src in [("current", data), ("original", orig)]:
    blk = src[0x12C * 0x400 : 0x12C * 0x400 + 0x1000]
    try_decrypt(blk, f"SID 0x12C {label}")
