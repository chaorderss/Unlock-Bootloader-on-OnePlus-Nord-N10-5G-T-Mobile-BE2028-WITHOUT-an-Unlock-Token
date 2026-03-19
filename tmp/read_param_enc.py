#!/usr/bin/env python3
"""Read current param SID 0x12C to verify TargetSWID and intranet values."""
import hashlib
import subprocess
from binascii import hexlify
from struct import unpack, pack
from Crypto.Cipher import AES

# Static key (param_mode=0)
AES_KEY = bytes.fromhex('3030304F6E65506C7573383138303030')
AES_IV = bytes.fromhex('562E17996D093D28DDB3BA695A2E6F58')

# Pull param directly from device
result = subprocess.run(['adb', 'shell', 'dd if=/dev/block/sda6 bs=4096 count=256 2>/dev/null'],
                       capture_output=True, timeout=30)
data = result.stdout
print(f"Read {len(data)} bytes from param partition")

# SID 0x12C
sid = 0x12C
offset = sid * 0x400
block = data[offset:offset + 0x1000]

# Parse header
magic = unpack('<I', block[:4])[0]
print(f"\nSID 0x12C at offset 0x{offset:X}")
print(f"Magic: 0x{magic:08X} (expected 0xA0AD646A)")

if magic != 0xA0AD646A:
    print("ERROR: Wrong magic!")
    exit(1)

hv = block[4]
cv = block[5]
updatecounter = unpack('<I', block[8:0xC])[0]
print(f"hv={hv}, cv={cv}, updatecounter={updatecounter}")

# Verify ciphertext hash
enchash = block[0x80:0x90]
encdata = block[0x400:0x400 + 0xC00]
computed_enchash = hashlib.md5(encdata).digest()
print(f"Ciphertext MD5 match: {enchash == computed_enchash}")

# Decrypt
cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
decdata = cipher.decrypt(encdata)

# Verify plaintext hash
dechash = decdata[:16]
itemdata = decdata[-0xB80:]
computed_dechash = hashlib.md5(itemdata).digest()
print(f"Plaintext MD5 match: {dechash == computed_dechash}")

if dechash != computed_dechash:
    print("ERROR: Decryption failed!")
    exit(1)

# Read fields (offsets are relative to itemdata, which starts at 0x80 in the logical layout)
# In the oneplus_param code, SID_ENC_SECRECY fields:
#   0x80 -> itemdata[0x80-0x80] = itemdata[0x00] = intranet
#   0x84 -> itemdata[0x04] = boottype
#   0x88 -> itemdata[0x08] = ONLINE_CFG_TEST_ENV
#   0x8C -> itemdata[0x0C] = TargetSWID
#   0x90 -> itemdata[0x10] = AgingFlag

intranet = unpack('<I', itemdata[0x00:0x04])[0]
boottype = unpack('<I', itemdata[0x04:0x08])[0]
online_cfg = unpack('<I', itemdata[0x08:0x0C])[0]
target_swid = unpack('<I', itemdata[0x0C:0x10])[0]
aging_flag = unpack('<I', itemdata[0x10:0x14])[0]

print(f"\n== SID 0x12C (Encrypted Secrecy) Fields ==")
print(f"  intranet (ops):  0x{intranet:08X} ({intranet})")
print(f"  boottype:        0x{boottype:08X}")
print(f"  ONLINE_CFG:      0x{online_cfg:08X}")
print(f"  TargetSWID:      0x{target_swid:08X} ({target_swid})")
print(f"  AgingFlag:       0x{aging_flag:08X}")
print(f"\n  First 32 bytes of itemdata: {hexlify(itemdata[:32]).decode()}")

# Also check SID 0x130 (Encrypted Carrier) if it exists
sid2 = 0x130
offset2 = sid2 * 0x400
if offset2 + 0x1000 <= len(data):
    block2 = data[offset2:offset2 + 0x1000]
    magic2 = unpack('<I', block2[:4])[0]
    print(f"\n== SID 0x130 (Encrypted Carrier) ==")
    print(f"Magic: 0x{magic2:08X} (expected 0xA0AD646A)")
    if magic2 == 0xA0AD646A:
        enchash2 = block2[0x80:0x90]
        encdata2 = block2[0x400:0x400 + 0xC00]
        computed_enchash2 = hashlib.md5(encdata2).digest()
        if enchash2 == computed_enchash2:
            cipher2 = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
            decdata2 = cipher2.decrypt(encdata2)
            itemdata2 = decdata2[-0xB80:]
            dechash2 = decdata2[:16]
            if hashlib.md5(itemdata2).digest() == dechash2:
                # Fields at offsets relative to logical 0x80
                carrier_fields = {
                    0x20: "CustFlag",       # 0xA0 - 0x80
                    0x24: "CustFlagMigration",
                    0x28: "carrier_id",     # 0xA8 - 0x80
                    0x2C: "carrier_init_flag"
                }
                for off, name in carrier_fields.items():
                    val = unpack('<I', itemdata2[off:off+4])[0]
                    print(f"  {name}: 0x{val:08X} ({val})")
            else:
                print("  Plaintext hash mismatch")
        else:
            print("  Ciphertext hash mismatch")
