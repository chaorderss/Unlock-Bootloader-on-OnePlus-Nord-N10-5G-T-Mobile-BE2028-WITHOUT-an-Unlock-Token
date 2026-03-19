#!/usr/bin/env python3
"""Check current param state after boot."""
import hashlib, struct, subprocess
from Crypto.Cipher import AES

IV = bytes.fromhex('562E17996D093D28DDB3BA695A2E6F58')
key = hashlib.sha256(b'a9264fbf8a75655d5b6b4487ea').digest()[:16]

# Read current param from device
result = subprocess.run(['adb', 'shell', 'dd if=/dev/block/sda6 2>/dev/null'],
                       capture_output=True)
data = result.stdout
print(f"Param size: {len(data)}")

for sid_name, sid_val in [('0x13C primary', 0x13C), ('0x33C backup', 0x33C)]:
    offset = sid_val * 0x400
    block = data[offset:offset+0x1000]
    hv, cv = block[0], block[1]
    uc = struct.unpack_from('<H', block, 2)[0]
    outer_md5 = block[4:20]
    enc = block[0x400:0x400+0xC00]

    # Check outer MD5
    computed_outer = hashlib.md5(enc).digest()
    outer_ok = outer_md5 == computed_outer

    cipher = AES.new(key, AES.MODE_CBC, IV)
    dec = cipher.decrypt(enc)
    itemdata = dec[-0xB80:]
    inner_ok = hashlib.md5(itemdata).digest() == dec[:16]

    print(f"\nSID {sid_name}: hv={hv} cv={cv} uc={uc}")
    print(f"  Outer MD5: {'OK' if outer_ok else 'MISMATCH'}")
    print(f"  Inner MD5: {'OK' if inner_ok else 'MISMATCH'}")

    if inner_ok:
        sf = struct.unpack('<I', itemdata[0:4])[0]
        swid = struct.unpack('<I', itemdata[4:8])[0]
        proc = struct.unpack('<I', itemdata[8:12])[0]
        print(f"  supported_flag = {sf}")
        print(f"  SWID = 0x{swid:08X}")
        print(f"  proc = 0x{proc:08X}")
    else:
        print(f"  Inner MD5 stored:   {dec[:16].hex()}")
        print(f"  Inner MD5 computed: {hashlib.md5(itemdata).digest().hex()}")
        # Show first bytes of dec anyway
        print(f"  dec[0x80:0x90] = {dec[0x80:0x90].hex()}")
