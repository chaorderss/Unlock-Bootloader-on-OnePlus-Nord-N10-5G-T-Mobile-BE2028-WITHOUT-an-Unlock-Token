#!/usr/bin/env python3
"""Modify param partition: set intranet=3 and boottype=0xA9E (sdebug) in SID 0x12C"""
import sys
import hashlib
import struct
sys.path.insert(0, "/Library/Frameworks/Python.framework/Versions/3.14/lib/python3.14/site-packages")
from edlclient.Library.Modules.oneplus_param import paramtools

PARAM_PATH = "/Users/xmxx/pinganhuijia/edl_backup/lun0/param.bin"
OUTPUT_PATH = "/Users/xmxx/pinganhuijia/tmp/param_modified.bin"

with open(PARAM_PATH, "rb") as f:
    param_data = bytearray(f.read())

print(f"Param size: {len(param_data)} bytes")
print(f"Magic: {param_data[:8]}")

# SID 0x12C at offset 0x4B000
sid = 0x12C
sid_offset = sid * 0x400
print(f"\nSID 0x12C at offset 0x{sid_offset:X}")
magic_val = struct.unpack_from('<I', param_data, sid_offset)[0]
print(f"SID magic: 0x{magic_val:08X} {'(valid)' if magic_val == 0xA0AD646A else '(INVALID!)'}")

# Try with different serials
# Device serial from EDL: db0c1e4b = 0xdb0c1e4b = 3674988107
serials_to_try = [
    (0xdb0c1e4b, "db0c1e4b (device serial)"),
    (123456, "123456 (default)"),
    (0, "0"),
]

for serial_val, serial_desc in serials_to_try:
    print(f"\n--- Trying serial={serial_desc} (mode=1) ---")
    pt = paramtools(mode=1, serial=serial_val)
    print(f"  AES key: {pt.aes_key.hex()}")

    sid_data = param_data[sid_offset:sid_offset + 0x1000]
    itemdata, hv, cv, updatecounter = pt.decryptsid(sid_data)

    if itemdata is not None:
        print(f"  SUCCESS! hv={hv}, cv={cv}, counter={updatecounter}")
        print(f"  Item data length: {len(itemdata)}")

        # Current values
        intranet = struct.unpack_from('<I', itemdata, 0x80 - 0x80)[0]
        boottype = struct.unpack_from('<I', itemdata, 0x84 - 0x80)[0]
        online_cfg = struct.unpack_from('<I', itemdata, 0x88 - 0x80)[0]
        target_swid = struct.unpack_from('<I', itemdata, 0x8C - 0x80)[0]
        aging_flag = struct.unpack_from('<I', itemdata, 0x90 - 0x80)[0]

        print(f"\n  Current values:")
        print(f"    intranet  (0x80): {intranet} (0x{intranet:X})")
        print(f"    boottype  (0x84): {boottype} (0x{boottype:X})")
        boottypes = {0: "normal", 0xA0: "auto", 0xB7: "debug", 0xA9E: "sdebug"}
        print(f"    boottype meaning: {boottypes.get(boottype, 'unknown')}")
        print(f"    ONLINE_CFG(0x88): {online_cfg} (0x{online_cfg:X})")
        print(f"    TargetSWID(0x8C): {target_swid} (0x{target_swid:X})")
        print(f"    AgingFlag (0x90): {aging_flag} (0x{aging_flag:X})")

        # Print non-zero values
        print(f"\n  Non-zero fields in decrypted data:")
        for i in range(0, len(itemdata), 4):
            val = struct.unpack_from('<I', itemdata, i)[0]
            if val != 0:
                print(f"    offset 0x{i+0x80:X}: 0x{val:08X} ({val})")

        # Modify values
        print(f"\n  === MODIFYING ===")
        print(f"  Setting intranet = 3 (enable ops)")
        print(f"  Setting boottype = 0xA9E (sdebug)")

        itemdata = bytearray(itemdata)
        struct.pack_into('<I', itemdata, 0x80 - 0x80, 3)       # intranet = 3
        struct.pack_into('<I', itemdata, 0x84 - 0x80, 0xA9E)   # boottype = sdebug

        # Re-encrypt
        mdata = pt.encryptsid(itemdata, hv, cv, updatecounter)

        # Write back
        param_modified = bytearray(param_data)
        param_modified[sid_offset:sid_offset + 0x1000] = mdata

        # Verify by decrypting again with bumped counter
        verify_itemdata, _, _, _ = pt.decryptsid(mdata)
        if verify_itemdata is not None:
            new_intranet = struct.unpack_from('<I', verify_itemdata, 0)[0]
            new_boottype = struct.unpack_from('<I', verify_itemdata, 4)[0]
            print(f"\n  Verification after re-encrypt:")
            print(f"    intranet = {new_intranet} (expected 3)")
            print(f"    boottype = 0x{new_boottype:X} (expected 0xA9E)")

            if new_intranet == 3 and new_boottype == 0xA9E:
                print(f"\n  ✓ Verification PASSED!")
                with open(OUTPUT_PATH, "wb") as f:
                    f.write(param_modified)
                print(f"  Written to: {OUTPUT_PATH}")
                print(f"  Size: {len(param_modified)} bytes")
            else:
                print(f"\n  ✗ Verification FAILED!")
        else:
            print(f"\n  ERROR: Could not verify re-encrypted data!")

        break  # Found working serial
    else:
        print(f"  Failed to decrypt")

# Also try mode=0 (default key)
print(f"\n--- Also trying mode=0 (default key) ---")
pt0 = paramtools(mode=0, serial=0)
print(f"  AES key: {pt0.aes_key.hex()}")
sid_data = param_data[sid_offset:sid_offset + 0x1000]
itemdata0, _, _, _ = pt0.decryptsid(sid_data)
if itemdata0 is not None:
    print(f"  mode=0 also works!")
else:
    print(f"  mode=0 failed (expected for param_mode=1 device)")
