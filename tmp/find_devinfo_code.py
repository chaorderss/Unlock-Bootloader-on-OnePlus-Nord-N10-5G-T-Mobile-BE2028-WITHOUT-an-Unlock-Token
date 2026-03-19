#!/usr/bin/env python3
"""Find all devinfo-related code in ABL PE32+ to check if there's signature verification"""
import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin','rb').read()

# Search for devinfo-related strings
print("=== devinfo-related strings ===")
for needle in [b'devinfo', b'ANDROID-BOOT', b'device_info', b'DeviceInfo', b'oem_unlock', b'is_unlocked', b'unlock_ability']:
    idx = 0
    while True:
        idx = data.find(needle, idx)
        if idx < 0:
            break
        end = idx
        while end < len(data) and end < idx + 120 and data[end] != 0:
            end += 1
        s = data[idx:end].decode('ascii', errors='replace')[:80]
        print(f"  {idx:#08x}: '{s}'")
        idx += 1

# Also check for ReadWriteDeviceInfo or similar function names
print()
print("=== Read/Write DeviceInfo strings ===")
for needle in [b'ReadDeviceInfo', b'WriteDeviceInfo', b'read_device_info', b'write_device_info',
               b'ReadWriteDeviceInfo', b'DevInfo', b'devinfo_read', b'devinfo_write',
               b'ANDROID-BOOT!']:
    idx = 0
    while True:
        idx = data.find(needle, idx)
        if idx < 0:
            break
        end = idx
        while end < len(data) and end < idx + 120 and data[end] != 0:
            end += 1
        s = data[idx:end].decode('ascii', errors='replace')[:80]
        print(f"  {idx:#08x}: '{s}'")
        idx += 1
