#!/usr/bin/env python3
"""
Prepare the modified FRP partition for OEM unlock.

Based on ABL analysis:
- IsAllowUnlock = FRP_partition[last_byte] & 1
- ABL code at 0x48600: ldrb w8, [x23, w8, uxtw] ; and w8, w8, #1
- Currently FRP is all zeros → IsAllowUnlock = 0
- Need to set last byte to 0x01
"""

import shutil
import os

frp_orig = '/Users/xmxx/pinganhuijia/edl_backup/lun0/frp.bin'
frp_mod = '/Users/xmxx/pinganhuijia/tmp/frp_unlocked.bin'

# Read original FRP
with open(frp_orig, 'rb') as f:
    data = bytearray(f.read())

print(f"FRP partition size: {len(data)} bytes")
print(f"Original last byte: 0x{data[-1]:02X}")
print(f"Original IsAllowUnlock: {data[-1] & 1}")

# Verify it's all zeros
nz_count = sum(1 for b in data if b != 0)
print(f"Non-zero bytes: {nz_count}")

# Set the last byte to 0x01 (enable OEM unlock)
data[-1] = 0x01

print(f"\nModified last byte: 0x{data[-1]:02X}")
print(f"Modified IsAllowUnlock: {data[-1] & 1}")

# Write modified FRP
with open(frp_mod, 'wb') as f:
    f.write(data)

print(f"\nSaved to: {frp_mod}")
print(f"Verified size: {os.path.getsize(frp_mod)} bytes")

# Verify the modification
with open(frp_mod, 'rb') as f:
    verify = f.read()
print(f"Verify last byte: 0x{verify[-1]:02X}")
print(f"Verify IsAllowUnlock: {verify[-1] & 1}")

# Also show what the ABL code will do:
print(f"""
=== ABL Flow After FRP Modification ===
1. ABL reads FRP partition (524288 bytes) from lun0
2. At 0x48600: ldrb w8, [buffer, 524287]  → w8 = 0x01
3. At 0x48604: and w8, w8, #1  → w8 = 1
4. At 0x48608: str w8, [0x1C0010]  → IsAllowUnlock = 1
5. fastboot oem device-info shows: IsAllowUnlock = true
6. fastboot oem unlock → SetDeviceUnlocked called
7. SetDeviceUnlocked writes is_unlocked=1 to RPMB (first write)
8. Calls 0x189E8 → VB protocol method_0x30 (VBResetDeviceState)
9. If method_0x30 returns 0: factory reset path → device unlocked!
10. If method_0x30 returns non-0: inverse write → still locked

NOTE: The VB protocol driver (in XBL/DXE) may have its own
check for OEM unlock. The FRP modification is necessary but
may not be sufficient if the driver also checks param partition
or other conditions.
""")

print("""
=== EDL Flash Commands ===
# Step 1: Flash modified FRP partition
edl w lun0 frp tmp/frp_unlocked.bin

# Step 2 (optional): Enable OEM unlock via param partition
edl modules ops,enable --devicemodel=20888

# Step 3: Reboot to fastboot
edl reset

# Step 4: Check device info
fastboot oem device-info

# Step 5: Attempt unlock
fastboot oem unlock
""")
