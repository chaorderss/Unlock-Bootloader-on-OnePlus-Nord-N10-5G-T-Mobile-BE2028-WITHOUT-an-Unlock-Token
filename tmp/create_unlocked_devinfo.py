#!/usr/bin/env python3
"""
Create a modified devinfo.bin with is_unlocked = 1.

DevInfo structure (from ABL reverse engineering):
  [0x00-0x0C] "ANDROID-BOOT!" magic (13 bytes)
  [0x0D]      is_unlocked (byte: 0=locked, 1=unlocked)
  [0x0E]      is_unlock_critical (byte)
  [0x0F]      charger_screen_enabled (byte)
  [0x90]      (offset 144, unknown flag)
  [0x94]      (offset 148, cleared on init)
  [0x998]     (offset 2456, flag)
  [0x99C]     (offset 2460, counter/flag)
  [0x9D8]     (offset 2520, 4-byte value)

ABL code evidence:
  SetUnlockValue (0x22e4c): strb w23, [x_devinfo, #13]  → devinfo[0x0D]
  SetUnlockCritical (0x22ea0): strb w23, [x_devinfo, #14] → devinfo[0x0E]
  WriteDeviceInfo (bl 0x18248): writes 2576 (0xA10) bytes to devinfo partition
  ReadDeviceInfo: only checks "ANDROID-BOOT!" magic, NO hash/signature
"""

import os
import hashlib

SRC = "/Users/xmxx/pinganhuijia/edl_backup/lun4/devinfo.bin"
DST = "/Users/xmxx/pinganhuijia/tmp/devinfo_unlocked.bin"

with open(SRC, "rb") as f:
    data = bytearray(f.read())

print(f"Original devinfo.bin: {len(data)} bytes")
print(f"  Magic:              {data[0:13]}")
print(f"  is_unlocked:        {data[0x0D]} ({'UNLOCKED' if data[0x0D] else 'LOCKED'})")
print(f"  is_unlock_critical: {data[0x0E]}")
print(f"  charger_screen:     {data[0x0F]}")
print(f"  SHA256:             {hashlib.sha256(data).hexdigest()}")

# Modify: set is_unlocked = 1
data[0x0D] = 0x01

print(f"\nModified devinfo.bin:")
print(f"  is_unlocked:        {data[0x0D]} ({'UNLOCKED' if data[0x0D] else 'LOCKED'})")
print(f"  is_unlock_critical: {data[0x0E]} (unchanged)")
print(f"  SHA256:             {hashlib.sha256(data).hexdigest()}")

with open(DST, "wb") as f:
    f.write(data)

print(f"\nWritten to: {DST}")
print(f"Size: {len(data)} bytes")

# Verify
with open(DST, "rb") as f:
    verify = f.read()
assert verify[0:13] == b"ANDROID-BOOT!", "Magic check failed!"
assert verify[0x0D] == 1, "is_unlocked not set!"
assert len(verify) == 4096, "Size mismatch!"
print("Verification: OK")
