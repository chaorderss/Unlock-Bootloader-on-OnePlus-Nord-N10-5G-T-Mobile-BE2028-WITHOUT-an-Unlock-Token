#!/usr/bin/env python3
"""
Build final devinfo:
  - [0x00-0x0C]: "ANDROID-BOOT!" (13 bytes)
  - [0x0D-0x0F]: 0x00 x3  (correct padding so DEVICE_MAGIC_SIZE=16 check passes)
  - [0x10]: is_unlocked = 1
  - [0x11]: is_unlock_critical = 1  (for good measure)
  - [0x12]: is_tampered = 0         (keep 0, don't want tampered flag)
  - [0x13]: charger_screen_enabled = 0
  - [0x14]: verity_mode = 0
  - [0x15]: oem_unlock_allowed = 1  (ensure get_unlock_ability still returns 1)
  The rest of the 4096 bytes remain 0x00.
"""
import struct, zlib
OUT = '/Users/xmxx/pinganhuijia/edl_backup/devinfo_final.bin'

dv = bytearray(4096)
magic = b'ANDROID-BOOT!'
dv[:len(magic)] = magic
# [0x0D-0x0F] = 0x00 (auto, already zero)
dv[0x10] = 0x01   # is_unlocked = TRUE
dv[0x11] = 0x00   # is_unlock_critical (keep 0)
dv[0x12] = 0x00   # is_tampered (keep 0, avoid tamper flag triggering red screen)
dv[0x13] = 0x00   # charger_screen_enabled
dv[0x14] = 0x00   # verity_mode
dv[0x15] = 0x01   # oem_unlock_allowed = 1 (preserves get_unlock_ability=1)

with open(OUT, 'wb') as f:
    f.write(dv)

print("Written:", OUT)
print("First 32 bytes:")
for i in range(0, 32, 16):
    chunk = dv[i:i+16]
    hexs = ' '.join(f'{b:02x}' for b in chunk)
    ascs = ''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
    print(f"  {i:04x}: {hexs}  {ascs}")
print()
print("Key fields:")
print(f"  [0x00-0x0C] = ", dv[:13])
print(f"  [0x0D-0x0F] = {dv[0x0D]:#04x} {dv[0x0E]:#04x} {dv[0x0F]:#04x}  (magic padding, must be 0)")
print(f"  [0x10] is_unlocked        = {dv[0x10]}")
print(f"  [0x11] is_unlock_critical = {dv[0x11]}")
print(f"  [0x12] is_tampered        = {dv[0x12]}")
print(f"  [0x13] chgr_screen        = {dv[0x13]}")
print(f"  [0x14] verity_mode        = {dv[0x14]}")
print(f"  [0x15] oem_unlock_allowed = {dv[0x15]}")
print()
print("CRC check won't apply (ABL seems not to use CRC for devinfo on this device)")
print()
print("Next steps:")
print("1. Reboot phone to EDL:  fastboot reboot edl  (or vol-down + power)")
print("2. Flash:  edl w devinfo edl_backup/devinfo_final.bin --loader <fhprg_op_n10.bin>")
print("3. Reboot to fastboot:  edl reset  then power+vol-up or  misc=bootonce-bootloader")
print("4. Check:  fastboot oem device-info")
print("   Expected: 'Device unlocked: true'")
print("5. If unlocked, install Magisk:")
print("   magiskboot patch boot.img  (or use Magisk app)")
print("   fastboot flash boot magisk_patched_boot.img")
print("   fastboot reboot")
