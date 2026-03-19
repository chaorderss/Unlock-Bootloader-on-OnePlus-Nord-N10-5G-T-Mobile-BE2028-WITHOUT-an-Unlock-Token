#!/usr/bin/env python3
"""
Create diagnostic devinfo binary for empirical testing.

Purpose: Flash this via EDL, boot to fastboot, check `fastboot oem device-info`.
The non-default values allow us to determine EXACTLY what happened during boot.

Fields set:
  [0x00-0x0C] "ANDROID-BOOT!" magic (preserved, 13 bytes)
  [0x0D] is_unlocked = 0x01 (changed from default 0x00)
  [0x0E] is_unlock_critical = 0x01 (changed from default 0x00)
  [0x0F] charger_screen = 0x00 (changed from default 0x01)
  [0x90] verity_mode = 0x00 (changed from default 0x01)
  [0x998] = 0xAA (marker byte, normally 0x01)
  [0xFFC-0xFFF] = "TEST" marker at end of 4096-byte partition

Expected results after boot:
  Case 1 - ALL defaults (unlocked=false, critical=false, charger=true):
    → init_defaults ran. Either magic failed or ReadWritePartition failed.
    → Check partition readback: if defaults on partition too → init_defaults persisted
    → If our values on partition → ReadWritePartition READ failed (data never loaded)

  Case 2 - unlocked=false, critical=false, charger=false (our charger persisted):
    → init_defaults did NOT run (charger would be 1 if it did)
    → Something specifically sets is_unlocked=0 and is_unlock_critical=0

  Case 3 - unlocked=false, critical=true, charger=false:
    → Only is_unlocked gets zeroed, not is_unlock_critical
    → Narrows the culprit to SetDeviceUnlocked or similar

  Case 4 - unlocked=true, critical=true, charger=false:
    → ALL our values persist! Success!
    → Previous test might have had a different issue
"""

import os

# Start with zeros
data = bytearray(4096)

# Magic
data[0:13] = b'ANDROID-BOOT!'

# Test values (all different from defaults)
data[0x0D] = 0x01  # is_unlocked = TRUE
data[0x0E] = 0x01  # is_unlock_critical = TRUE
data[0x0F] = 0x00  # charger_screen = DISABLED (default is 1)
data[0x90] = 0x00  # verity_mode = DISABLED (default is 1)
data[0x998] = 0xAA # marker byte (default area has 0x01)

# End-of-partition marker
data[0xFFC:0x1000] = b'TEST'

out_path = '/Users/xmxx/pinganhuijia/tmp/devinfo_diagnostic.bin'
with open(out_path, 'wb') as f:
    f.write(data)

print(f'Created: {out_path}')
print(f'Size: {len(data)} bytes')
print()
print('Verification:')
print(f'  Magic:              {data[0:13]}')
print(f'  is_unlocked [0x0D]: 0x{data[0x0D]:02X} (want: 0x01)')
print(f'  is_unlock_cr[0x0E]: 0x{data[0x0E]:02X} (want: 0x01)')
print(f'  charger_scr [0x0F]: 0x{data[0x0F]:02X} (want: 0x00, default=0x01)')
print(f'  verity_mode [0x90]: 0x{data[0x90]:02X} (want: 0x00, default=0x01)')
print(f'  marker      [0x998]:0x{data[0x998]:02X} (want: 0xAA)')
print(f'  end marker  [FFC]:  {data[0xFFC:0x1000]}')
print()
print('=== FLASH INSTRUCTIONS ===')
print('1. Connect device in EDL mode')
print('2. Run: edl w devinfo tmp/devinfo_diagnostic.bin --lun=4')
print('3. Verify: edl r devinfo tmp/devinfo_readback_pre.bin --lun=4')
print('4. Reboot: edl reset')
print('5. Wait for fastboot mode (hold vol-down during boot?)')
print('6. Run: fastboot oem device-info')
print('7. Read back: edl r devinfo tmp/devinfo_readback_post.bin --lun=4')
print()
print('=== RESULT INTERPRETATION ===')
print('After step 6, check fastboot output:')
print('  unlocked=false + critical=false + charger=enabled  → init_defaults ran')
print('  unlocked=false + critical=false + charger=disabled  → specific zeroing')
print('  unlocked=false + critical=true  + charger=disabled  → only is_unlocked targeted')
print('  unlocked=true  + critical=true  + charger=disabled  → SUCCESS! All persisted')
