#!/usr/bin/env python3
"""
Analyze diagnostic devinfo results.
Run this after flashing devinfo_diagnostic.bin, booting, checking fastboot,
and reading back the partition.

Usage:
  python3 tmp/analyze_diagnostic.py [readback_file]
  Default readback file: tmp/devinfo_readback_post.bin
"""
import sys
import os

path = sys.argv[1] if len(sys.argv) > 1 else '/Users/xmxx/pinganhuijia/tmp/devinfo_readback_post.bin'

if not os.path.exists(path):
    print(f'File not found: {path}')
    print('Available readback files:')
    tmp = '/Users/xmxx/pinganhuijia/tmp'
    for f in sorted(os.listdir(tmp)):
        if 'devinfo' in f and f.endswith('.bin'):
            print(f'  {os.path.join(tmp, f)}')
    sys.exit(1)

data = open(path, 'rb').read()
print(f'Analyzing: {path}')
print(f'Size: {len(data)} bytes')
print()

magic = data[0:13]
is_unlocked = data[0x0D]
is_unlock_critical = data[0x0E]
charger_screen = data[0x0F]
verity_mode = data[0x90] if len(data) > 0x90 else None
marker = data[0x998] if len(data) > 0x998 else None
end_marker = data[0xFFC:0x1000] if len(data) >= 0x1000 else None

print('=== READBACK VALUES ===')
print(f'  Magic:              {magic} {"OK" if magic == b"ANDROID-BOOT!" else "CHANGED!"}')
print(f'  is_unlocked [0x0D]: 0x{is_unlocked:02X} (set=0x01, default=0x00)')
print(f'  is_unlock_cr[0x0E]: 0x{is_unlock_critical:02X} (set=0x01, default=0x00)')
print(f'  charger_scr [0x0F]: 0x{charger_screen:02X} (set=0x00, default=0x01)')
if verity_mode is not None:
    print(f'  verity_mode [0x90]: 0x{verity_mode:02X} (set=0x00, default=0x01)')
if marker is not None:
    print(f'  marker    [0x998]:  0x{marker:02X} (set=0xAA)')
if end_marker is not None:
    print(f'  end marker [FFC]:   {end_marker} (set=b"TEST")')

# Compare with what we flashed
print()
print('=== DIAGNOSIS ===')

our_values = (is_unlocked == 0x01 and is_unlock_critical == 0x01 and
              charger_screen == 0x00 and (verity_mode == 0x00 if verity_mode is not None else True))
defaults = (is_unlocked == 0x00 and is_unlock_critical == 0x00 and
            charger_screen == 0x01 and (verity_mode == 0x01 if verity_mode is not None else True))

if our_values:
    print('ALL VALUES MATCH WHAT WE FLASHED!')
    print('→ The partition was NOT modified by boot.')
    print('→ If fastboot still shows unlocked=false, the in-memory buffer is different from partition.')
    print('→ This rules out init_defaults and confirms the paradox: partition has 1, memory has 0.')
elif defaults:
    print('ALL VALUES ARE DEFAULTS!')
    print('→ init_defaults RAN during boot.')
    if magic == b'ANDROID-BOOT!':
        print('→ Magic is correct, so init_defaults was called via OemCheckResetDevInfo (param==1)')
        print('→ OR: ReadWritePartition READ returned stale data with wrong magic')
    else:
        print('→ Magic was also reset, confirming init_defaults wrote everything')
    if end_marker == b'TEST':
        print('→ End marker preserved — init_defaults only writes first 2576 bytes')
    else:
        print('→ End marker also cleared — partition was fully rewritten')
elif is_unlocked == 0x00 and charger_screen == 0x00:
    print('is_unlocked=0 but charger_screen=0 (our value persisted)')
    print('→ init_defaults did NOT run (it would set charger=1)')
    if is_unlock_critical == 0x01:
        print('→ is_unlock_critical preserved! Only is_unlocked was targeted.')
        print('→ SetDeviceUnlocked second write path OR some undiscovered code')
    else:
        print('→ Both is_unlocked and is_unlock_critical were zeroed.')
        print('→ Some code specifically resets both unlock flags without calling init_defaults')
elif is_unlocked == 0x00 and charger_screen == 0x01:
    print('is_unlocked=0 AND charger_screen CHANGED to 1 (was 0)')
    print('→ Something modified both fields. Partial init_defaults?')
    print('→ Or SetChargerScreen(1) ran (persists) + something zeroed is_unlocked')
else:
    print('UNEXPECTED COMBINATION:')
    print(f'  unlocked={is_unlocked}, critical={is_unlock_critical}, charger={charger_screen}')
    print('→ Need further analysis')

# Also check if ReadDeviceInfo buffer size (2576 bytes = 0xA10) matters
if len(data) >= 0xA10:
    print()
    print(f'=== Bytes beyond ReadDeviceInfo range (offset 0xA10+) ===')
    # Check if data beyond 2576 is untouched
    beyond = data[0xA10:0x1000]
    if all(b == 0 for b in beyond):
        print('  All zeros beyond 0xA10 (as expected from our test binary)')
    else:
        non_zero = [(0xA10+i, b) for i, b in enumerate(beyond) if b != 0]
        if non_zero:
            print(f'  Non-zero bytes found beyond 0xA10: {non_zero[:10]}')
