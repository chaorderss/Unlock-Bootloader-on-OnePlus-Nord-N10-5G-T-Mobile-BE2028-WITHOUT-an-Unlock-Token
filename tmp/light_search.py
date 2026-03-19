#!/usr/bin/env python3
"""Lightweight search: check specific small partitions for ANDROID-BOOT! magic."""
import os

backup_dir = '/Users/xmxx/pinganhuijia/edl_backup'
magic = b'ANDROID-BOOT!'

# Only check files under 1MB to avoid freezing
for lun in ['lun0', 'lun1', 'lun2', 'lun3', 'lun4', 'lun5']:
    lun_dir = os.path.join(backup_dir, lun)
    if not os.path.isdir(lun_dir):
        continue
    for fname in sorted(os.listdir(lun_dir)):
        fpath = os.path.join(lun_dir, fname)
        size = os.path.getsize(fpath)
        if size > 1048576 or size == 0:  # skip >1MB
            continue
        try:
            data = open(fpath, 'rb').read()
            idx = data.find(magic)
            if idx >= 0:
                print(f'FOUND! {lun}/{fname} (size={size}) at offset 0x{idx:X}')
                print(f'  bytes[0x0D]: 0x{data[idx+13]:02X}')
                print(f'  bytes[0x0E]: 0x{data[idx+14]:02X}')
                print(f'  bytes[0x0F]: 0x{data[idx+15]:02X}')
        except Exception as e:
            pass

print('\nDone.')
