#!/usr/bin/env python3
"""Check op1, config, and other partitions for ANDROID-BOOT! magic."""
import os

magic = b'ANDROID-BOOT!'
base = '/Users/xmxx/pinganhuijia/edl_backup'
targets = [
    'lun4/op1.bin',
    'lun0/config.bin',
    'lun0/oem_dycnvbk.bin',
    'lun0/oem_stanvbk.bin',
    'lun0/persist.bin',
]

for t in targets:
    fp = os.path.join(base, t)
    if not os.path.isfile(fp):
        continue
    sz = os.path.getsize(fp)
    with open(fp, 'rb') as f:
        data = f.read(min(sz, 10 * 1024 * 1024))
    idx = data.find(magic)
    if idx >= 0:
        print(f'{t}: FOUND at 0x{idx:X} (size={sz})')
        d = data[idx:idx+0x20]
        print(f'  hex: {d.hex()}')
    else:
        print(f'{t}: not found (size={sz})')

# Also dump the first 128 bytes of op1
op1 = os.path.join(base, 'lun4/op1.bin')
if os.path.isfile(op1):
    with open(op1, 'rb') as f:
        d = f.read(128)
    print(f'\nop1.bin first 128 bytes:')
    for i in range(0, len(d), 16):
        hx = ' '.join(f'{b:02X}' for b in d[i:i+16])
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in d[i:i+16])
        print(f'  {i:04X}: {hx}  {asc}')

# Dump first 128 bytes of config.bin
cfg = os.path.join(base, 'lun0/config.bin')
if os.path.isfile(cfg):
    with open(cfg, 'rb') as f:
        d = f.read(128)
    print(f'\nconfig.bin first 128 bytes:')
    for i in range(0, len(d), 16):
        hx = ' '.join(f'{b:02X}' for b in d[i:i+16])
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in d[i:i+16])
        print(f'  {i:04X}: {hx}  {asc}')

print('\nDone.')
