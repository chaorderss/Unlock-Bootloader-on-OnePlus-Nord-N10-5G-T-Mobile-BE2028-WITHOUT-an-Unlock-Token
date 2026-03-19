#!/usr/bin/env python3
import os, sys

magic = b'ANDROID-BOOT!'
base = '/Users/xmxx/pinganhuijia/edl_backup'

targets = [
    'lun0/config.bin', 'lun0/frp.bin', 'lun0/misc.bin', 'lun0/param.bin',
    'lun0/persist.bin',
    'lun1/xbl_config_a.bin', 'lun2/xbl_config_b.bin',
    'lun4/multiimgoem.bin', 'lun4/op1.bin', 'lun4/dip.bin',
    'lun4/reserve1.bin', 'lun4/abl_log.bin', 'lun4/logfs.bin',
    'lun4/logdump.bin', 'lun4/catecontentfv.bin', 'lun4/catefv.bin',
    'lun4/cateloader.bin', 'lun4/questdatafv.bin',
]

for t in targets:
    fp = os.path.join(base, t)
    if not os.path.isfile(fp):
        print(f'SKIP: {t}')
        continue
    sz = os.path.getsize(fp)
    sys.stdout.write(f'{t} ({sz})... ')
    sys.stdout.flush()
    with open(fp, 'rb') as f:
        chunk_size = 1024 * 1024
        offset = 0
        found = False
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            idx = data.find(magic)
            if idx >= 0:
                pos = offset + idx
                print(f'FOUND at 0x{pos:X}')
                d = data[idx:idx+0x100]
                print(f'  is_unlocked={d[0xD]:02X} unlock_critical={d[0xE]:02X} charger={d[0xF]:02X}')
                found = True
                break
            offset += len(data) - len(magic)
            f.seek(offset)
        if not found:
            print('no')

print('\nDone.')
