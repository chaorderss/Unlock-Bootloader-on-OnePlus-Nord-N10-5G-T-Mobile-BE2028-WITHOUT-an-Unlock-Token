#!/usr/bin/env python3
import struct, gzip

with open('edl_backup/abl_b.img','rb') as f:
    f.seek(0x3000)
    payload = f.read(0x212000)

gzip_off = 0x7518
gz_data = payload[gzip_off:]
print(f'Trying to decompress GZIP at PT_LOAD+0x{gzip_off:X} ...')
try:
    dec = gzip.decompress(gz_data)
    print(f'Decompressed size: 0x{len(dec):X} bytes')
    for s in [b'Please flash unlock token', b'unlocked, Skipping boot',
              b'ANDROID-BOOT!', b'Device unlocked', b'avb_slot_verify',
              b'Your device is corrupt', b'boot state is:',
              b'OemCheckResetDevInfo']:
        idx = dec.find(s)
        if idx != -1:
            snippet = dec[idx:idx+60]
            printable = ''.join(chr(b) if 32<=b<127 else '.' for b in snippet)
            print(f'  [FOUND] 0x{idx:06X}: {printable[:60]}')
        else:
            print(f'  [NOT FOUND] {s.decode("ascii","ignore")}')
except Exception as e:
    print(f'Decompression failed: {e}')
    pos = 0
    while True:
        idx = payload.find(b'\x1f\x8b', pos+1)
        if idx == -1:
            break
        print(f'  gzip signature at payload+0x{idx:X}')
        pos = idx
        if pos > gzip_off + 0x100000:
            break
