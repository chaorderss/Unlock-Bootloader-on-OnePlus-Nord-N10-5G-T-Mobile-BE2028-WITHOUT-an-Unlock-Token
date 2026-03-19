#!/usr/bin/env python3
"""
Try all GZIP signatures in T-Mobile ABL PT_LOAD to find the one
that contains 'ANDROID-BOOT!' (i.e. the actual ABL runtime code).
"""
import gzip

with open('edl_backup/abl_b.img','rb') as f:
    f.seek(0x3000)
    payload = f.read(0x212000)

# Find all gzip sigs
gzip_sigs = []
pos = 0
while True:
    idx = payload.find(b'\x1f\x8b', pos)
    if idx == -1:
        break
    gzip_sigs.append(idx)
    pos = idx + 1

print(f"Found {len(gzip_sigs)} possible GZIP streams")

target_strings = [
    b'ANDROID-BOOT!',
    b'Please flash unlock token',
    b'unlocked, Skipping boot',
    b'Device unlocked',
]

for sig_off in gzip_sigs:
    try:
        dec = gzip.decompress(payload[sig_off:])
        hits = []
        for s in target_strings:
            if s in dec:
                hits.append(s.decode('ascii', 'ignore'))
        if hits:
            print(f"\n*** payload+0x{sig_off:X}: decompressed 0x{len(dec):X} bytes, FOUND: {hits}")
        else:
            print(f"  payload+0x{sig_off:X}: decompressed 0x{len(dec):X} bytes, no key strings")
    except Exception as e:
        pass  # silent skip on failures
