#!/usr/bin/env python3
"""Search for target instruction sequence in raw ABL images"""
import struct

target_seq = bytes.fromhex('d65f03c097fff21972001c1f54000080320003e0')

for name in ['global_abl.img', 'global_abl_padded.img', 'global_abl_raw.img']:
    path = '/Users/xmxx/pinganhuijia/' + name
    try:
        with open(path, 'rb') as f:
            data = f.read()
        idx = data.find(target_seq)
        if idx >= 0:
            print(name + ': FOUND at offset ' + hex(idx))
            beq_off = idx + 12
            print('  B.EQ at offset ' + hex(beq_off) + ': ' + data[beq_off:beq_off+4].hex())
        else:
            print(name + ': not found in ' + str(len(data)) + ' bytes')
    except FileNotFoundError:
        pass

# Confirm in decompressed blob
with open('/Users/xmxx/pinganhuijia/global_abl_decompressed.bin', 'rb') as f:
    data = f.read()
idx = data.find(target_seq)
print('decompressed.bin: found at ' + hex(idx) + ' (expected 0x3bc70)')
print('  B.EQ at ' + hex(idx+12) + ': ' + data[idx+12:idx+16].hex())
