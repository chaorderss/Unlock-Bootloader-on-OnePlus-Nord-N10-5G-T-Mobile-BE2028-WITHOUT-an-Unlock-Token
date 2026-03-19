#!/usr/bin/env python3
"""Search for target instruction sequence in raw ABL images - correct byte order"""
import struct

# ARM64 instructions are stored little-endian in memory
# d65f03c0 -> c0 03 5f d6
# 97fff219 -> 19 f2 ff 97
# 72001c1f -> 1f 1c 00 72
# 54000080 -> 80 00 00 54
# 320003e0 -> e0 03 00 32
insns = [0xd65f03c0, 0x97fff219, 0x72001c1f, 0x54000080, 0x320003e0]
target_seq = b''.join(struct.pack('<I', x) for x in insns)
print('Searching for: ' + target_seq.hex())

for name in ['global_abl.img', 'global_abl_padded.img', 'global_abl_raw.img', 'global_abl_decompressed.bin']:
    path = '/Users/xmxx/pinganhuijia/' + name
    try:
        with open(path, 'rb') as f:
            data = f.read()
        idx = data.find(target_seq)
        if idx >= 0:
            print(name + ': FOUND at offset ' + hex(idx))
            beq_off = idx + 12  # 3 instructions * 4 bytes
            beq_bytes = data[beq_off:beq_off+4]
            beq_val = struct.unpack('<I', beq_bytes)[0]
            print('  B.EQ at file offset ' + hex(beq_off) + ': ' + hex(beq_val) + ' (bytes: ' + beq_bytes.hex() + ')')
        else:
            print(name + ': not found in ' + str(len(data)) + ' bytes')
    except FileNotFoundError:
        pass
