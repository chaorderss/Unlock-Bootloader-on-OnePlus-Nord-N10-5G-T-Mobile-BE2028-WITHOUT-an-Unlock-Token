#!/usr/bin/env python3
"""枚举 param 分区所有 SID 块，找 unlock 状态"""

with open("edl_backup/param.bin", "rb") as f:
    param = f.read()

print("=== PARAM 分区 SID 表 ===")
print(f"{'偏移':10s}  {'SID':5s}  {'名称':24s}  数据预览")
print("-" * 80)

block_size = 0x400
for i in range(0, len(param), block_size):
    block = param[i:i+block_size]
    if all(b == 0 for b in block):
        continue
    name = block[:16].split(b'\x00')[0].decode('ascii', errors='replace')
    sid = int.from_bytes(block[0x10:0x14], 'little')
    size_field = int.from_bytes(block[0x14:0x18], 'little')
    preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in block[0x18:0x18+40])
    hex_preview = block[0x18:0x18+16].hex()
    print(f"  {hex(i):8s}  {sid:5d}  {name:24s}  [{hex_preview}] {preview}")
