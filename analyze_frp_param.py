#!/usr/bin/env python3
"""
分析 frp.bin 和 param.bin 分区：
1. frp.bin — IsAllowUnlock 读取的 FRP 分区，确认其内容
2. param.bin — OnePlus param 系统，找 unlock/lock 状态字段
"""

import struct
import hashlib
import re

def hexdump(data, offset=0, length=256):
    for i in range(0, min(length, len(data)), 16):
        row = data[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in row)
        asc_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
        print(f"  {offset+i:08x}:  {hex_part:<48}  {asc_part}")

def find_all(data, needle):
    results = []
    idx = 0
    while True:
        pos = data.find(needle, idx)
        if pos < 0:
            break
        results.append(pos)
        idx = pos + 1
    return results

# ══════════════════════════════════════════════════════════════════════════════
# 1. FRP 分区分析
# ══════════════════════════════════════════════════════════════════════════════
print("=" * 70)
print("FRP 分区分析 (frp.bin)")
print("=" * 70)

with open("edl_backup/frp.bin", "rb") as f:
    frp = f.read()

print(f"大小: {len(frp)} bytes ({len(frp)//1024}KB)")
print(f"全零: {all(b == 0 for b in frp)}")
print(f"非零字节数: {sum(1 for b in frp if b != 0)}")

# 找非零区域
nonzero_ranges = []
in_nonzero = False
start = 0
for i, b in enumerate(frp):
    if b != 0 and not in_nonzero:
        start = i
        in_nonzero = True
    elif b == 0 and in_nonzero:
        nonzero_ranges.append((start, i))
        in_nonzero = False
if in_nonzero:
    nonzero_ranges.append((start, len(frp)))

print(f"非零区域: {nonzero_ranges[:20]}")
for (s, e) in nonzero_ranges[:5]:
    print(f"\n  [{hex(s)}..{hex(e)}]:")
    hexdump(frp[s:e+32], offset=s)

# 搜索常见的 FRP unlock 标记
print("\nFRP 分区字符串:")
for kw in [b'unlock', b'lock', b'frp', b'allow', b'factory', b'\x01', b'\xff']:
    positions = find_all(frp, kw)
    if positions:
        print(f"  '{kw!r}' 出现 {len(positions)} 次, 首见 {hex(positions[0])}")

# ══════════════════════════════════════════════════════════════════════════════
# 2. PARAM 分区分析
# ══════════════════════════════════════════════════════════════════════════════
print("\n\n" + "=" * 70)
print("PARAM 分区分析 (param.bin)")
print("=" * 70)

with open("edl_backup/param.bin", "rb") as f:
    param = f.read()

print(f"大小: {len(param)} bytes ({len(param)//1024}KB)")

# 找头部
print("\n头部 (前256字节):")
hexdump(param, length=256)

# 搜索魔术字符串
print("\nPARAM 字符串:")
for kw in [b'PARAM', b'param', b'OnePlus', b'oneplus', b'OP_', b'op_',
           b'unlock', b'locked', b'is_unlock', b'devinfo',
           b'magic', b'MAGIC', b'\xaa\xbb', b'\xde\xad\xbe\xef']:
    positions = find_all(param, kw)
    if positions:
        print(f"  '{kw!r}': {len(positions)} 次, 首 {hex(positions[0])}")

# 尝试找到块结构
# OnePlus param 通常是固定块大小 (如 4096 字节) 的 SID 表
# 每个 SID 块有 header + data + checksum
print("\n\n尝试识别 param 块结构...")
BLOCK_SIZES = [512, 1024, 2048, 4096]
for bs in BLOCK_SIZES:
    # 看每个块的前8字节有没有规律
    first_bytes = []
    for i in range(0, min(len(param), bs*16), bs):
        block = param[i:i+bs]
        first_bytes.append(block[:8].hex())
    unique = len(set(first_bytes))
    print(f"  块大小={bs}: 前16块首8字节唯一值={unique} {first_bytes[:8]}")

# 找所有可打印字符串
print("\n\nPARAM 中的所有可打印字符串 (>=8字节):")
for m in re.finditer(rb'[\x20-\x7e]{8,}', param):
    print(f"  @{hex(m.start())}: {m.group().decode()!r}")

# MD5 校验块分析
print("\n\nMD5 特征搜索 (16字节随机块可能是 MD5):")
# 看 param 分区是否有规律性非零块
nonzero_blocks_count = sum(1 for i in range(0, len(param), 512)
                           if any(b != 0 for b in param[i:i+512]))
print(f"  非零 512B 块数: {nonzero_blocks_count} / {len(param)//512}")

# 打印所有非零块
for i in range(0, len(param), 512):
    block = param[i:i+512]
    if any(b != 0 for b in block):
        print(f"\n  非零块 @{hex(i)} (前128字节):")
        hexdump(block[:128], offset=i)

print("\n[完成]")
