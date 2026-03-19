#!/usr/bin/env python3
"""
分析 param 分区结构，寻找 reset_devinfo 标志
"""
import struct
import hashlib

PARAM = "/Users/xmxx/pinganhuijia/edl_backup/param.bin"
with open(PARAM, "rb") as f:
    param = f.read()

print(f"param.bin 大小: {len(param)} bytes (0x{len(param):X})")
print(f"MD5: {hashlib.md5(param).hexdigest()}")

# ============================================================
# 1. 头部结构分析
# ============================================================
print("\n" + "=" * 70)
print("1. 头部结构 (前 256 字节)")
print("=" * 70)
for i in range(0, 256, 16):
    hex_part = ' '.join(f'{param[i+j]:02X}' for j in range(16))
    ascii_part = ''.join(chr(param[i+j]) if 0x20 <= param[i+j] < 0x7F else '.' for j in range(16))
    print(f"  0x{i:04X}: {hex_part}  {ascii_part}")

# ============================================================
# 2. 搜索 "PRODUCT" 和其他已知字段
# ============================================================
print("\n" + "=" * 70)
print("2. 搜索已知字段")
print("=" * 70)
for needle, label in [(b"PRODUCT", "PRODUCT"), (b"20801", "Model"),
                       (b"20888", "Model2"), (b"20889", "Model3"),
                       (b"\x00\x04\x00\x00", "Magic?"),
                       (b"ANDROID", "ANDROID"), (b"param", "param"),
                       (b"reset", "reset"), (b"devinfo", "devinfo")]:
    pos = 0
    while True:
        idx = param.find(needle, pos)
        if idx == -1:
            break
        context = param[max(0,idx-8):idx+len(needle)+8]
        print(f"  [{label}] 0x{idx:06X}: {context.hex()}")
        pos = idx + len(needle)

# ============================================================
# 3. 分析段结构 — 查找 MD5 校验和
# ============================================================
print("\n" + "=" * 70)
print("3. 搜索 MD5 校验和 (16字节高熵块)")
print("=" * 70)
md5_candidates = []
for i in range(0, len(param) - 16, 16):
    block = param[i:i+16]
    # High entropy: all bytes different, no zeros
    unique = len(set(block))
    if unique >= 12 and all(b != 0 for b in block):
        # Check if surrounding area is meaningful
        before = param[max(0,i-4):i]
        after = param[i+16:i+20]
        md5_candidates.append(i)

print(f"  找到 {len(md5_candidates)} 个高熵 16 字节块 (可能是 MD5)")
for off in md5_candidates[:20]:
    print(f"  0x{off:06X}: {param[off:off+16].hex()}")

# ============================================================
# 4. 查找段边界 (0x1000 = 4K 对齐的非零块)
# ============================================================
print("\n" + "=" * 70)
print("4. 段分布（4K 块使用情况）")
print("=" * 70)
for i in range(0, len(param), 0x1000):
    block = param[i:i+0x1000]
    nonzero = sum(1 for b in block if b != 0)
    if nonzero > 0:
        first_bytes = block[:32].hex()
        print(f"  0x{i:06X}: {nonzero:4d} 非零字节 | {first_bytes}")

# ============================================================
# 5. 检查 SID 结构 — 查看是否有段索引表
# ============================================================
print("\n" + "=" * 70)
print("5. 查找段索引表（固定模式）")
print("=" * 70)
# Check for repeated 4-byte patterns that could be segment offsets
for off in range(0, 0x200, 4):
    val = struct.unpack_from('<I', param, off)[0]
    if 0x1000 <= val <= len(param) and val % 0x100 == 0:
        print(f"  0x{off:04X}: 0x{val:08X} (可能是段偏移)")

# Check for 8-byte entries: (offset, size) pairs
for off in range(0, 0x400, 8):
    offset_val = struct.unpack_from('<I', param, off)[0]
    size_val = struct.unpack_from('<I', param, off+4)[0]
    if 0x1000 <= offset_val <= len(param) and 0 < size_val <= 0x10000:
        print(f"  0x{off:04X}: offset=0x{offset_val:X}, size=0x{size_val:X}")

# ============================================================
# 6. 检查偏移 0x31A0 附近（get_param 使用的偏移）
# ============================================================
print("\n" + "=" * 70)
print("6. 偏移 0x31A0 附近 (get_param 读取 reset_devinfo 的位置)")
print("=" * 70)
for i in range(0x3180, 0x31E0, 16):
    hex_part = ' '.join(f'{param[i+j]:02X}' for j in range(16))
    ascii_part = ''.join(chr(param[i+j]) if 0x20 <= param[i+j] < 0x7F else '.' for j in range(16))
    print(f"  0x{i:04X}: {hex_part}  {ascii_part}")

# ============================================================
# 7. dump SID 相关区域 — 检查 SID 13 (0xD)
# ============================================================
print("\n" + "=" * 70)
print("7. 搜索 SID 结构 (寻找索引 13 相关数据)")
print("=" * 70)
# set_param_by_index_and_offset(13, 0x24, buf, 4) — SID=13, offset=0x24
# This means there's a segment with index 13, and within it, offset 0x24 has the flag

# Look for SID header patterns
# Common patterns: magic words followed by index
for off in range(0, len(param) - 4):
    val = struct.unpack_from('<I', param, off)[0]
    if val == 0x0D:  # Looking for SID index 13
        # Check context
        before = struct.unpack_from('<I', param, max(0, off-4))[0] if off >= 4 else 0
        after = struct.unpack_from('<I', param, off+4)[0] if off + 4 < len(param) else 0
        # Only report if surrounding looks structured
        if (before < 0x100 or after < 0x1000) and off < 0x1000:
            context = param[max(0,off-8):off+12].hex()
            print(f"  0x{off:04X}: val=0x{val:08X} | context: {context}")

# ============================================================
# 8. 加密段检测
# ============================================================
print("\n" + "=" * 70)
print("8. 加密段检测（高熵区域）")
print("=" * 70)
import math
for i in range(0, len(param), 0x1000):
    block = param[i:i+0x1000]
    nonzero = sum(1 for b in block if b != 0)
    if nonzero > 100:
        # Calculate Shannon entropy
        freq = {}
        for b in block:
            freq[b] = freq.get(b, 0) + 1
        entropy = -sum((c/len(block)) * math.log2(c/len(block)) for c in freq.values())
        enc_label = "★ 可能加密" if entropy > 7.0 else "  明文" if entropy < 5.0 else "  中等"
        print(f"  0x{i:06X}: 熵={entropy:.2f} {enc_label} ({nonzero} 非零字节)")

# ============================================================
# 9. 检查偏移 0x2888 附近（第二个 get_param 调用）
# ============================================================
print("\n" + "=" * 70)
print("9. 偏移 0x2888 附近 (第2个 get_param 调用)")
print("=" * 70)
for i in range(0x2870, 0x28B0, 16):
    hex_part = ' '.join(f'{param[i+j]:02X}' for j in range(16))
    ascii_part = ''.join(chr(param[i+j]) if 0x20 <= param[i+j] < 0x7F else '.' for j in range(16))
    print(f"  0x{i:04X}: {hex_part}  {ascii_part}")

# ============================================================
# 10. 检查是否有 "global_patched" 版本
# ============================================================
print("\n" + "=" * 70)
print("10. 检查备份文件中的 param 版本")
print("=" * 70)
import os
for root, dirs, files in os.walk("/Users/xmxx/pinganhuijia"):
    for f in files:
        if "param" in f.lower():
            full = os.path.join(root, f)
            size = os.path.getsize(full)
            print(f"  {full} ({size} bytes)")

print("\nDone.")
