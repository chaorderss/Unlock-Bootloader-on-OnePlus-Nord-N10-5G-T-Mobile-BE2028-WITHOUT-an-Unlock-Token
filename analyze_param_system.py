#!/usr/bin/env python3
"""
专注分析 OnePlus param 分区系统:
- set_param_by_index_and_offset / get_param_by_index_and_offset
- write_param_block / read_param_block
- initEncryptedBlockMD5
- OemCheckResetDevInfo 与 param 系统的联系

目标：理解 devinfo 读取路径 => 是从 'param' 分区还是 devinfo 分区
"""

DECOMP = "edl_backup/abl_decompressed_lzma_0x3078.bin"

with open(DECOMP, 'rb') as f:
    data = f.read()

def ctx(offset, before=200, after=300):
    start = max(0, offset - before)
    end = min(len(data), offset + after)
    chunk = data[start:end]
    for i in range(0, len(chunk), 16):
        row = chunk[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in row)
        asc_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
        print(f"  {start+i:08x}:  {hex_part:<48}  {asc_part}")

def find_all(needle):
    results = []
    idx = 0
    while True:
        pos = data.find(needle, idx)
        if pos < 0:
            break
        results.append(pos)
        idx = pos + 1
    return results

# ── 全局 param 分区名出现次数 ─────────────────────────────────────────────
print("=== 分区名搜索 ===")
for name in [b'param', b'/param', b'opconfig', b'persist', b'frp', b'config',
             b'devcfg', b'nvram', b'nvm', b'NVRAM']:
    positions = find_all(name)
    print(f"  '{name.decode()}': {len(positions)} 次, 首见 {hex(positions[0]) if positions else 'none'}")

# ── param 分区读写日志 ────────────────────────────────────────────────────
print("\n=== param 分区读写详情 ===")
for needle in [b'write_param_block', b'read_param_block',
               b'write_param_encrypt_block', b'read_param_encrypt_block',
               b'set_param_by_index_and_offset',
               b'get_param_by_index_and_offset',
               b'Error write param partition',
               b'param_init',
               b'initEncryptedBlockMD5']:
    positions = find_all(needle)
    if positions:
        print(f"\n[{needle.decode()}] 出现 {len(positions)} 次")
        for pos in positions[:2]:
            p = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[max(0,pos-80):pos+len(needle)+120])
            print(f"  @{hex(pos)}: {p!r}")

# ── is_unlocked 在 param 里的 SID (slot ID) ──────────────────────────────
print("\n\n=== unlock 相关 SID 分析 ===")
# OemCheckResetDevInfo 把 devinfo 的某个字段重置时会用 set_param_by_index
# 找 devinfo 的 "index" 和这些 ops 的关联
for needle in [b'unlock_count', b'poweron_count', b'poweroff_count', b'update_count']:
    positions = find_all(needle)
    if positions:
        pos = positions[0]
        p = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[max(0,pos-60):pos+len(needle)+120])
        print(f"\n[{needle.decode()}] @{hex(pos)}: {p!r}")

# ── 关键：ABL_TAMPER / tamper 标记在 param 还是 devinfo ─────────────────
print("\n\n=== tamper / abl_tamper 标记位置 ===")
for needle in [b'abl_tamper', b'ABL_TAMPER', b'tamper', b'Set abl_tamper',
               b'tamper_detect', b'is_tampered']:
    positions = find_all(needle)
    if positions:
        pos = positions[0]
        p = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[max(0,pos-80):pos+len(needle)+150])
        print(f"\n[{needle.decode()}] @{hex(pos)}: {p!r}")

# ── 找 devinfo 分区 GUID 或名字 ──────────────────────────────────────────
print("\n\n=== 分区访问函数名 ===")
for needle in [b'GetPartitionEntry', b'partition devinfo',
               b'ReadFromPartition', b'WriteToPartition',
               b'ops->read_from_partition', b'ops->write_to_partition',
               b'BlockIo->ReadBlocks', b'BlockIo->WriteBlocks']:
    positions = find_all(needle)
    if positions:
        pos = positions[0]
        p = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[max(0,pos-40):pos+len(needle)+100])
        print(f"\n[{needle.decode()}] @{hex(pos)}: {p!r}")

print("\n[完成]")
