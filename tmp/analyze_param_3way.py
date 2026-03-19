#!/usr/bin/env python3
"""分析 param 三个版本的差异：original / patched (刷入) / readback (重启后)"""
import struct

def read(path):
    with open(path, "rb") as f:
        return f.read()

orig    = read("edl_backup/param.bin")
patched = read("edl_backup/param_global_patched.bin")
actual  = read("tmp/param_readback_after_reboot.bin")

# 分区域统计差异
BLOCK = 0x400  # 1024-byte param blocks
regions = {}
for i in range(0, min(len(orig), len(patched), len(actual)), BLOCK):
    blk_orig = orig[i:i+BLOCK]
    blk_pat  = patched[i:i+BLOCK]
    blk_act  = actual[i:i+BLOCK]

    d_pat_orig = sum(a!=b for a,b in zip(blk_orig, blk_pat))
    d_act_orig = sum(a!=b for a,b in zip(blk_orig, blk_act))
    d_act_pat  = sum(a!=b for a,b in zip(blk_pat, blk_act))

    if d_pat_orig or d_act_orig or d_act_pat:
        # Try to read block name
        name = ""
        try:
            end = blk_orig.index(0)
            name = blk_orig[:end].decode('ascii', errors='replace')
        except ValueError:
            if blk_orig[:4] == b'\xa0\xad\x64\x6a':
                name = f"ENCRYPTED(magic=6a64ada0)"
            else:
                name = f"data({blk_orig[:4].hex()})"

        regions[i] = {
            "name": name,
            "pat_vs_orig": d_pat_orig,
            "act_vs_orig": d_act_orig,
            "act_vs_pat":  d_act_pat,
        }

print("=" * 90)
print(f"  PARAM 三方对比: original / patched(刷入前) / readback(重启后EDL读回)")
print("=" * 90)
print(f"\n  总差异: readback vs patched = 3080 bytes, readback vs original = 6154 bytes")
print(f"\n{'offset':>10}  {'block name':<28} {'pat-orig':>9} {'act-orig':>9} {'act-pat':>9}  状态")
print("-" * 90)

for off, r in sorted(regions.items()):
    status = ""
    if r["act_vs_pat"] == 0:
        status = "✅ 保持patched值"
    elif r["act_vs_orig"] == 0:
        status = "❌ 被恢复为original"
    elif r["pat_vs_orig"] == 0 and r["act_vs_orig"] > 0:
        status = "⚠️ ABL新写入(orig==patched但readback不同)"
    elif r["act_vs_pat"] > 0 and r["act_vs_orig"] > 0:
        status = "⚠️ ABL修改(三方都不同)"

    print(f"  0x{off:06X}  {r['name']:<28} {r['pat_vs_orig']:>9} {r['act_orig']:>9} {r['act_vs_pat']:>9}  {status}"
          if 'act_orig' in r else
          f"  0x{off:06X}  {r['name']:<28} {r['pat_vs_orig']:>9} {r['act_vs_orig']:>9} {r['act_vs_pat']:>9}  {status}")

# 重点：找 ABL 新写入的区域（patched == original 但 readback 不同）
print("\n" + "=" * 90)
print("  ABL 新写入的字节 (原始==patched 但 readback不同，即 ABL 自己写的)")
print("=" * 90)
new_writes = []
for i in range(min(len(orig), len(patched), len(actual))):
    if orig[i] == patched[i] and actual[i] != orig[i]:
        new_writes.append((i, orig[i], actual[i]))

print(f"  共 {len(new_writes)} 个字节被 ABL 新写入")
for off, o, a in new_writes[:50]:
    # find which block
    blk_off = (off // BLOCK) * BLOCK
    print(f"  0x{off:06X}  (block 0x{blk_off:06X})  orig=0x{o:02X} → readback=0x{a:02X}")
if len(new_writes) > 50:
    print(f"  ... 还有 {len(new_writes)-50} 个")

# 重点：找被恢复为original的字节（patched不同于original，但readback==original）
print("\n" + "=" * 90)
print("  被 ABL 恢复为 original 的字节 (patched!=original 但 readback==original)")
print("=" * 90)
reverted = []
for i in range(min(len(orig), len(patched), len(actual))):
    if patched[i] != orig[i] and actual[i] == orig[i]:
        reverted.append((i, orig[i], patched[i]))

print(f"  共 {len(reverted)} 个字节被恢复")
for off, o, p in reverted[:50]:
    blk_off = (off // BLOCK) * BLOCK
    print(f"  0x{off:06X}  (block 0x{blk_off:06X})  patched=0x{p:02X} → reverted to orig=0x{o:02X}")
if len(reverted) > 50:
    print(f"  ... 还有 {len(reverted)-50} 个")

# 重点：三方都不同的字节
print("\n" + "=" * 90)
print("  三方都不同的字节 (ABL 写了新值，既不是orig也不是patched)")
print("=" * 90)
triple_diff = []
for i in range(min(len(orig), len(patched), len(actual))):
    if orig[i] != patched[i] and patched[i] != actual[i] and orig[i] != actual[i]:
        triple_diff.append((i, orig[i], patched[i], actual[i]))

print(f"  共 {len(triple_diff)} 个字节")
for off, o, p, a in triple_diff[:50]:
    blk_off = (off // BLOCK) * BLOCK
    print(f"  0x{off:06X}  (block 0x{blk_off:06X})  orig=0x{o:02X}  patched=0x{p:02X}  readback=0x{a:02X}")
if len(triple_diff) > 50:
    print(f"  ... 还有 {len(triple_diff)-50} 个")

# 特别关注：SID 13 (0x0D) 区域 — OemCheckResetDevInfo 写入 SID=13, offset=0x30
print("\n" + "=" * 90)
print("  特别关注: 可能的 unlock 状态在 param 中的位置")
print("=" * 90)
# Scan all blocks for SID
for i in range(0, min(len(actual), 0x50000), BLOCK):
    blk = actual[i:i+BLOCK]
    if len(blk) >= 24:
        sid = struct.unpack_from('<I', blk, 16)[0]
        if sid == 13 or sid == 0x0D:
            print(f"\n  Block at 0x{i:06X}: SID={sid}")
            print(f"    Header: {blk[:32].hex()}")
            print(f"    Data[0x20:0x40]: {blk[0x20:0x40].hex()}")
            print(f"    Data[0x30:0x40]: {blk[0x30:0x40].hex()}")
            # Compare same block in all 3
            ob = orig[i:i+BLOCK]
            pb = patched[i:i+BLOCK]
            print(f"    orig    [0x30:0x40]: {ob[0x30:0x40].hex()}")
            print(f"    patched [0x30:0x40]: {pb[0x30:0x40].hex()}")
            print(f"    readback[0x30:0x40]: {blk[0x30:0x40].hex()}")

# Also check for blocks where header has name containing unlock-related
print("\n  Scanning for unlock/devinfo related block names...")
for i in range(0, min(len(actual), 0x50000), BLOCK):
    blk = actual[i:i+BLOCK]
    try:
        end = blk.index(0)
        name = blk[:end].decode('ascii', errors='replace').lower()
        if any(k in name for k in ['unlock', 'lock', 'dev', 'misc', 'config']):
            sid = struct.unpack_from('<I', blk, 16)[0] if len(blk) >= 20 else -1
            print(f"  0x{i:06X}: name='{blk[:end].decode()}', SID={sid}")
            # show first 64 bytes of data
            print(f"    orig data:     {orig[i+24:i+56].hex()}")
            print(f"    patched data:  {patched[i+24:i+56].hex()}")
            print(f"    readback data: {actual[i+24:i+56].hex()}")
    except (ValueError, UnicodeDecodeError):
        pass
