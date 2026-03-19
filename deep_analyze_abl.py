#!/usr/bin/env python3
"""
深入分析解压后的 ABL，追踪以下路径：
1. ReadDevInfo / WriteDevInfo 函数上下文
2. RPMB 读写上下文
3. FRP 分区读写上下文
4. AllowUnlock / get_unlock_ability 调用链
5. devinfo 完整性校验
"""

DECOMP = "edl_backup/abl_decompressed_lzma_0x3078.bin"

with open(DECOMP, 'rb') as f:
    data = f.read()

def show_context(offset, before=200, after=300, label=""):
    start = max(0, offset - before)
    end = min(len(data), offset + after)
    chunk = data[start:end]
    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
    print(f"\n{'='*70}")
    print(f"[+{hex(offset)}] {label}")
    print(f"{'='*70}")
    print(printable)

def find_all(needle, after_offset=0):
    results = []
    idx = after_offset
    while True:
        pos = data.find(needle, idx)
        if pos < 0:
            break
        results.append(pos)
        idx = pos + 1
    return results


# ── 1. ANDROID-BOOT! ───────────────────────────────────────────────────────
print("\n\n[1] ANDROID-BOOT! magic 上下文 => 这是 devinfo 头部校验入口")
for pos in find_all(b'ANDROID-BOOT!'):
    show_context(pos, before=80, after=200, label=f"ANDROID-BOOT! @{hex(pos)}")

# ── 2. WriteDevInfo / ReadDevInfo 相关 ─────────────────────────────────────
print("\n\n[2] DevInfo 读写函数名")
for needle in [b'ReadDevInfo', b'WriteDevInfo', b'GetDevInfo', b'SetDevInfo',
               b'set_devinfo', b'reset_devinfo', b'OemCheckResetDevInfo']:
    for pos in find_all(needle):
        show_context(pos, before=60, after=150, label=f"'{needle.decode()}' @{hex(pos)}")

# ── 3. RPMB 上下文 ─────────────────────────────────────────────────────────
print("\n\n[3] RPMB 操作上下文")
for needle in [b'RPMB', b'rpmb']:
    for pos in find_all(needle):
        show_context(pos, before=80, after=200, label=f"RPMB @{hex(pos)}")

# ── 4. FRP 分区操作 ────────────────────────────────────────────────────────
print("\n\n[4] FRP 分区操作上下文")
for needle in [b'FRP', b'frp', b'Error Reading FRP']:
    for pos in find_all(needle):
        show_context(pos, before=80, after=200, label=f"FRP @{hex(pos)}")

# ── 5. AllowUnlock 判断逻辑 ────────────────────────────────────────────────
print("\n\n[5] AllowUnlock / get_unlock_ability 判断逻辑")
for needle in [b'AllowUnlock', b'allowUnlock', b'allow_unlock',
               b'get_unlock_ability', b'get_unlock_code',
               b'unlock_ability', b'IsDeviceUnlocked']:
    for pos in find_all(needle):
        show_context(pos, before=80, after=300, label=f"'{needle.decode()}' @{hex(pos)}")

# ── 6. THW / Token 锁定字符串上下文 ───────────────────────────────────────
print("\n\n[6] T-Mobile 运营商锁 (THW) 上下文")
for pos in find_all(b'THW'):
    show_context(pos, before=120, after=300, label=f"THW @{hex(pos)}")

# ── 7. CRC / hash devinfo 完整性 ──────────────────────────────────────────
print("\n\n[7] devinfo 完整性相关 (magic, crc, hash)")
for needle in [b'invalid devinfo', b'devinfo_magic', b'devinfo_crc',
               b'devinfo corrupt', b'Bad devinfo', b'devinfo check',
               b'Unable to Write Device Info', b'Unable to Read Device Info']:
    for pos in find_all(needle):
        show_context(pos, before=80, after=200, label=f"'{needle.decode()}' @{hex(pos)}")

# ── 8. SPI / NV 非分区存储 ────────────────────────────────────────────────
print("\n\n[8] SPI/NV/非分区存储迹象")
for needle in [b'Store SPI', b'SPI to RPMB', b'RPMB success', b'sw prj id',
               b'software ID from', b'software_id', b'swprjid']:
    for pos in find_all(needle):
        show_context(pos, before=80, after=200, label=f"'{needle.decode()}' @{hex(pos)}")

print("\n\n[分析完成]")
