#!/usr/bin/env python3
"""
精准分析两个关键路径：
1. IsAllowUnlock 的 FRP 读取逻辑（决定 flashing unlock 是否允许）
2. THW 附近 obfuscated strings（运营商锁字符串）
3. devinfo 的 ReadDevInfo 完整路径：是否读 RPMB / partition
4. 解码 THW 附近的 ROT/XOR obfuscated 命令字符串
"""

DECOMP = "edl_backup/abl_decompressed_lzma_0x3078.bin"

with open(DECOMP, 'rb') as f:
    data = f.read()

def show_hex_context(offset, before=128, after=256):
    start = max(0, offset - before)
    end = min(len(data), offset + after)
    chunk = data[start:end]
    # print hex + ascii
    for i in range(0, len(chunk), 16):
        row = chunk[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in row)
        asc_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
        print(f"  {start+i:08x}:  {hex_part:<48}  {asc_part}")

# ── A. 解码 THW 附近的 obfuscated strings ──────────────────────────────────
# 从分析结果看 @0x638d1 起，有诸如 jqtxsth%xut 这样的编码字符串
# 这是 ROT-5 或 XOR 编码的 fastboot 命令。尝试不同解码方式。

print("=" * 70)
print("A. THW 附近 obfuscated fastboot 命令解码")
print("=" * 70)

obf_region = data[0x63880:0x63a00]
printable = ''.join(chr(b) if 32 <= b < 127 else ' ' for b in obf_region)
print("原始可打印段:")
print(printable[:800])
print()

# 尝试 ROT-5 (对字母 -5)
def rot_decode(s, n=5):
    result = []
    for c in s:
        if 33 <= ord(c) <= 126:
            result.append(chr((ord(c) - 33 - n) % 94 + 33))
        else:
            result.append(c)
    return ''.join(result)

# 提取 obfuscated 片段 (以 %xut 结尾的格式字符串)
import re
tokens = re.findall(r'[a-zA-Z0-9|~{}/\\]+%xut', printable)
print(f"找到 {len(tokens)} 个可能的 obfuscated 字符串")
for tok in tokens[:30]:
    tok_clean = tok.replace('%xut', '')
    for shift in range(1, 10):
        decoded = rot_decode(tok_clean, shift)
        print(f"  shift={shift}: {tok_clean!r} => {decoded!r}")
    print()

# ── B. IsAllowUnlock 完整上下文 ────────────────────────────────────────────
print("\n" + "=" * 70)
print("B. IsAllowUnlock 完整调用链 (FRP 读取) 十六进制上下文")
print("=" * 70)

idx = data.find(b'IsAllowUnlock is %d')
if idx >= 0:
    print(f"IsAllowUnlock log string @ {hex(idx)}")
    show_hex_context(idx - 0x80, before=0, after=400)

# ── C. devinfo 读取路径检查：magic 附近代码 ────────────────────────────────
print("\n" + "=" * 70)
print("C. ANDROID-BOOT! devinfo magic 周边（WriteDevInfo 错误处理）")
print("=" * 70)
idx = data.find(b'ANDROID-BOOT!')
if idx >= 0:
    show_hex_context(idx - 0x100, before=0, after=256)

# ── D. Unable to Read Device Info → 确认 devinfo 来源 ─────────────────────
print("\n" + "=" * 70)
print("D. Unable to Read Device Info → 确认读取来源是分区还是 RPMB")
print("=" * 70)
idx = data.find(b'Unable to Read Device Info')
if idx >= 0:
    print(f"  @ {hex(idx)}")
    show_hex_context(idx - 0x180, before=0, after=300)

# ── E. OemCheckResetDevInfo 参数上下文 ────────────────────────────────────
print("\n" + "=" * 70)
print("E. OemCheckResetDevInfo / reset_devinfo 详细上下文")
print("=" * 70)
idx = data.find(b'OemCheckResetDevInfo')
if idx >= 0:
    show_hex_context(idx - 0x100, before=0, after=300)

# ── F. 搜索 "set_param_by_index" — 这是 OnePlus 私有 NV 系统 ──────────────
print("\n" + "=" * 70)
print("F. OnePlus param / NV 系统上下文")
print("=" * 70)
for needle in [b'set_param_by_index', b'get_param_by_index', b'param_part',
               b'param_ops', b'read_param', b'write_param', b'NV_',
               b'op_nv', b'OP_NV', b'GetParam', b'SetParam']:
    idx = data.find(needle)
    if idx >= 0:
        ctx = data[max(0,idx-50):idx+len(needle)+100]
        p = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
        print(f"  '{needle.decode()}' @{hex(idx)}: {p!r}")

print("\n[完成]")
