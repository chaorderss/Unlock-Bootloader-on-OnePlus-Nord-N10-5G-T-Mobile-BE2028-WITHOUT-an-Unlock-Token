
#!/usr/bin/env python3
"""
解码 ABL 里的 obfuscated fastboot 命令字符串 (ROT cipher)。
示例：jqtxsth%xut => shift=5 => elosnoc (反向=console)
"""

DECOMP = "edl_backup/abl_decompressed_lzma_0x3078.bin"

with open(DECOMP, 'rb') as f:
    data = f.read()

import re

# THW 前后的原始 obfuscated 区域
region = data[0x63880:0x63a00]
text = ''.join(chr(b) if 32 <= b < 127 else '\x00' for b in region)

# 提取 %xut 格式的 obfuscated 命令 (不含数字前缀)
tokens = re.findall(r'([!-~]+?)%xut', text)

print("=== ROT 解码所有 THW obfuscated 字符串 ===\n")

def rot_decode(s, n):
    result = []
    for c in s:
        o = ord(c)
        if 33 <= o <= 126:
            result.append(chr((o - 33 - n) % 94 + 33))
        else:
            result.append(c)
    return ''.join(result)

# shift=5 是最常见的中国厂商 ABL obfuscation
for tok in tokens:
    for shift in [5, 1, 3, 7]:
        decoded = rot_decode(tok, shift)
        # 检查解码结果是否全是可打印字母
        if all(c.isalnum() or c in '-_.' for c in decoded):
            print(f"  shift={shift}: {tok!r:40s} => {decoded!r}")
            break
    else:
        # fallback: 打印 shift=5
        d5 = rot_decode(tok, 5)
        print(f"  shift=5: {tok!r:40s} => {d5!r}  [mixed]")

# 二次确认: 提取 %pfjqrjrp%xut 形式 (两段式)
print("\n\n=== 命令:子命令 两段式 obfuscated ===\n")
two_part = re.findall(r'([!-~]+?)%pfj([!-~]+?)%xut', text)
for a, b in two_part:
    da = rot_decode(a, 5)
    db = rot_decode(b, 5)
    print(f"  {a!r} {b!r}  =>  {da!r} {db!r}")

# 解码 65K:IYXK<WYK=6WY5955:K9 风格（非字母 ROT）
print("\n\n=== 数字/符号混合 obfuscated ===\n")
mixed = re.findall(r'([0-9A-Z:<>=]{8,})%xut', text)
for m in mixed[:20]:
    for shift in range(1, 20):
        decoded = rot_decode(m, shift)
        if decoded.replace('-', '').replace('_', '').replace('.', '').isalnum():
            print(f"  shift={shift}: {m!r:45s} => {decoded!r}")
            break
    else:
        print(f"  ????:  {m!r}")
