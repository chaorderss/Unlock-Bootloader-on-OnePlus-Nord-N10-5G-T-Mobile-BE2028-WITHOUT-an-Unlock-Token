#!/usr/bin/env python3
"""
创建仅修改 reset_devinfo=0 的最小化 param 补丁
不修改 intranet 或 Unlock_Count，减少副作用
"""
import sys
sys.path.insert(0, '/Library/Frameworks/Python.framework/Versions/3.14/lib/python3.14/site-packages')
from edlclient.Library.Modules.oneplus_param import paramtools

PARAM_IN  = '/Users/xmxx/pinganhuijia/edl_backup/param.bin'
PARAM_OUT = '/Users/xmxx/pinganhuijia/tmp/param_reset_devinfo_0.bin'

with open(PARAM_IN, 'rb') as f:
    data = f.read()

p = paramtools(0, 0)

# 仅修改 reset_devinfo = 0
# SID 0xC (DOWNLOAD segment), offset 0x1A0
data = p.setparamvalue(data, 0xC, 0x1A0, 0)
print("✓ reset_devinfo (SID 0xC, off 0x1A0) set to 0")

with open(PARAM_OUT, 'wb') as f:
    f.write(data)
print(f"✓ Written: {PARAM_OUT}")
print(f"  Size: {len(data)} bytes")

# 验证
with open(PARAM_OUT, 'rb') as f:
    v = f.read()
v_orig = open(PARAM_IN, 'rb').read()

diff_count = sum(1 for a, b in zip(v, v_orig) if a != b)
print(f"\n  与原始 param.bin 差异字节: {diff_count}")

# 显示差异位置
for i in range(len(v)):
    if v[i] != v_orig[i]:
        print(f"  0x{i:06X}: 0x{v_orig[i]:02X} → 0x{v[i]:02X}")
