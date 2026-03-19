#!/usr/bin/env python3
"""
创建最终的完整 param patch：
1. intranet=3 in ENC_SECRECY (SID 0x12C) — 启用 OPS 工厂模式，绕过 T-Mobile THW 限制
2. intranet_3t=1 in DOWNLOAD (SID 0xC, offset 0x1A4) — 兼容老款设备
3. reset_devinfo=0 in DOWNLOAD (SID 0xC, offset 0x1A0) — 防止 ABL 重置 devinfo
4. Unlock_Count=1 in PHONE_HISTORY (SID 0xD, offset 0x28) — 与 devinfo is_unlocked=1 保持一致

用法：
  python3 make_final_param_patch.py
输出：
  edl_backup/param_final.bin  — 可直接 EDL flash 的 param 镜像
"""
import sys
sys.path.insert(0, '/Library/Frameworks/Python.framework/Versions/3.14/lib/python3.14/site-packages')

from edlclient.Library.Modules.oneplus_param import paramtools

PARAM_ORIG  = '/Users/xmxx/pinganhuijia/edl_backup/param.bin'          # 原始备份
PARAM_OUT   = '/Users/xmxx/pinganhuijia/edl_backup/param_final.bin'    # 最终输出

print("Reading original param.bin...")
with open(PARAM_ORIG, 'rb') as f:
    data = bytearray(f.read())

# Use default key (mode=0) — proven correct for this device
param = paramtools(0, 0)

print("\n[1] Setting ENC_SECRECY.intranet = 0x3 (SID 0x12C, offset 0x80)")
data = bytearray(param.setparamvalue(bytes(data), 0x12C, 0x80, 0x3))
print("    Done.")

print("[2] Setting DOWNLOAD.intranet_3t = 0x1 (SID 0xC, offset 0x1A4)")
data = bytearray(param.setparamvalue(bytes(data), 0xC, 0x1A4, 0x1))
print("    Done.")

print("[3] Setting DOWNLOAD.reset_devinfo = 0x0 (SID 0xC, offset 0x1A0) — prevent ABL from resetting devinfo")
data = bytearray(param.setparamvalue(bytes(data), 0xC, 0x1A0, 0x0))
print("    Done.")

print("[4] Setting PHONE_HISTORY.Unlock_Count = 0x1 (SID 0xD, offset 0x28)")
data = bytearray(param.setparamvalue(bytes(data), 0xD, 0x28, 0x1))
print("    Done.")

# Write output
with open(PARAM_OUT, 'wb') as f:
    f.write(data)
print(f"\nWritten: {PARAM_OUT}")

# Verify
print("\n=== Verification ===")
with open(PARAM_OUT, 'rb') as f:
    verify = f.read()
pv = paramtools(0, 0)

print("\n-- Encrypted fields --")
pv.parse_encrypted_fields(verify)

print("\n-- Plaintext changes --")
# SID 0xD at 0x3400
import struct
sid_d = verify[0x3400:0x3800]
unlock_count = struct.unpack_from('<I', sid_d, 0x28)[0]
reset_devinfo = struct.unpack_from('<I', verify, 0x3000 + 0x1A0)[0]
intranet_3t   = struct.unpack_from('<I', verify, 0x3000 + 0x1A4)[0]
print(f"  PHONE_HISTORY.Unlock_Count  (0x3428): {unlock_count:#x}")
print(f"  DOWNLOAD.reset_devinfo      (0x41A0): {reset_devinfo:#x}")
print(f"  DOWNLOAD.intranet_3t        (0x41A4): {intranet_3t:#x}")
