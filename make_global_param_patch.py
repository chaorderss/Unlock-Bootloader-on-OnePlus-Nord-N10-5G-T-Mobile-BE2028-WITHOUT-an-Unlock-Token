import sys
sys.path.insert(0, '/Library/Frameworks/Python.framework/Versions/3.14/lib/python3.14/site-packages')
from edlclient.Library.Modules.oneplus_param import paramtools

PARAM_IN  = '/Users/xmxx/pinganhuijia/edl_backup/param.bin'
PARAM_OUT = '/Users/xmxx/pinganhuijia/edl_backup/param_global_patched.bin'

with open(PARAM_IN, 'rb') as f:
    data = f.read()

p = paramtools(0, 0)  # mode=0: default key

# SID 0x12C (ENC_SECRECY) offset 0x80: intranet = 3 (OPS 工厂模式)
data = p.setparamvalue(data, 0x12C, 0x80, 3)
print("intranet (SID 0x12C, off 0x80) set to 3")

# SID 0xC (DOWNLOAD) offset 0x1A0: reset_devinfo = 0 (禁止启动时重置)
data = p.setparamvalue(data, 0xC, 0x1A0, 0)
print("reset_devinfo (SID 0xC, off 0x1A0) set to 0")

# SID 0xD (PHONE_HISTORY) offset 0x28: Unlock_Count = 1
data = p.setparamvalue(data, 0xD, 0x28, 1)
print("Unlock_Count (SID 0xD, off 0x28) set to 1")

with open(PARAM_OUT, 'wb') as f:
    f.write(data)
print(f"Written: {PARAM_OUT}")

with open(PARAM_OUT, 'rb') as f:
    v = f.read()
p2 = paramtools(0, 0)
print("\n=== Verify patched ===")
p2.parse_encrypted_fields(v)
