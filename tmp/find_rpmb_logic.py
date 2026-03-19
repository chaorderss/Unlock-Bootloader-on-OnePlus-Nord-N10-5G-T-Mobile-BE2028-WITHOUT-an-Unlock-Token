#!/usr/bin/env python3
"""Find all RPMB/SoftwareProjectID related strings and analyze ABL logic."""
import struct

with open('/tmp/abl_dec.bin', 'rb') as f:
    data = f.read()

strings_to_find = [
    b'sw_proj_id_proc',
    b'init_param_sw_prj_id',
    b'check and restore',
    b'backup software ID',
    b'Store SPI to RPMB',
    b'Clean backup proc',
    b'Software ID equals',
    b'GetParamSoftwareProjectID',
    b'GetParamSoftwareProjectIDProcState',
    b'Failed to store SPI',
    b'RPMB enalb',
    b'start backup',
    b'setswprojmodel',
    b'SetSwProjModel',
    b'Process:',
]

print("=== String locations ===")
for s in strings_to_find:
    idx = 0
    while True:
        pos = data.find(s, idx)
        if pos == -1:
            break
        end = data.find(b'\x00', pos)
        if end == -1:
            end = pos + 80
        strval = data[pos:end].decode('ascii', errors='replace')
        print(f"  0x{pos:06X}: {strval}")
        idx = pos + 1

# Now find the PE image base and code section
# The decompressed binary is a PE image
# Look for the MZ header
mz_pos = data.find(b'MZ')
print(f"\n=== MZ header at 0x{mz_pos:06X} ===" if mz_pos != -1 else "\nNo MZ header found")

# Also check for ARM64 instruction patterns around the key strings
# Let's look for references to the string addresses
# In UEFI DXE drivers on ARM64, strings are typically referenced via ADRP+ADD pairs

# First let's find what offset the code loads from for sw_proj_id_proc
# Let's look at GetParamSoftwareProjectIDProcState
proc_state_str = data.find(b'GetParamSoftwareProjectIDProcState')
print(f"\nGetParamSoftwareProjectIDProcState string at 0x{proc_state_str:06X}")

# Look for init_param_sw_prj_id strings - these tell us the function's behavior
# Let's find the format strings with line numbers
fmt_strings = [
    b'%a[%r] sw_proj_id_proc:',
    b'%a[%r] Process: check and restore',
    b'%a[%r] Process: start backup',
    b'%a[%r] Store SPI to RPMB',
    b'%a[%r] RPMB enalb',
    b'%a[%r] Software ID equals',
    b'%a[%r] Failed to store SPI',
]

print("\n=== Format strings ===")
for s in fmt_strings:
    pos = data.find(s)
    if pos != -1:
        end = data.find(b'\x00', pos)
        strval = data[pos:end].decode('ascii', errors='replace')
        print(f"  0x{pos:06X}: {strval}")

# Look for RPMB related function names
print("\n=== RPMB function/string search ===")
rpmb_strings = [b'RPMB', b'rpmb', b'Rpmb', b'StoreRpmb', b'ReadRpmb', b'WriteRpmb',
                 b'RpmbRead', b'RpmbWrite', b'gRpmb', b'RpmbStorageDxe',
                 b'OpRpmb', b'OplusRpmb', b'OemRpmb']
for s in rpmb_strings:
    idx = 0
    while True:
        pos = data.find(s, idx)
        if pos == -1:
            break
        # Get context
        start = max(0, pos - 4)
        end = min(len(data), data.find(b'\x00', pos) + 1 if data.find(b'\x00', pos) != -1 else pos + 60)
        strval = data[pos:end].decode('ascii', errors='replace')
        print(f"  0x{pos:06X}: {strval[:80]}")
        idx = pos + 1

# Search for GUID patterns that might be RPMB protocol GUIDs
# Try to find "OplusRpmbProtocol" or similar
print("\n=== Searching for protocol/GUID references ===")
for pattern in [b'Oplus', b'OPLUS', b'oplus', b'OnePlus', b'ONEPLUS']:
    idx = 0
    while True:
        pos = data.find(pattern, idx)
        if pos == -1:
            break
        end = data.find(b'\x00', pos)
        if end == -1 or end - pos > 100:
            end = pos + 60
        strval = data[pos:end].decode('ascii', errors='replace')
        if len(strval) > 3:
            print(f"  0x{pos:06X}: {strval[:80]}")
        idx = pos + 1

# Dump the hex around the sw_proj_id_proc format string to see the function layout
proc_fmt = data.find(b'sw_proj_id_proc')
if proc_fmt != -1:
    print(f"\n=== Hex context around sw_proj_id_proc string (0x{proc_fmt:06X}) ===")
    start = max(0, proc_fmt - 0x100)
    for off in range(start, min(len(data), proc_fmt + 0x300), 16):
        hexbytes = data[off:off+16].hex()
        ascii_repr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[off:off+16])
        print(f"  0x{off:06X}: {hexbytes}  {ascii_repr}")
