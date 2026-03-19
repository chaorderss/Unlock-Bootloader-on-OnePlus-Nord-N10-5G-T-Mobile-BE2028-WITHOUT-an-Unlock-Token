#!/usr/bin/env python3
"""
Check if VB protocol GUID exists in uefisecapp or other XBL modules.
This tells us which module provides the VBResetDeviceState function.
"""

import os
import struct

edl_base = '/Users/xmxx/pinganhuijia/edl_backup'

# VB protocol GUID: 8E5EFF91-21B6-47D3-AF2B-C15A01E020EC
guid_bytes = bytes.fromhex('91ff5e8eb621d347af2bc15a01e020ec')

# Check relevant firmware images
targets = [
    ('lun4', 'uefisecapp_a.bin'),
    ('lun1', 'xbl_a.bin'),
    ('lun1', 'xbl_config_a.bin'),
    ('lun4', 'imagefv_a.bin'),
    ('lun4', 'hyp_a.bin'),
    ('lun4', 'tz_a.bin'),
    ('lun4', 'storsec_a.bin'),
]

print(f"VB Protocol GUID: 8E5EFF91-21B6-47D3-AF2B-C15A01E020EC")
print(f"Binary: {guid_bytes.hex()}")

for lun, fname in targets:
    path = os.path.join(edl_base, lun, fname)
    if not os.path.exists(path):
        continue

    with open(path, 'rb') as f:
        data = f.read()

    size = len(data)
    idx = data.find(guid_bytes)

    if idx >= 0:
        print(f"\n  ✓ FOUND in {lun}/{fname} ({size} bytes) at offset 0x{idx:X}")
        # Find all occurrences
        count = 0
        pos = 0
        while True:
            pos = data.find(guid_bytes, pos)
            if pos == -1:
                break
            count += 1
            # Show context
            hex_ctx = data[max(0,pos-16):pos+32].hex()
            print(f"    [{count}] offset 0x{pos:X}: ...{hex_ctx}...")
            pos += 1

        # Also check for MZ header (PE)
        mz_idx = data.find(b'MZ')
        while mz_idx >= 0:
            # Check if valid PE
            if mz_idx + 64 <= len(data):
                pe_off = struct.unpack_from('<I', data, mz_idx + 0x3C)[0]
                if mz_idx + pe_off + 4 <= len(data):
                    sig = data[mz_idx+pe_off:mz_idx+pe_off+4]
                    if sig == b'PE\x00\x00':
                        print(f"    PE module at offset 0x{mz_idx:X}")
            mz_idx = data.find(b'MZ', mz_idx + 1)
            if mz_idx > 0x100000:  # Limit search
                break
    else:
        print(f"  ✗ Not in {lun}/{fname} ({size} bytes)")

# Also search for "ResetDeviceState" or "AllowUnlock" strings in these files
print("\n=== String search in firmware ===")
search_terms = [b'ResetDeviceState', b'AllowUnlock', b'oem_unlock', b'OemUnlock',
                b'IsAllow', b'device_state', b'DeviceState']
for lun, fname in targets:
    path = os.path.join(edl_base, lun, fname)
    if not os.path.exists(path):
        continue
    with open(path, 'rb') as f:
        data = f.read()

    found = []
    for term in search_terms:
        idx = data.find(term)
        if idx >= 0:
            # Get context string
            start = idx
            while start > 0 and data[start-1] != 0:
                start -= 1
            end = data.find(0, idx)
            if end < 0:
                end = idx + len(term)
            try:
                s = data[start:end].decode('ascii', errors='replace')
                found.append((idx, s))
            except:
                found.append((idx, term.decode()))

    if found:
        print(f"\n  {lun}/{fname}:")
        for idx, s in found[:20]:
            print(f"    0x{idx:X}: '{s}'")
