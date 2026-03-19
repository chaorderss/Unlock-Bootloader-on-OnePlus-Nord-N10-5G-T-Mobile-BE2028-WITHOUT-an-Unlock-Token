#!/usr/bin/env python3
"""
Check FRP partition in EDL backup, analyze its structure,
and determine how to enable OEM unlock via FRP.
"""
import os
import struct

edl_base = '/Users/xmxx/pinganhuijia/edl_backup'

# 1. Find FRP partition
print("=== Looking for FRP partition ===")
for lun in range(6):
    lun_dir = os.path.join(edl_base, f'lun{lun}')
    if not os.path.exists(lun_dir):
        continue
    for f in sorted(os.listdir(lun_dir)):
        fl = f.lower()
        if 'frp' in fl or 'persistentdata' in fl or 'pdb' in fl:
            path = os.path.join(lun_dir, f)
            size = os.path.getsize(path)
            print(f"  FOUND: {path} ({size} bytes)")
            with open(path, 'rb') as fh:
                data = fh.read()
            # Analyze
            print(f"  First 64 bytes: {data[:64].hex()}")
            print(f"  Last 16 bytes: {data[-16:].hex()}")

            # The PDB format (Android PersistentDataBlock):
            # [0:4] magic = 0x10101010
            # [4:8] datablock_size
            # [8:8+datablock_size] data
            # [last byte] OEM unlock enabled flag

            # Check magic
            if len(data) >= 4:
                magic = struct.unpack_from('<I', data, 0)[0]
                print(f"  Magic: 0x{magic:08X}")
                if magic == 0x10101010:
                    print("  ✓ PersistentDataBlock magic!")
                    if len(data) >= 8:
                        block_size = struct.unpack_from('<I', data, 4)[0]
                        print(f"  Data block size: {block_size}")

            # Check last byte (OEM unlock flag)
            if len(data) > 0:
                last_byte = data[-1]
                print(f"  Last byte: 0x{last_byte:02X}")
                print(f"  OEM Unlock enabled: {bool(last_byte & 1)}")

            # Non-zero regions
            print(f"  Non-zero regions:")
            for off in range(0, len(data), 16):
                chunk = data[off:off+16]
                if any(b != 0 for b in chunk):
                    hex_str = chunk.hex()
                    ascii_str = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk)
                    print(f"    0x{off:04X}: {hex_str}  {ascii_str}")

# 2. Also list ALL partitions across all LUNs for completeness
print("\n=== Full partition list (all LUNs) ===")
for lun in range(6):
    lun_dir = os.path.join(edl_base, f'lun{lun}')
    if not os.path.exists(lun_dir):
        continue
    files = sorted(os.listdir(lun_dir))
    print(f"\n  lun{lun}: {len(files)} files")
    for f in files:
        path = os.path.join(lun_dir, f)
        size = os.path.getsize(path)
        note = ''
        if 'frp' in f.lower():
            note = ' *** FRP ***'
        elif 'param' in f.lower():
            note = ' *** PARAM ***'
        elif 'config' in f.lower():
            note = ' *** CONFIG ***'
        elif 'devinfo' in f.lower():
            note = ' *** DEVINFO ***'
        print(f"    {f}: {size:>10} bytes{note}")
