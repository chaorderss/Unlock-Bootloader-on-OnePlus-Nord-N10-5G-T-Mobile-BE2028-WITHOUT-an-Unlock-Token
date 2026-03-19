#!/usr/bin/env python3
"""Deep investigation: search ALL backed-up partitions for devinfo-related data.
Also examine logfs, config, and other Qualcomm-specific storage."""

import struct
import os
import glob

BACKUP = "/Users/xmxx/pinganhuijia/edl_backup"

def search_file(filepath, needles):
    with open(filepath, 'rb') as f:
        data = f.read()
    results = {}
    for name, needle in needles:
        offsets = []
        pos = 0
        while True:
            idx = data.find(needle, pos)
            if idx < 0:
                break
            offsets.append(idx)
            pos = idx + 1
        if offsets:
            results[name] = (offsets, data)
    return results

def hexdump(data, start=0, length=256):
    for i in range(0, min(length, len(data)-start), 16):
        off = start + i
        h = ' '.join(f'{data[off+j]:02X}' for j in range(min(16, len(data)-off)))
        a = ''.join(chr(data[off+j]) if 32<=data[off+j]<127 else '.' for j in range(min(16, len(data)-off)))
        print(f"  {off:04X}: {h:<48s} {a}")

def main():
    needles = [
        ("ANDROID-BOOT!", b'ANDROID-BOOT!'),
        ("devinfo-ascii", b'devinfo'),
        ("devinfo-ucs2", "devinfo".encode('utf-16-le')),
        ("DeviceInfo-ucs2", "DeviceInfo".encode('utf-16-le')),
        ("protocol-guid", bytes([0x91, 0xFF, 0x5E, 0x8E, 0xB6, 0x21, 0xD3, 0x47,
                                 0xAF, 0x2B, 0xC1, 0x5A, 0x01, 0xE0, 0x20, 0xEC])),
        ("devinfo-type-guid", bytes([0xF4, 0xDC, 0xAD, 0x65, 0x5C, 0x0C, 0x9A, 0x4D,
                                     0xAC, 0x2D, 0xD9, 0x0B, 0x5C, 0xBF, 0xCD, 0x03])),
    ]

    print("=== Searching ALL backup partitions (skipping >200MB) ===")
    for lun_dir in sorted(glob.glob(os.path.join(BACKUP, "lun*"))):
        for f in sorted(glob.glob(os.path.join(lun_dir, "*.bin"))):
            fname = os.path.relpath(f, BACKUP)
            fsize = os.path.getsize(f)
            if fsize > 200_000_000:
                continue
            results = search_file(f, needles)
            if results:
                print(f"\n  {fname} ({fsize} bytes):")
                for name, (offsets, data) in results.items():
                    for off in offsets[:5]:
                        ctx = data[max(0,off-8):off+48]
                        ascii_ctx = ''.join(chr(b) if 32<=b<127 else '.' for b in ctx)
                        print(f"    {name} @ 0x{off:X}: {ctx.hex()}")
                        print(f"      ASCII: {ascii_ctx}")

    # logfs deep analysis
    logfs_path = os.path.join(BACKUP, "lun4/logfs.bin")
    if os.path.exists(logfs_path):
        print(f"\n=== logfs.bin ===")
        with open(logfs_path, 'rb') as f:
            data = f.read()
        nz = sum(1 for b in data if b not in (0, 0xFF))
        last_nz = 0
        for i in range(len(data)-1, -1, -1):
            if data[i] not in (0, 0xFF):
                last_nz = i
                break
        print(f"Size: {len(data)}, Non-zero/non-FF: {nz}, Last data: 0x{last_nz:X}")
        hexdump(data, 0, 256)

    # config.bin
    config_path = os.path.join(BACKUP, "lun0/config.bin")
    if os.path.exists(config_path):
        print(f"\n=== config.bin ===")
        with open(config_path, 'rb') as f:
            data = f.read()
        nz = sum(1 for b in data if b != 0)
        print(f"Size: {len(data)}, Non-zero: {nz}")
        if nz > 0:
            first_nz = next(i for i in range(len(data)) if data[i] != 0)
            hexdump(data, max(0, first_nz-16), 512)

    # secdata
    secdata_path = os.path.join(BACKUP, "lun4/secdata.bin")
    if os.path.exists(secdata_path):
        print(f"\n=== secdata.bin ===")
        with open(secdata_path, 'rb') as f:
            data = f.read()
        nz = sum(1 for b in data if b != 0)
        print(f"Size: {len(data)}, Non-zero: {nz}")
        hexdump(data, 0, 256)

    # dip
    dip_path = os.path.join(BACKUP, "lun4/dip.bin")
    if os.path.exists(dip_path):
        print(f"\n=== dip.bin ===")
        with open(dip_path, 'rb') as f:
            data = f.read()
        nz = sum(1 for b in data if b not in (0, 0xFF))
        print(f"Size: {len(data)}, Non-zero/non-FF: {nz}")
        hexdump(data, 0, 256)

    # misc
    misc_path = os.path.join(BACKUP, "lun0/misc.bin")
    if os.path.exists(misc_path):
        print(f"\n=== misc.bin ===")
        with open(misc_path, 'rb') as f:
            data = f.read()
        nz = sum(1 for b in data[:4096] if b != 0)
        print(f"Size: {len(data)}, First 4K non-zero: {nz}")
        hexdump(data, 0, 256)

    # ssd
    ssd_path = os.path.join(BACKUP, "lun0/ssd.bin")
    if os.path.exists(ssd_path):
        print(f"\n=== ssd.bin ===")
        with open(ssd_path, 'rb') as f:
            data = f.read()
        nz = sum(1 for b in data if b != 0)
        print(f"Size: {len(data)}, Non-zero: {nz}")
        if nz > 0:
            hexdump(data, 0, 256)

if __name__ == '__main__':
    main()
