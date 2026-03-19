#!/usr/bin/env python3
"""
Check logfs and other UEFI NV storage partitions for devinfo data.
Also search for "devinfo" string (both ASCII and UCS-2) in all small partitions.
"""
import os, struct

base = '/Users/xmxx/pinganhuijia/edl_backup'
magic = b'ANDROID-BOOT!'
devinfo_ascii = b'devinfo'
devinfo_ucs2 = 'devinfo'.encode('utf-16-le')

# 1. Check logfs partition (Qualcomm UEFI NV variable store)
logfs = os.path.join(base, 'lun4/logfs.bin')
if os.path.isfile(logfs):
    sz = os.path.getsize(logfs)
    print(f"=== logfs.bin ({sz} bytes) ===")
    with open(logfs, 'rb') as f:
        data = f.read()

    # Search for ANDROID-BOOT! magic
    idx = data.find(magic)
    if idx >= 0:
        print(f"  FOUND magic at offset 0x{idx:X}!")
        d = data[idx:idx+0x20]
        print(f"  hex: {d.hex()}")
        print(f"  is_unlocked={data[idx+0xD]:02X} charger={data[idx+0xF]:02X}")
    else:
        print(f"  No ANDROID-BOOT! magic found")

    # Search for "devinfo" ASCII
    idx = data.find(devinfo_ascii)
    if idx >= 0:
        print(f"  Found 'devinfo' ASCII at offset 0x{idx:X}")
        ctx = data[max(0,idx-16):idx+32]
        print(f"  context: {ctx.hex()}")

    # Search for "devinfo" UCS-2
    idx = data.find(devinfo_ucs2)
    if idx >= 0:
        print(f"  Found 'devinfo' UCS-2 at offset 0x{idx:X}")
        ctx = data[max(0,idx-16):idx+32]
        print(f"  context: {ctx.hex()}")

    # Dump first 256 bytes
    print(f"\n  First 256 bytes of logfs:")
    for i in range(0, min(256, len(data)), 16):
        hx = ' '.join(f'{data[i+j]:02X}' for j in range(min(16, len(data)-i)))
        asc = ''.join(chr(data[i+j]) if 32 <= data[i+j] < 127 else '.' for j in range(min(16, len(data)-i)))
        print(f"    {i:04X}: {hx:<48s}  {asc}")

    # Check if it looks like UEFI FV (firmware volume)
    fv_sig = data.find(b'_FVH')
    if fv_sig >= 0:
        print(f"\n  Found FV header signature at 0x{fv_sig:X}")

    # Check for EFI variable headers (signature 0x55AA)
    for off in range(0, min(len(data), 0x100000), 2):
        if data[off:off+2] == b'\xAA\x55':
            # Might be a variable header, check context
            if off < 100:
                continue
            ctx = data[off-4:off+32]
            # Look for recognizable strings nearby
            nearby = data[max(0,off-64):off+128]
            if devinfo_ascii in nearby or devinfo_ucs2 in nearby:
                print(f"  Found 0xAA55 near 'devinfo' at offset 0x{off:X}")
                print(f"  context: {ctx.hex()}")
else:
    print("logfs.bin not found")

# 2. Also check other potential NV storage partitions
for part in ['lun4/logdump.bin', 'lun4/limits.bin', 'lun4/apdp.bin',
             'lun4/reserve1.bin', 'lun4/dip.bin']:
    fp = os.path.join(base, part)
    if not os.path.isfile(fp):
        continue
    sz = os.path.getsize(fp)
    if sz > 2 * 1024 * 1024:
        continue
    with open(fp, 'rb') as f:
        data = f.read()
    found_any = False
    idx = data.find(magic)
    if idx >= 0:
        print(f"\n{part}: FOUND magic at 0x{idx:X}")
        found_any = True
    idx = data.find(devinfo_ucs2)
    if idx >= 0:
        print(f"\n{part}: Found 'devinfo' UCS-2 at 0x{idx:X}")
        ctx = data[max(0,idx-16):idx+64]
        print(f"  context: {ctx.hex()}")
        found_any = True
    if not found_any and sz < 100000:
        # Also dump first 64 bytes of small partitions
        nz = next((i for i in range(len(data)) if data[i] != 0), None)
        if nz is not None:
            print(f"\n{part} ({sz}): first non-zero at 0x{nz:X}")
            d = data[nz:nz+64]
            hx = ' '.join(f'{b:02X}' for b in d)
            print(f"  {hx}")

# 3. Also search the GPT tables for partition entries with "devinfo" name
for lun in range(6):
    gpt_path = os.path.join(base, f'lun{lun}/gpt_main{lun}.bin')
    if not os.path.isfile(gpt_path):
        continue
    with open(gpt_path, 'rb') as f:
        gpt = f.read()
    idx = 0
    while True:
        idx = gpt.find(devinfo_ucs2, idx)
        if idx < 0:
            break
        print(f"\nFound 'devinfo' in GPT of LUN{lun} at offset 0x{idx:X}")
        # GPT entry is 128 bytes, name starts at offset 56 within entry
        entry_start = idx - 56
        if entry_start >= 0 and entry_start + 128 <= len(gpt):
            entry = gpt[entry_start:entry_start+128]
            type_guid = entry[0:16]
            unique_guid = entry[16:32]
            first_lba = struct.unpack('<Q', entry[32:40])[0]
            last_lba = struct.unpack('<Q', entry[40:48])[0]
            attrs = struct.unpack('<Q', entry[48:56])[0]
            name = entry[56:128].decode('utf-16-le', errors='replace').split('\x00')[0]

            a, b, c = struct.unpack('<IHH', type_guid[:8])
            d = type_guid[8:16]
            type_str = f"{a:08X}-{b:04X}-{c:04X}-{d[:2].hex().upper()}-{d[2:].hex().upper()}"

            a, b, c = struct.unpack('<IHH', unique_guid[:8])
            d = unique_guid[8:16]
            uniq_str = f"{a:08X}-{b:04X}-{c:04X}-{d[:2].hex().upper()}-{d[2:].hex().upper()}"

            print(f"  Name: {name}")
            print(f"  Type GUID: {type_str}")
            print(f"  Unique GUID: {uniq_str}")
            print(f"  First LBA: {first_lba} (0x{first_lba:X})")
            print(f"  Last LBA: {last_lba} (0x{last_lba:X})")
            print(f"  Attrs: 0x{attrs:016X}")
            print(f"  Size: {(last_lba - first_lba + 1)} sectors")
        idx += 1

print("\nDone.")
