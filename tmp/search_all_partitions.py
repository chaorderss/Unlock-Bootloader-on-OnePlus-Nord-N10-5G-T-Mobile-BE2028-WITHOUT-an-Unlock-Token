#!/usr/bin/env python3
"""
Search ALL backed-up partitions across ALL LUNs for "ANDROID-BOOT!" magic.
Also search for devinfo-like structures and related GUIDs.
"""
import os
import struct

BACKUP_DIR = '/Users/xmxx/pinganhuijia/edl_backup'
MAGIC = b'ANDROID-BOOT!'
PROTO_GUID = bytes.fromhex('91ff5e8eb621d347af2bc15a01e020ec')  # 8E5EFF91-21B6-47D3

print("=" * 70)
print("Search ALL backup partitions for ANDROID-BOOT! magic")
print("=" * 70)

found_magic = []
found_guid = []

for lun_dir in sorted(os.listdir(BACKUP_DIR)):
    lun_path = os.path.join(BACKUP_DIR, lun_dir)
    if not os.path.isdir(lun_path):
        # Also check top-level files
        if lun_dir.endswith('.bin'):
            fpath = os.path.join(BACKUP_DIR, lun_dir)
            data = open(fpath, 'rb').read()
            idx = data.find(MAGIC)
            if idx >= 0:
                found_magic.append((lun_dir, fpath, idx, len(data)))
                print(f"  ★ MAGIC in {lun_dir} at offset 0x{idx:X}")
            idx = data.find(PROTO_GUID)
            if idx >= 0:
                found_guid.append((lun_dir, fpath, idx))
                print(f"  ★ PROTO GUID in {lun_dir} at offset 0x{idx:X}")
        continue

    for fname in sorted(os.listdir(lun_path)):
        if not fname.endswith('.bin'):
            continue
        fpath = os.path.join(lun_path, fname)
        try:
            data = open(fpath, 'rb').read()
        except:
            continue

        # Search for magic
        offset = 0
        while True:
            idx = data.find(MAGIC, offset)
            if idx < 0:
                break
            found_magic.append((f"{lun_dir}/{fname}", fpath, idx, len(data)))
            print(f"  ★ MAGIC in {lun_dir}/{fname} at offset 0x{idx:X} (file size: {len(data)})")
            # Show context
            start = max(0, idx - 4)
            end = min(len(data), idx + 32)
            context = data[start:end]
            print(f"    Context: {context.hex()}")
            print(f"    is_unlocked [+0x0D]: 0x{data[idx+0x0D]:02X}" if idx + 0x0D < len(data) else "")
            print(f"    charger_scr [+0x0F]: 0x{data[idx+0x0F]:02X}" if idx + 0x0F < len(data) else "")
            offset = idx + 1

        # Search for protocol GUID
        idx = data.find(PROTO_GUID)
        if idx >= 0:
            found_guid.append((f"{lun_dir}/{fname}", fpath, idx))
            print(f"  ★ PROTO GUID in {lun_dir}/{fname} at offset 0x{idx:X}")

print(f"\n{'='*70}")
print(f"Summary: Found MAGIC in {len(found_magic)} locations, PROTO GUID in {len(found_guid)} locations")
print(f"{'='*70}")

for name, path, off, size in found_magic:
    data = open(path, 'rb').read()
    print(f"\n  {name}: offset 0x{off:X}, file size {size}")
    print(f"    Magic: {data[off:off+13]}")
    if off + 0x10 <= len(data):
        print(f"    [0x0D] is_unlocked:     0x{data[off+0x0D]:02X}")
        print(f"    [0x0E] is_unlock_crit:  0x{data[off+0x0E]:02X}")
        print(f"    [0x0F] charger_screen:  0x{data[off+0x0F]:02X}")
    if off + 0x91 <= len(data):
        print(f"    [0x90] verity_mode:     0x{data[off+0x90]:02X}")

for name, path, off in found_guid:
    print(f"\n  PROTO GUID in {name} at 0x{off:X}")

# Also check GPT tables on all LUNs for 'devinfo' partition
print(f"\n{'='*70}")
print("Search GPT tables on all LUNs for 'devinfo' partition name")
print(f"{'='*70}")

for lun_dir in sorted(os.listdir(BACKUP_DIR)):
    lun_path = os.path.join(BACKUP_DIR, lun_dir)
    if not os.path.isdir(lun_path):
        continue

    for fname in sorted(os.listdir(lun_path)):
        if 'gpt' not in fname.lower():
            continue
        fpath = os.path.join(lun_path, fname)
        data = open(fpath, 'rb').read()

        # Try to find "devinfo" in UTF-16LE
        devinfo_utf16 = 'devinfo'.encode('utf-16-le')
        idx = data.find(devinfo_utf16)
        if idx >= 0:
            print(f"  Found 'devinfo' in {lun_dir}/{fname} at offset 0x{idx:X}")
            # Parse the GPT entry
            entry_start = idx - 56  # name field is at offset 56 in GPT entry
            if entry_start >= 0:
                first_lba = struct.unpack_from('<Q', data, entry_start + 32)[0]
                last_lba = struct.unpack_from('<Q', data, entry_start + 40)[0]
                type_guid = data[entry_start:entry_start+16]
                unique_guid = data[entry_start+16:entry_start+32]
                print(f"    First LBA: {first_lba}, Last LBA: {last_lba}")

                def fmtg(b):
                    return (f'{struct.unpack_from("<I",b,0)[0]:08X}-'
                            f'{struct.unpack_from("<H",b,4)[0]:04X}-'
                            f'{struct.unpack_from("<H",b,6)[0]:04X}-'
                            f'{b[8]:02X}{b[9]:02X}-{b[10]:02X}{b[11]:02X}{b[12]:02X}{b[13]:02X}{b[14]:02X}{b[15]:02X}')
                print(f"    Type GUID: {fmtg(type_guid)}")
                print(f"    Unique GUID: {fmtg(unique_guid)}")

# Check param partition for ANDROID-BOOT! or devinfo structures
print(f"\n{'='*70}")
print("Check param partition for devinfo-like data")
print(f"{'='*70}")

param_path = os.path.join(BACKUP_DIR, 'param.bin')
if os.path.exists(param_path):
    param = open(param_path, 'rb').read()
    print(f"  param.bin size: {len(param)} bytes")
    idx = param.find(MAGIC)
    if idx >= 0:
        print(f"  ★★★ ANDROID-BOOT! found in param.bin at offset 0x{idx:X}!")
        print(f"    [+0x0D]: 0x{param[idx+0x0D]:02X}")
        print(f"    [+0x0E]: 0x{param[idx+0x0E]:02X}")
        print(f"    [+0x0F]: 0x{param[idx+0x0F]:02X}")
    else:
        print(f"  ANDROID-BOOT! not found in param.bin")

    # Search for "devinfo" string
    idx = param.find(b'devinfo')
    if idx >= 0:
        print(f"  'devinfo' string found at offset 0x{idx:X}")
        print(f"    Context: {param[max(0,idx-8):idx+32].hex()}")

# Check if any XBL/bootloader partitions contain the protocol GUID
print(f"\n{'='*70}")
print("Search boot partitions for protocol GUID")
print(f"{'='*70}")

for lun_dir in ['lun0', 'lun1', 'lun2', 'lun3', 'lun4', 'lun5']:
    lun_path = os.path.join(BACKUP_DIR, lun_dir)
    if not os.path.isdir(lun_path):
        continue
    for fname in sorted(os.listdir(lun_path)):
        if not fname.endswith('.bin'):
            continue
        if any(x in fname.lower() for x in ['xbl', 'abl', 'hyp', 'tz', 'devcfg', 'imagefv',
                                               'cateloader', 'catefv', 'catecontentfv', 'core_nhlos',
                                               'keymaster', 'featenabler', 'multiimgoem']):
            fpath = os.path.join(lun_path, fname)
            data = open(fpath, 'rb').read()
            idx = data.find(PROTO_GUID)
            if idx >= 0:
                print(f"  ★ PROTO GUID in {lun_dir}/{fname} at offset 0x{idx:X}")
                # Show surrounding data
                print(f"    Context: ...{data[max(0,idx-16):idx+32].hex()}")

print("\nDone.")
