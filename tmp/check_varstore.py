#!/usr/bin/env python3
"""
Check the uefivarstore partition for devinfo data.
UEFI NV variable stores typically use a specific format:
- FV header (EFI_FIRMWARE_VOLUME_HEADER)
- Variable headers with name, GUID, data
"""
import struct, os

base = '/Users/xmxx/pinganhuijia/edl_backup'

# First find uefivarstore in the GPT
gpt_file = os.path.join(base, 'lun4/gpt_main4.bin')
with open(gpt_file, 'rb') as f:
    gpt = f.read()

entry_base = 2 * 4096
for i in range(96):
    off = entry_base + i * 128
    if off + 128 > len(gpt):
        break
    first_lba = struct.unpack('<Q', gpt[off+32:off+40])[0]
    last_lba = struct.unpack('<Q', gpt[off+40:off+48])[0]
    name = gpt[off+56:off+128].decode('utf-16-le').rstrip('\x00')
    if name == 'uefivarstore':
        size = (last_lba - first_lba + 1) * 4096
        print(f"uefivarstore: LBA {first_lba}-{last_lba}, size={size} ({size/1024:.0f} KB)")
        break

# Check if we have a backup of uefivarstore
vs_files = []
for lun in range(6):
    d = os.path.join(base, f'lun{lun}')
    if not os.path.isdir(d):
        continue
    for fn in os.listdir(d):
        if 'uefi' in fn.lower() or 'varstore' in fn.lower():
            vs_files.append(os.path.join(d, fn))

if vs_files:
    print(f"\nFound varstore backup files: {vs_files}")
else:
    print(f"\nNo uefivarstore backup file found!")
    print("Checking all LUN4 files...")
    d = os.path.join(base, 'lun4')
    for fn in sorted(os.listdir(d)):
        fp = os.path.join(d, fn)
        if os.path.isfile(fp):
            sz = os.path.getsize(fp)
            if 'var' in fn.lower() or 'store' in fn.lower() or 'uefi' in fn.lower():
                print(f"  {fn}: {sz} bytes")

# Try to find uefivarstore as a file (it might have been backed up with that name)
uefi_path = os.path.join(base, 'lun4/uefivarstore.bin')
if not os.path.isfile(uefi_path):
    # Check rawprogram for the partition
    import xml.etree.ElementTree as ET
    rp = os.path.join(base, 'lun4/rawprogram4.xml')
    if os.path.isfile(rp):
        tree = ET.parse(rp)
        for prog in tree.getroot().iter('program'):
            if prog.get('label') == 'uefivarstore':
                print(f"\nrawprogram4.xml uefivarstore entry:")
                for k in ['label', 'filename', 'start_sector', 'num_partition_sectors',
                          'SECTOR_SIZE_IN_BYTES', 'start_byte_hex', 'size_in_KB']:
                    print(f"  {k}: {prog.get(k, 'N/A')}")

# List ALL files in all LUN backup directories
print(f"\n=== All backup files ===")
for lun in range(6):
    d = os.path.join(base, f'lun{lun}')
    if not os.path.isdir(d):
        continue
    for fn in sorted(os.listdir(d)):
        if fn.endswith('.xml') or fn.endswith('.bin'):
            fp = os.path.join(d, fn)
            sz = os.path.getsize(fp)
            print(f"  lun{lun}/{fn}: {sz}")

# Check if storsec, secdata, or config might have devinfo
# Also search for "ANDROID-BOOT!" in the logfs and uefivarstore areas
print(f"\n=== Searching specific partitions for devinfo data ===")
magic = b'ANDROID-BOOT!'
for fn in ['lun4/logfs.bin', 'lun4/storsec_a.bin', 'lun4/secdata.bin']:
    fp = os.path.join(base, fn)
    if not os.path.isfile(fp):
        print(f"  {fn}: NOT FOUND")
        continue
    with open(fp, 'rb') as f:
        data = f.read()
    idx = data.find(magic)
    if idx >= 0:
        print(f"  {fn}: FOUND magic at 0x{idx:X}!")
    else:
        # Also search for "devinfo" string (ASCII or UCS-2)
        idx_a = data.find(b'devinfo')
        idx_u = data.find(b'd\x00e\x00v\x00i\x00n\x00f\x00o\x00')
        if idx_a >= 0:
            print(f"  {fn}: found 'devinfo' ASCII at 0x{idx_a:X}")
        elif idx_u >= 0:
            print(f"  {fn}: found 'devinfo' UCS-2 at 0x{idx_u:X}")
        else:
            print(f"  {fn}: no devinfo refs (size={len(data)})")

print("\nDone.")
