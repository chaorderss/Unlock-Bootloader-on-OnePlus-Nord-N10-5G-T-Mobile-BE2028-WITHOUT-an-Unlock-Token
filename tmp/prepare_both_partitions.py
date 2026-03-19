#!/usr/bin/env python3
"""
Check both config and frp partitions and prepare modifications for both.
The ABL function reads partition named "config" (UTF-16) but logs it as "FRP".
"""
import os
import struct

edl_base = '/Users/xmxx/pinganhuijia/edl_backup'

for part_name in ['config', 'frp']:
    path = os.path.join(edl_base, 'lun0', f'{part_name}.bin')
    with open(path, 'rb') as f:
        data = f.read()

    nz = sum(1 for b in data if b != 0)
    print(f"\n=== {part_name}.bin ===")
    print(f"  Size: {len(data)} bytes")
    print(f"  Non-zero bytes: {nz}")
    print(f"  Last byte: 0x{data[-1]:02X}")
    print(f"  IsAllowUnlock (last_byte & 1): {data[-1] & 1}")

    if nz > 0:
        print(f"  Non-zero data:")
        for off in range(0, len(data), 16):
            chunk = data[off:off+16]
            if any(b != 0 for b in chunk):
                hex_str = chunk.hex()
                ascii_str = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk)
                print(f"    0x{off:05X}: {hex_str}  {ascii_str}")

# Also check in the GPT what partition type GUIDs they have
print("\n=== Checking partition GUIDs in GPT ===")
gpt_path = os.path.join(edl_base, 'lun0', 'gpt_main0.bin')
with open(gpt_path, 'rb') as f:
    gpt = f.read()

# GPT header at LBA 1 (4096-byte sectors)
# For lun0, sector size might be 512 or 4096
# Check GPT signature
for sector_size in [512, 4096]:
    hdr_off = sector_size
    sig = gpt[hdr_off:hdr_off+8]
    if sig == b'EFI PART':
        print(f"  GPT found at offset {sector_size} (sector size: {sector_size})")
        entry_lba = struct.unpack_from('<Q', gpt, hdr_off + 72)[0]
        entry_count = struct.unpack_from('<I', gpt, hdr_off + 80)[0]
        entry_size = struct.unpack_from('<I', gpt, hdr_off + 84)[0]
        print(f"  Entry LBA: {entry_lba}, count: {entry_count}, size: {entry_size}")

        entries_off = entry_lba * sector_size
        for i in range(entry_count):
            ent_off = entries_off + i * entry_size
            if ent_off + entry_size > len(gpt):
                break

            type_guid = gpt[ent_off:ent_off+16]
            if all(b == 0 for b in type_guid):
                continue

            name_raw = gpt[ent_off+56:ent_off+56+72]
            name = name_raw.decode('utf-16-le', errors='replace').rstrip('\x00')

            first_lba = struct.unpack_from('<Q', gpt, ent_off + 32)[0]
            last_lba = struct.unpack_from('<Q', gpt, ent_off + 40)[0]
            size_bytes = (last_lba - first_lba + 1) * sector_size

            if name.lower() in ['config', 'frp', 'devinfo', 'param']:
                d1, d2, d3 = struct.unpack_from('<IHH', type_guid, 0)
                d4 = type_guid[8:16]
                guid_str = f"{d1:08X}-{d2:04X}-{d3:04X}-{d4[0]:02X}{d4[1]:02X}-"
                guid_str += f"{d4[2]:02X}{d4[3]:02X}{d4[4]:02X}{d4[5]:02X}{d4[6]:02X}{d4[7]:02X}"
                print(f"  {name}: LBA {first_lba}-{last_lba}, size={size_bytes}, GUID={guid_str}")

# Prepare both modified partitions
print("\n=== Preparing modified partitions ===")
for part_name in ['config', 'frp']:
    src = os.path.join(edl_base, 'lun0', f'{part_name}.bin')
    dst = os.path.join('/Users/xmxx/pinganhuijia/tmp', f'{part_name}_unlocked.bin')

    with open(src, 'rb') as f:
        data = bytearray(f.read())

    data[-1] = 0x01  # Set OEM unlock flag

    with open(dst, 'wb') as f:
        f.write(data)

    print(f"  {dst}: last byte = 0x{data[-1]:02X}, size = {len(data)}")
