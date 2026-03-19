#!/usr/bin/env python3
"""
Deep GPT analysis - check sector sizes, devinfo type GUID,
and what's at the 512B-sector offset.
"""
import struct, os

base = '/Users/xmxx/pinganhuijia/edl_backup'
gpt_file = os.path.join(base, 'lun4/gpt_main4.bin')

with open(gpt_file, 'rb') as f:
    gpt = f.read()

print(f"gpt_main4.bin size: {len(gpt)} bytes")

# 1. Check what's at various offsets
print("\n=== Raw data at key offsets ===")
for off in [0x0, 0x1C0, 0x1FE, 0x200, 0x400, 0x1000]:
    d = gpt[off:off+16]
    hx = ' '.join(f'{b:02X}' for b in d)
    print(f"  0x{off:04X}: {hx}")

# 2. GPT header at 0x1000
print("\n=== GPT Header at 0x1000 ===")
hdr = gpt[0x1000:0x1060]
sig = hdr[0:8]
print(f"  Signature: {sig}")
rev = struct.unpack('<I', hdr[8:12])[0]
hdr_size = struct.unpack('<I', hdr[12:16])[0]
my_lba = struct.unpack('<Q', hdr[24:32])[0]
alt_lba = struct.unpack('<Q', hdr[32:40])[0]
first_usable = struct.unpack('<Q', hdr[40:48])[0]
last_usable = struct.unpack('<Q', hdr[48:56])[0]
disk_guid = hdr[56:72]
part_entry_lba = struct.unpack('<Q', hdr[72:80])[0]
num_entries = struct.unpack('<I', hdr[80:84])[0]
entry_size = struct.unpack('<I', hdr[84:88])[0]

print(f"  Revision: {rev:#x}")
print(f"  Header size: {hdr_size}")
print(f"  My LBA: {my_lba}")
print(f"  Alternate LBA: {alt_lba}")
print(f"  First usable LBA: {first_usable}")
print(f"  Last usable LBA: {last_usable}")
print(f"  Entry start LBA: {part_entry_lba}")
print(f"  Num entries: {num_entries}")
print(f"  Entry size: {entry_size}")

# 3. Parse ALL partition entries, find devinfo and neighbors
print(f"\n=== Partition entries (at 4K LBA {part_entry_lba} = offset 0x{part_entry_lba*4096:X}) ===")
entry_base = part_entry_lba * 4096

devinfo_entry = None
partitions = []
for i in range(num_entries):
    off = entry_base + i * entry_size
    if off + entry_size > len(gpt):
        break
    type_guid = gpt[off:off+16]
    unique_guid = gpt[off+16:off+32]
    first_lba = struct.unpack('<Q', gpt[off+32:off+40])[0]
    last_lba = struct.unpack('<Q', gpt[off+40:off+48])[0]
    attrs = struct.unpack('<Q', gpt[off+48:off+56])[0]
    name = gpt[off+56:off+128].decode('utf-16-le').rstrip('\x00')

    if first_lba == 0 and last_lba == 0:
        continue

    partitions.append((name, first_lba, last_lba, type_guid, unique_guid))

    if name == 'devinfo':
        devinfo_entry = (name, first_lba, last_lba, type_guid, unique_guid, attrs)

def format_guid(g):
    a, b, c = struct.unpack('<IHH', g[:8])
    d = g[8:16]
    return f"{a:08X}-{b:04X}-{c:04X}-{d[:2].hex().upper()}-{d[2:].hex().upper()}"

if devinfo_entry:
    name, first, last, tg, ug, attrs = devinfo_entry
    print(f"\n  *** devinfo partition ***")
    print(f"  First LBA: {first}")
    print(f"  Last LBA: {last}")
    print(f"  Attributes: 0x{attrs:016X}")
    print(f"  Type GUID: {format_guid(tg)}")
    print(f"  Unique GUID: {format_guid(ug)}")
    print(f"  Byte offset (4K): 0x{first*4096:X}")
    print(f"  Byte offset (512B): 0x{first*512:X}")

# Print devinfo neighbors
print(f"\n=== Partitions near devinfo (LBA 535022) ===")
for name, first, last, tg, ug in partitions:
    if abs(first - 535022) < 200 or abs(last - 535022) < 200:
        size_kb = (last - first + 1) * 4096 / 1024
        print(f"  {name:20s}: LBA {first:>8d} - {last:>8d} ({size_kb:.0f} KB)")

# 4. Check if 512B-sector GPT exists at offset 0x200
print(f"\n=== Check for 512B-sector GPT at offset 0x200 ===")
at_200 = gpt[0x200:0x208]
print(f"  Bytes at 0x200: {at_200.hex()}")
print(f"  Is 'EFI PART'? {'YES!' if at_200 == b'EFI PART' else 'NO'}")

# 5. Check what partition would be at 512B-offset for devinfo LBA
byte_512 = 535022 * 512
sector_4k = byte_512 // 4096
print(f"\n=== Sector Size Mismatch Analysis ===")
print(f"  devinfo LBA in GPT: {535022}")
print(f"  At 4K sectors: byte 0x{535022*4096:X}")
print(f"  At 512B sectors: byte 0x{535022*512:X} (4K sector {sector_4k})")

for name, first, last, tg, ug in partitions:
    if first <= sector_4k <= last:
        inner_off = (sector_4k - first) * 4096
        print(f"  512B-offset falls in: '{name}' (LBA {first}-{last})")
        print(f"  Offset within '{name}': 0x{inner_off:X} ({inner_off/1024/1024:.1f} MB)")

# 6. The devinfo Type GUID - is it standard or OnePlus custom?
if devinfo_entry:
    tg = devinfo_entry[3]
    tg_str = format_guid(tg)
    print(f"\n=== devinfo Type GUID analysis ===")
    print(f"  Type GUID: {tg_str}")
    # Check if it matches the GUID in ABL at 0x69C80
    pe_guid_69c80 = "95A9A93E-A86E-4926-AAEF-9918E772D987"
    pe_guid_69b20 = "FE2555BE-D716-4686-B9D0-79DB5921B70D"
    if tg_str == pe_guid_69c80:
        print(f"  MATCHES ABL GUID at 0x69C80!")
    elif tg_str == pe_guid_69b20:
        print(f"  MATCHES ABL GUID at 0x69B20!")
    else:
        print(f"  Does NOT match known ABL GUIDs")
        print(f"  ABL GUID 0x69C80: {pe_guid_69c80}")
        print(f"  ABL GUID 0x69B20: {pe_guid_69b20}")

    # Known Qualcomm partition type GUIDs
    known_types = {
        "DEA0BA2C-CBDD-4805-B4F9-F428251C3E98": "EFI_SYSTEM",
        "C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "EFI_SYSTEM_PARTITION",
        "024E4F25-54B9-4154-A8C2-E6CDD41DBBA8": "Android boot",
        "20117F86-E985-4357-B9EE-374BC1D8487D": "Android data",
        "38F428E6-D326-425D-9140-6E0EA133647C": "Android misc",
        "4627AE27-CFEF-48A1-88FE-99C3509ADE26": "Android system",
        "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "Microsoft Basic Data",
        "65ADDCF4-0C5C-4D9A-AC2D-D90B5CBFCD03": "QC APPS (devinfo type)",
    }
    tg_upper = tg_str.upper()
    if tg_upper in {k.upper(): k for k in known_types}:
        for k, v in known_types.items():
            if k.upper() == tg_upper:
                print(f"  Known type: {v}")
                break
    else:
        print(f"  Type GUID not in known list")

# 7. List ALL unique partition type GUIDs used
print(f"\n=== All unique partition type GUIDs ===")
type_guids = {}
for name, first, last, tg, ug in partitions:
    tg_str = format_guid(tg)
    if tg_str not in type_guids:
        type_guids[tg_str] = []
    type_guids[tg_str].append(name)

for guid, names in type_guids.items():
    sample = ', '.join(names[:5])
    if len(names) > 5:
        sample += f', ... ({len(names)} total)'
    print(f"  {guid}: {sample}")
