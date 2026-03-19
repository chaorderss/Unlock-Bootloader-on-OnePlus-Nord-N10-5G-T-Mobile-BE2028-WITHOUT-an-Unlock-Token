#!/usr/bin/env python3
"""
Analyze GPT headers to check sector size and devinfo partition location.
Compare what EDL uses vs what ABL/UEFI might use.
"""
import struct, os

base = '/Users/xmxx/pinganhuijia/edl_backup'

def parse_gpt_header(data, label):
    """Parse GPT header."""
    sig = data[0:8]
    if sig != b'EFI PART':
        print(f"  [{label}] No valid GPT signature at offset 0")
        # Try offset 0x200 (512-byte sector) and 0x1000 (4K sector)
        for off in [0x200, 0x1000]:
            if data[off:off+8] == b'EFI PART':
                print(f"  [{label}] Found GPT signature at offset 0x{off:X}")
                return parse_gpt_header_at(data, off, label)
        return
    return parse_gpt_header_at(data, 0, label)

def parse_gpt_header_at(data, off, label):
    sig = data[off:off+8]
    rev = struct.unpack('<I', data[off+8:off+12])[0]
    hdr_size = struct.unpack('<I', data[off+12:off+16])[0]
    my_lba = struct.unpack('<Q', data[off+24:off+32])[0]
    alt_lba = struct.unpack('<Q', data[off+32:off+40])[0]
    first_usable = struct.unpack('<Q', data[off+40:off+48])[0]
    last_usable = struct.unpack('<Q', data[off+48:off+56])[0]
    part_entry_lba = struct.unpack('<Q', data[off+72:off+80])[0]
    num_entries = struct.unpack('<I', data[off+80:off+84])[0]
    entry_size = struct.unpack('<I', data[off+84:off+88])[0]

    print(f"  [{label}] GPT Header at offset 0x{off:X}:")
    print(f"    Revision: 0x{rev:08X}")
    print(f"    Header size: {hdr_size}")
    print(f"    My LBA: {my_lba}")
    print(f"    Alt LBA: {alt_lba}")
    print(f"    First usable LBA: {first_usable}")
    print(f"    Last usable LBA: {last_usable}")
    print(f"    Partition entry start LBA: {part_entry_lba}")
    print(f"    Num partition entries: {num_entries}")
    print(f"    Partition entry size: {entry_size}")

    # Infer sector size from header position
    if off == 0x200:
        inferred_sector = 512
    elif off == 0x1000:
        inferred_sector = 4096
    else:
        inferred_sector = "unknown"
    print(f"    Inferred sector size: {inferred_sector}")

    return {
        'offset': off,
        'my_lba': my_lba,
        'part_entry_lba': part_entry_lba,
        'num_entries': num_entries,
        'entry_size': entry_size,
        'inferred_sector': inferred_sector,
    }

def find_devinfo_entry(data, gpt_info, sector_size):
    """Find devinfo partition entry."""
    entry_off = gpt_info['part_entry_lba'] * sector_size
    entry_size = gpt_info['entry_size']

    for i in range(gpt_info['num_entries']):
        off = entry_off + i * entry_size
        if off + entry_size > len(data):
            break
        # Partition name is at offset 56, UCS-2 encoded
        name_raw = data[off+56:off+56+72]
        try:
            name = name_raw.decode('utf-16-le').rstrip('\x00')
        except:
            name = ""
        if not name:
            continue

        type_guid = data[off:off+16]
        unique_guid = data[off+16:off+32]
        first_lba = struct.unpack('<Q', data[off+32:off+40])[0]
        last_lba = struct.unpack('<Q', data[off+40:off+48])[0]

        if name == 'devinfo':
            byte_offset = first_lba * sector_size
            size_bytes = (last_lba - first_lba + 1) * sector_size
            print(f"\n  devinfo partition entry (sector_size={sector_size}):")
            print(f"    First LBA: {first_lba} (byte offset: 0x{byte_offset:X})")
            print(f"    Last LBA: {last_lba}")
            print(f"    Size: {size_bytes} bytes ({size_bytes/1024:.1f} KB)")

            # Also compute what this would be with different sector sizes
            for ss in [512, 4096]:
                bo = first_lba * ss
                print(f"    If sector_size={ss}: byte offset = 0x{bo:X} ({bo})")

            return first_lba

# Parse LUN4 GPT
print("=" * 60)
print("LUN4 GPT Analysis")
print("=" * 60)

gpt_file = os.path.join(base, 'lun4/gpt_main4.bin')
if os.path.isfile(gpt_file):
    with open(gpt_file, 'rb') as f:
        gpt_data = f.read()
    print(f"gpt_main4.bin size: {len(gpt_data)} bytes")

    # Dump first 32 bytes to check for protective MBR or GPT header
    print(f"  First 32 bytes: {gpt_data[:32].hex()}")

    # Check multiple offsets for GPT signature
    for off in [0, 0x200, 0x1000]:
        if gpt_data[off:off+8] == b'EFI PART':
            print(f"  GPT signature found at offset 0x{off:X}")
            gpt_info = parse_gpt_header_at(gpt_data, off, f"offset_0x{off:X}")

            if gpt_info:
                sector_size = gpt_info['inferred_sector'] if isinstance(gpt_info['inferred_sector'], int) else 4096
                find_devinfo_entry(gpt_data, gpt_info, sector_size)

# Also check rawprogram XML for reference
print(f"\n{'=' * 60}")
print("rawprogram4.xml reference:")
print("=" * 60)
import xml.etree.ElementTree as ET
rp_file = os.path.join(base, 'lun4/rawprogram4.xml')
if os.path.isfile(rp_file):
    tree = ET.parse(rp_file)
    root = tree.getroot()
    for prog in root.iter('program'):
        if prog.get('label') == 'devinfo':
            for key in ['label', 'start_sector', 'num_partition_sectors',
                       'SECTOR_SIZE_IN_BYTES', 'start_byte_hex', 'size_in_KB']:
                val = prog.get(key, 'N/A')
                print(f"  {key}: {val}")

# Compute what happens with sector size mismatch
print(f"\n{'=' * 60}")
print("Sector size mismatch analysis:")
print("=" * 60)
print("EDL uses rawprogram4.xml: sector 535022, sector_size=4096")
print(f"  EDL byte offset: {535022 * 4096} = 0x{535022 * 4096:X}")
print(f"  If ABL uses 512B sectors with same LBA: {535022 * 512} = 0x{535022 * 512:X}")
print(f"  Ratio: 4096/512 = 8x")
print(f"  If ABL translates: LBA 535022 in GPT(4K) -> LBA {535022 * 8} in BlockIO(512B)")
print(f"  That would give same byte offset: {535022 * 8 * 512} = 0x{535022 * 8 * 512:X}")
