#!/usr/bin/env python3
"""
Check if sector size mismatch exists.
Strategy: Read raw bytes from the PHYSICAL disk at both possible offsets:
  - 0x829EE000 (LBA 535022 * 4096) — where EDL writes
  - 0x1053DC00 (LBA 535022 * 512) — where ABL would read if using 512B sectors

We'll create EDL commands to read raw sectors at both locations.
Also check what the edl tool actually uses for sector addressing.
"""

# First, let's check what the actual edl python tool does
# The edl tool for Qualcomm uses the Firehose protocol
# Firehose's read command uses SECTOR_SIZE_IN_BYTES from the rawprogram XML
# But when reading by partition name, it uses the GPT from the device

# The key question: does EDL's 'edl r devinfo' use:
#   a) rawprogram XML sector info (4K sectors, LBA 535022)
#   b) on-device GPT with whatever sector size the device reports

# UFS devices have both physical and logical sector sizes
# Physical Block Size = 4096
# Logical Block Size can be 512 or 4096

# Let's check by creating commands to read raw data at both offsets

print("=" * 60)
print("EDL Commands to Test Sector Size Mismatch")
print("=" * 60)

print("""
THEORY: ABL's UEFI Block I/O uses 512-byte logical sectors.
GPT on disk uses 4K sectors (confirmed from gpt_main4.bin).
When ABL parses GPT, it reads LBA 535022 as the devinfo start.
But Block I/O translates this to sector 535022 * 512 = 0x1053DC00.

TEST PLAN:
1. Read 4096 bytes at the "correct" EDL offset (LBA 535022 * 4096 = 0x829EE000)
   This is where EDL writes 'devinfo'

2. Read 4096 bytes at the "mismatched" offset (LBA 535022 * 512 = 0x1053DC00)
   This is where ABL would read if sector size is 512

Commands to run on device via EDL:

# Method 1: Read the partition by name (this is what we've been doing)
edl r devinfo devinfo_by_name.bin --lun 4

# Method 2: Read raw sectors at the 4K offset
edl rs 535022 1 devinfo_4k.bin --lun 4 --sectorsize 4096

# Method 3: Read raw sectors using 512B sector addressing
# LBA 535022 at 512B = byte offset 0x1053DC00
# To read this with 4K sector tool: sector = 0x1053DC00 / 4096 = 66811
edl rs 66811 1 devinfo_512b_as4k.bin --lun 4 --sectorsize 4096

# Method 4: If edl supports 512B sector read
# LBA 4280176 at 512B = byte offset 0x829EE000 (same physical location as 4K LBA 535022)
edl rs 535022 8 devinfo_512b_raw.bin --lun 4 --sectorsize 512
""")

# Actually, let's think about this differently.
# The edl tool reads devinfo by partition name from the on-device GPT.
# If on-device GPT uses 4K sectors and edl correctly handles this,
# then 'edl r devinfo' reads the correct data.
# We confirmed the data is there (our diagnostic values preserved).
#
# The issue is ABL's UEFI firmware uses a DIFFERENT GPT or sector size.
#
# BUT WAIT - there's another possibility:
# What if the UEFI firmware has its OWN partition table,
# separate from the GPT? This is common on Qualcomm:
# The XBL/UEFI drivers can have a hardcoded partition table
# or read from a different GPT.

# Let's check: does LUN4 have BOTH a primary GPT (at LBA 0-5)
# and a backup GPT (at end)?
# And are they using the same sector size?

import struct, os

base = '/Users/xmxx/pinganhuijia/edl_backup/lun4'

# Check backup GPT
backup_gpt = os.path.join(base, 'gpt_backup4.bin')
if os.path.isfile(backup_gpt):
    with open(backup_gpt, 'rb') as f:
        data = f.read()
    print(f"gpt_backup4.bin size: {len(data)} bytes")
    for off in [0, 0x200, 0x1000, len(data)-0x200, len(data)-0x1000]:
        if 0 <= off < len(data)-8:
            if data[off:off+8] == b'EFI PART':
                print(f"  GPT signature at offset 0x{off:X}")
                my_lba = struct.unpack('<Q', data[off+24:off+32])[0]
                alt_lba = struct.unpack('<Q', data[off+32:off+40])[0]
                print(f"  My LBA: {my_lba}, Alt LBA: {alt_lba}")

# More importantly: compute both possible locations
print(f"\n{'='*60}")
print("Physical byte offsets:")
print(f"{'='*60}")
lba = 535022
print(f"devinfo GPT LBA: {lba}")
print(f"  4K sector: byte 0x{lba*4096:X} = {lba*4096}")
print(f"  512B sector: byte 0x{lba*512:X} = {lba*512}")
print(f"  Difference: {lba*4096 - lba*512} bytes = {(lba*4096 - lba*512)/1024/1024:.1f} MB")
print(f"  4K sector in 512B: LBA {lba*8} (*8)")

# Which sector at 512B gives the SAME byte offset as 4K/535022?
# 535022 * 4096 = X * 512 -> X = 535022 * 8 = 4280176
print(f"\n  To reach 0x829EE000 with 512B sectors: LBA {lba*8}")
print(f"  Verify: {lba*8} * 512 = 0x{lba*8*512:X}")

# What partition is at 512B LBA 535022 (byte 0x1053DC00)?
# 0x1053DC00 / 4096 = 66811.0 -> 4K LBA 66811
sector_4k = (lba * 512) // 4096
print(f"\n  0x1053DC00 in 4K LBAs = LBA {sector_4k}")

# Check what partition is at 4K LBA 66811
main_gpt = os.path.join(base, 'gpt_main4.bin')
with open(main_gpt, 'rb') as f:
    gpt_data = f.read()

# Parse partition entries (at 4K sector 2 = offset 0x2000)
entry_off = 2 * 4096  # LBA 2, 4K sectors
for i in range(96):
    off = entry_off + i * 128
    if off + 128 > len(gpt_data):
        break
    first_lba = struct.unpack('<Q', gpt_data[off+32:off+40])[0]
    last_lba = struct.unpack('<Q', gpt_data[off+40:off+48])[0]
    if first_lba == 0:
        continue
    name = gpt_data[off+56:off+128].decode('utf-16-le').rstrip('\x00')
    if not name:
        continue

    # Check if LBA 66811 falls within this partition
    if first_lba <= sector_4k <= last_lba:
        print(f"\n  At 4K LBA {sector_4k}: partition '{name}' (LBA {first_lba}-{last_lba})")
        part_offset = (sector_4k - first_lba) * 4096
        print(f"    Offset within partition: 0x{part_offset:X}")

    # Also print devinfo neighbors for context
    if abs(first_lba - 535022) < 100 or name == 'devinfo':
        print(f"  Partition '{name}': LBA {first_lba}-{last_lba} (byte 0x{first_lba*4096:X}-0x{last_lba*4096+4095:X})")
