#!/usr/bin/env python3
"""Dump raw hex of SID 0x12C and 0x13C to compare structure."""
import subprocess
import hashlib
from binascii import hexlify
from struct import unpack

result = subprocess.run(['adb', 'shell', 'dd if=/dev/block/sda6 2>/dev/null'],
                       capture_output=True, timeout=30)
data = result.stdout
print(f"Param partition size: {len(data)}")

for sid_val in [0x12C, 0x130, 0x134, 0x138, 0x13C, 0x140, 0x144]:
    offset = sid_val * 0x400
    if offset + 0x1000 > len(data):
        print(f"\nSID 0x{sid_val:X}: out of range")
        continue
    block = data[offset:offset + 0x1000]
    magic = unpack('<I', block[:4])[0]
    if magic != 0xA0AD646A:
        print(f"\nSID 0x{sid_val:X} (offset 0x{offset:X}): magic=0x{magic:08X} (NOT param magic)")
        continue

    hv = block[4]
    cv = block[5]
    update_counter = block[0x10]
    enchash = block[0x80:0x90]
    encdata = block[0x400:0x400 + 0xC00]
    computed = hashlib.md5(encdata).digest()

    print(f"\nSID 0x{sid_val:X} (offset 0x{offset:X}):")
    print(f"  magic=0xA0AD646A  hv={hv}  cv={cv}  update_counter={update_counter}")
    print(f"  enchash:  {hexlify(enchash).decode()}")
    print(f"  computed: {hexlify(computed).decode()}")
    print(f"  ciphertext_ok: {enchash == computed}")
    print(f"  Header (0x00-0x20): {hexlify(block[:0x20]).decode()}")
    print(f"  Header (0x70-0xA0): {hexlify(block[0x70:0xA0]).decode()}")
    # Check bytes 6-0x10 for any clues
    print(f"  Bytes 0x06-0x10: {hexlify(block[6:0x10]).decode()}")
    print(f"  Bytes 0x10-0x20: {hexlify(block[0x10:0x20]).decode()}")

# Also check if there are backup SIDs
for sid_val in [0x32C, 0x330, 0x334, 0x338, 0x33C]:
    offset = sid_val * 0x400
    if offset + 0x1000 > len(data):
        print(f"\nBackup SID 0x{sid_val:X}: out of range (offset 0x{offset:X})")
        continue
    block = data[offset:offset + 0x1000]
    magic = unpack('<I', block[:4])[0]
    if magic == 0xA0AD646A:
        print(f"\nBackup SID 0x{sid_val:X} (offset 0x{offset:X}): HAS VALID MAGIC")
        hv = block[4]
        cv = block[5]
        update_counter = block[0x10]
        print(f"  hv={hv}  cv={cv}  update_counter={update_counter}")
    else:
        print(f"\nBackup SID 0x{sid_val:X} (offset 0x{offset:X}): magic=0x{magic:08X}")
