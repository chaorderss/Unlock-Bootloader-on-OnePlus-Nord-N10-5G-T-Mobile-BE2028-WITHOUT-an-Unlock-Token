#!/usr/bin/env python3
"""
Create a test-modified wlanmdsp.mbn to check if MBN auth is enforced.
Strategy: Modify a single byte in a LOAD segment's non-critical area.
If the modem checks hashes, it will reject. If not, it will load.
"""
import struct, sys, shutil

src = "wlanmdsp.mbn"
dst = "wlanmdsp_modified.mbn"
backup = "wlanmdsp_original.mbn"

# Parse ELF
with open(src, "rb") as f:
    data = bytearray(f.read())

print(f"Original size: {len(data)} bytes")

# Backup
shutil.copy2(src, backup)
print(f"Backup saved to {backup}")

# Parse ELF header
e_phoff = struct.unpack_from('<I', data, 28)[0]
e_phnum = struct.unpack_from('<H', data, 44)[0]
print(f"Program headers: {e_phnum} at offset 0x{e_phoff:x}")

# Find LOAD segments
for i in range(e_phnum):
    off = e_phoff + i * 32
    p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
        struct.unpack_from('<IIIIIIII', data, off)

    prot = ""
    if p_flags & 4: prot += "R"
    if p_flags & 2: prot += "W"
    if p_flags & 1: prot += "X"

    if p_type == 1:  # LOAD
        print(f"  PH[{i}] LOAD: file 0x{p_offset:08x}-0x{p_offset+p_filesz:08x} "
              f"vaddr 0x{p_vaddr:08x} ({prot})")

# Modify strategy 1: Flip a bit in the RODATA segment (PH[5])
# PH[5] has strings at file offset 0x368000
# Find a string we can modify safely
rodata_off = 0x368000

# Find "wlan_ant_share_5g.c" string (first string in RODATA)
target_str = b"wlan_ant_share_5g.c"
idx = data.find(target_str, rodata_off)
if idx >= 0:
    print(f"\nFound target string at file offset 0x{idx:x}")
    print(f"  Original: {data[idx:idx+len(target_str)]}")

    # Modify: change 'w' to 'W' (harmless capitalization change)
    data[idx] = ord('W')
    print(f"  Modified: {data[idx:idx+len(target_str)]}")
else:
    # Fallback: modify last byte of RODATA
    idx = rodata_off + 0x100
    print(f"\nModifying byte at offset 0x{idx:x}")
    print(f"  Original: 0x{data[idx]:02x}")
    data[idx] ^= 0x01  # Flip one bit
    print(f"  Modified: 0x{data[idx]:02x}")

with open(dst, "wb") as f:
    f.write(data)

print(f"\nModified firmware saved to {dst}")
print(f"Size: {len(data)} bytes (unchanged)")

# Also create a version with hash segment zeroed
dst2 = "wlanmdsp_nohash.mbn"
data2 = bytearray(open(src, "rb").read())

# PH[1] is the hash segment at file offset 0x1000, size 0x1A60
hash_off = 0x1000
hash_size = 0x1A60
print(f"\nZeroing hash segment at file[0x{hash_off:x}-0x{hash_off+hash_size:x}]")
for i in range(hash_off, hash_off + hash_size):
    data2[i] = 0
with open(dst2, "wb") as f:
    f.write(data2)
print(f"No-hash firmware saved to {dst2}")
