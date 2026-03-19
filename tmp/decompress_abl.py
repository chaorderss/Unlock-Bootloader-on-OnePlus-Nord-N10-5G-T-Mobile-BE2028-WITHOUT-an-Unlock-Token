#!/usr/bin/env python3
"""Decompress LZMA GUID-defined section from ABL FV."""
import struct, lzma
from binascii import hexlify

with open('/tmp/abl_a.bin', 'rb') as f:
    abl = f.read()

# The GUID_DEFINED section starts at file 0x3048, section at 0x3048+24=0x3060
# Section header: 4 bytes (size+type), then GUID_DEFINED: 16 guid + 2 offset + 2 attrs
# Data starts at DataOff=24 within the section data (after section header)

sec_start = 0x3060  # section start
sec_size_bytes = abl[sec_start:sec_start+3]
sec_size = sec_size_bytes[0] | (sec_size_bytes[1] << 8) | (sec_size_bytes[2] << 16)
sec_data = abl[sec_start+4:sec_start+sec_size]

# GUID_DEFINED header: 16 guid + 2 data_offset + 2 attrs = 20 bytes
# DataOffset=24 means data starts 24 bytes into section data
inner = sec_data[24:]
print(f"Inner data size: {len(inner)} bytes")
print(f"First 32 bytes: {hexlify(inner[:32]).decode()}")

# Try LZMA decompression with different approaches
# EFI LZMA format: 5 byte props + 8 byte uncompressed size (LE) + compressed data

# Approach 1: Raw LZMA
print("\nApproach 1: Raw lzma.decompress()...")
try:
    dec = lzma.decompress(inner)
    print(f"Success: {len(dec)} bytes")
except Exception as e:
    print(f"Failed: {e}")

# Approach 2: LZMA with format=FORMAT_RAW
print("\nApproach 2: FORMAT_RAW with auto filter...")
for filter_id in [lzma.FILTER_LZMA1, lzma.FILTER_LZMA2]:
    for dict_size in [16*1024*1024, 8*1024*1024, 4*1024*1024, 2*1024*1024]:
        try:
            props_byte = inner[0]
            lc = props_byte % 9
            rem = props_byte // 9
            lp = rem % 5
            pb = rem // 5

            dec = lzma.decompress(inner[13:], format=lzma.FORMAT_RAW,
                                  filters=[{"id": filter_id, "lc": lc, "lp": lp, "pb": pb,
                                           "dict_size": dict_size}])
            print(f"Success with filter={filter_id}, dict={dict_size}: {len(dec)} bytes")
            break
        except:
            pass

# Approach 3: Wrap with LZMA alone header
print("\nApproach 3: Manual LZMA1 header...")
# LZMA1 standalone format: 5 props + 8 uncompressed_size + data
# EFI format: might already be this
# Props byte: inner[0], then 4 bytes dict_size (LE), then 8 bytes uncompressed_size, then data
props = inner[:5]
uncompressed_size = struct.unpack('<Q', inner[5:13])[0]
print(f"LZMA props: {hexlify(props).decode()}")
print(f"Uncompressed size: {uncompressed_size} (0x{uncompressed_size:X})")
compressed = inner[13:]

# Create proper LZMA alone format
try:
    # The LZMA alone format is: props(5) + size(8) + data
    # inner already contains props(5) + size(8) + data - so inner IS the LZMA alone format!
    decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
    dec = decompressor.decompress(inner)
    print(f"FORMAT_ALONE success: {len(dec)} bytes")

    with open('/tmp/abl_decompressed.bin', 'wb') as f:
        f.write(dec)
    print(f"Saved to /tmp/abl_decompressed.bin")

    # Search for key strings
    for s in [b'Encrypted block', b'get_param_by_index', b'000OnePlus818000',
              b'000OnePlus', b'sw_proj_id', b'init_param', b'verified success',
              b'GetParam', b'SoftwareProject', b'carrier']:
        idx = dec.find(s)
        if idx >= 0:
            start = idx
            while start > 0 and dec[start-1] != 0:
                start -= 1
            end = idx
            while end < len(dec) and dec[end] != 0:
                end += 1
            txt = dec[start:end].decode('utf-8', errors='replace')
            print(f"  FOUND '{s.decode()}' at 0x{idx:X}: '{txt[:120]}'")
        else:
            print(f"  '{s.decode()}': not found")
except Exception as e:
    print(f"Failed: {e}")

# Approach 4: Skip first bytes and try
print("\nApproach 4: trying with different start offsets...")
for skip in [0, 4, 8, 16]:
    try:
        decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
        dec = decompressor.decompress(inner[skip:])
        print(f"Skip={skip}: {len(dec)} bytes")
        break
    except Exception as e:
        if skip < 16:
            continue
        print(f"All skips failed. Last error: {e}")
