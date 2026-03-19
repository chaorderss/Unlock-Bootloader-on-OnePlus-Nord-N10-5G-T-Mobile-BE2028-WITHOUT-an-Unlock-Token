#!/usr/bin/env python3
"""Decompress ABL FV with corrected offsets."""
import struct, lzma
from binascii import hexlify

with open('/tmp/abl_a.bin', 'rb') as f:
    abl = f.read()

# The GUID_DEFINED section:
# Section common header at 0x3060: 4 bytes
# GUID_DEFINED header: 16 guid + 2 dataoffset + 2 attrs = 20 bytes
# DataOffset = 24 from section START = byte 24 from 0x3060 = 0x3078, or byte 20 from 0x3064 (data start)
# But first 4 bytes of section data (at 0x3064) is start of GUID

# Let me just scan ALL of the FV for LZMA headers
fv_data = abl[0x3000:0x3000 + 0x1F0000]
print(f"FV size: {len(fv_data)}")

# LZMA props byte is usually 0x5D (for lc=3, lp=0, pb=2) or similar small values
# Try every candidate position in the FV
found = False
for i in range(0, min(0x200, len(fv_data))):
    chunk = fv_data[i:]
    if len(chunk) < 13:
        break
    props = chunk[0]
    lc = props % 9
    lp = (props // 9) % 5
    pb = (props // 9) // 5
    if lc > 8 or lp > 4 or pb > 4:
        continue
    dict_size = struct.unpack('<I', chunk[1:5])[0]
    if dict_size == 0 or dict_size > 64*1024*1024:
        continue
    uncomp_size = struct.unpack('<Q', chunk[5:13])[0]
    if uncomp_size > 0 and uncomp_size < 32*1024*1024:
        # Plausible LZMA header
        try:
            dec = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
            result = dec.decompress(chunk[:min(len(chunk), 2*1024*1024)])
            if len(result) > 1000:
                abs_off = 0x3000 + i
                print(f"\nLZMA at FV+0x{i:X} (abs 0x{abs_off:X}):")
                print(f"  Props: lc={lc} lp={lp} pb={pb}, Dict=0x{dict_size:X}")
                print(f"  Uncompressed size: {uncomp_size}")
                print(f"  Decompressed: {len(result)} bytes")

                with open('/tmp/abl_dec.bin', 'wb') as f:
                    f.write(result)

                # Search for strings
                for s in [b'Encrypted block', b'get_param_by_index', b'000OnePlus818000',
                          b'000OnePlus', b'sw_proj_id', b'init_param', b'verified success',
                          b'GetParam', b'carrier', b'param_key', b'AES']:
                    idx = result.find(s)
                    if idx >= 0:
                        start = idx
                        while start > 0 and result[start-1] != 0:
                            start -= 1
                        end = idx
                        while end < len(result) and result[end] != 0:
                            end += 1
                        txt = result[start:end].decode('utf-8', errors='replace')
                        print(f"  FOUND '{s.decode()}' at 0x{idx:X}: '{txt[:120]}'")

                found = True
                break
        except:
            pass

if not found:
    # Try broader search within whole FV
    print("\nTrying broader search in entire FV...")
    for i in range(0, len(fv_data) - 13, 4):
        chunk = fv_data[i:]
        props = chunk[0]
        lc = props % 9
        lp = (props // 9) % 5
        pb = (props // 9) // 5
        if lc > 4 or lp > 4 or pb > 4:
            continue
        dict_size = struct.unpack('<I', chunk[1:5])[0]
        if dict_size < 1024 or dict_size > 32*1024*1024:
            continue
        uncomp_size = struct.unpack('<Q', chunk[5:13])[0]
        if uncomp_size < 10000 or uncomp_size > 16*1024*1024:
            continue
        try:
            dec = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
            result = dec.decompress(chunk[:min(len(chunk), 2*1024*1024)])
            if len(result) > 10000:
                abs_off = 0x3000 + i
                print(f"\nLZMA at FV+0x{i:X} (abs 0x{abs_off:X}):")
                print(f"  Decompressed: {len(result)} bytes")
                has_strings = result.find(b'Encrypted') >= 0 or result.find(b'param') >= 0
                print(f"  Has param strings: {has_strings}")
                if has_strings:
                    with open('/tmp/abl_dec.bin', 'wb') as f:
                        f.write(result)
                    found = True
                    break
        except:
            pass

    if not found:
        print("No LZMA content found with expected strings")
