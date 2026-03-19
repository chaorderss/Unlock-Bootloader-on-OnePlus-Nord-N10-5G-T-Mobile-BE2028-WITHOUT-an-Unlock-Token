#!/usr/bin/env python3
"""Parse FV at correct offset and extract/decompress all PE sections."""
import struct, lzma
from binascii import hexlify

with open('/tmp/abl_a.bin', 'rb') as f:
    abl = f.read()

fv_start = 0x3000
fv_length = struct.unpack('<Q', abl[fv_start+0x20:fv_start+0x28])[0]
hdr_len = struct.unpack('<H', abl[fv_start+0x30:fv_start+0x32])[0]

print(f"FV at 0x{fv_start:X}, length=0x{fv_length:X}, hdr=0x{hdr_len:X}")

file_start = fv_start + hdr_len
fv_end = fv_start + fv_length
file_count = 0
all_decompressed = bytearray()

while file_start < fv_end:
    file_start = (file_start + 7) & ~7
    if file_start + 24 >= len(abl):
        break

    # Check for padding
    if all(b == 0xFF for b in abl[file_start:file_start+16]):
        break

    file_guid = abl[file_start:file_start+16]
    file_type = abl[file_start+18]
    file_size_bytes = abl[file_start+20:file_start+23]
    file_size = file_size_bytes[0] | (file_size_bytes[1] << 8) | (file_size_bytes[2] << 16)
    file_state = abl[file_start+23]

    if file_size <= 24 or file_size > 0x200000:
        break

    guid_str = f"{struct.unpack('<I', file_guid[:4])[0]:08x}-{struct.unpack('<H', file_guid[4:6])[0]:04x}-{struct.unpack('<H', file_guid[6:8])[0]:04x}-{file_guid[8:10].hex()}-{file_guid[10:16].hex()}"
    type_names = {1:"RAW", 2:"FREEFORM", 3:"SEC_CORE", 4:"PEI_CORE", 5:"DXE_CORE",
                  6:"PEIM", 7:"DRIVER", 8:"COMBINED", 9:"APPLICATION", 0xB:"FV_IMAGE"}
    type_str = type_names.get(file_type, f"type_0x{file_type:02X}")

    print(f"\nFile #{file_count} at 0x{file_start:X}: {type_str} size=0x{file_size:X} GUID={guid_str}")

    # Parse sections
    sec_start = file_start + 24
    while sec_start < file_start + file_size - 4:
        sec_size_bytes = abl[sec_start:sec_start+3]
        sec_size = sec_size_bytes[0] | (sec_size_bytes[1] << 8) | (sec_size_bytes[2] << 16)
        sec_type = abl[sec_start+3]

        if sec_size < 4 or sec_size > file_size:
            break

        sec_data = abl[sec_start+4:sec_start+sec_size]
        sec_names = {0x01:"COMPRESSION", 0x02:"GUID_DEFINED", 0x10:"PE32", 0x12:"TE",
                     0x13:"DXE_DEPEX", 0x14:"VERSION", 0x15:"UI", 0x17:"FV_IMAGE",
                     0x19:"RAW", 0x1B:"PEI_DEPEX"}
        sec_name = sec_names.get(sec_type, f"sec_0x{sec_type:02X}")

        print(f"  Section: {sec_name} size=0x{sec_size:X}")

        if sec_type == 0x15:  # UI (name string)
            try:
                name = sec_data.decode('utf-16le', errors='replace').rstrip('\x00')
                print(f"    Name: {name}")
            except:
                pass

        elif sec_type == 0x02:  # GUID_DEFINED
            if len(sec_data) >= 20:
                guid = sec_data[:16]
                data_offset = struct.unpack('<H', sec_data[16:18])[0]
                attrs = struct.unpack('<H', sec_data[18:20])[0]
                inner = sec_data[data_offset:]
                g = hexlify(guid).decode()
                print(f"    GUID={g} DataOff={data_offset} Attrs={attrs} InnerSize={len(inner)}")

                # Try LZMA (with various header offsets)
                for skip in [0, 5, 8, 13]:
                    try:
                        dec = lzma.decompress(inner[skip:])
                        print(f"    Decompressed (skip={skip}): {len(dec)} bytes")
                        all_decompressed.extend(dec)

                        # Quick search for key strings
                        for s in [b'Encrypted block', b'get_param_by_index', b'000OnePlus']:
                            idx = dec.find(s)
                            if idx >= 0:
                                print(f"    ** FOUND '{s.decode()}' at +0x{idx:X}")
                        break
                    except:
                        pass

        elif sec_type == 0x01:  # COMPRESSION
            if len(sec_data) >= 8:
                uncomp_size = struct.unpack('<I', sec_data[:4])[0]
                comp_type = struct.unpack('<I', sec_data[4:8])[0]
                comp_data = sec_data[8:]
                print(f"    UncompSize=0x{uncomp_size:X} CompType={comp_type}")

                if comp_type == 2:  # LZMA
                    for skip in [0, 5]:
                        try:
                            dec = lzma.decompress(comp_data[skip:])
                            print(f"    Decompressed: {len(dec)} bytes")
                            all_decompressed.extend(dec)
                            for s in [b'Encrypted block', b'000OnePlus']:
                                idx = dec.find(s)
                                if idx >= 0:
                                    print(f"    ** FOUND '{s.decode()}' at +0x{idx:X}")
                            break
                        except Exception as e:
                            pass
                elif comp_type == 1:  # EFI Standard (Tiano)
                    print(f"    Tiano compression (not supported)")
                elif comp_type == 0:  # Not compressed
                    all_decompressed.extend(comp_data)

        elif sec_type == 0x10:  # PE32
            all_decompressed.extend(sec_data)
            for s in [b'Encrypted block', b'000OnePlus']:
                idx = sec_data.find(s)
                if idx >= 0:
                    print(f"    ** FOUND '{s.decode()}' in PE at +0x{idx:X}")

        elif sec_type == 0x12:  # TE
            all_decompressed.extend(sec_data)

        sec_start = (sec_start + sec_size + 3) & ~3

    file_start += file_size
    file_count += 1
    if file_count > 100:
        break

print(f"\n=== Summary ===")
print(f"Files found: {file_count}")
print(f"Total extracted/decompressed: {len(all_decompressed)} bytes")

if all_decompressed:
    with open('/tmp/abl_all_sections.bin', 'wb') as f:
        f.write(all_decompressed)
    print(f"Saved to /tmp/abl_all_sections.bin")

    # Final search
    print("\n=== Searching all extracted content ===")
    for s in [b'Encrypted block', b'get_param_by_index', b'sw_proj_id',
              b'000OnePlus818000', b'000OnePlus', b'OnePlus818',
              b'init_param_sw', b'check and restore', b'SoftwareProject',
              b'carrier', b'GetParam', b'verified success']:
        idx = all_decompressed.find(s)
        if idx >= 0:
            start = idx
            while start > 0 and all_decompressed[start-1] != 0:
                start -= 1
            end = idx
            while end < len(all_decompressed) and all_decompressed[end] != 0:
                end += 1
            txt = bytes(all_decompressed[start:end]).decode('utf-8', errors='replace')
            print(f"  '{s.decode()}' at 0x{idx:X}: '{txt[:120]}'")
        else:
            print(f"  '{s.decode()}': not found")
