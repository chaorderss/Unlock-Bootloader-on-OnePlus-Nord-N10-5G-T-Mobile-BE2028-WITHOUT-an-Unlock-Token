#!/usr/bin/env python3
"""Analyze FV structure in ABL and find/decompress PE sections."""
import struct, lzma, io
from binascii import hexlify

with open('/tmp/abl_a.bin', 'rb') as f:
    abl = f.read()

# FV at 0x3028
fv_start = 0x3028
print(f"=== FV at 0x{fv_start:X} ===")
# EFI_FIRMWARE_VOLUME_HEADER
# 16 bytes: ZeroVector
# 16 bytes: FileSystemGuid
# 8 bytes: FvLength
# 4 bytes: Signature (_FVH)
# ...
fv_sig = abl[fv_start+0x28:fv_start+0x2C]
print(f"FV Signature: {fv_sig}")
fv_length = struct.unpack('<Q', abl[fv_start+0x20:fv_start+0x28])[0]
print(f"FV Length: 0x{fv_length:X} ({fv_length//1024} KB)")
fv_hdr_len = struct.unpack('<H', abl[fv_start+0x30:fv_start+0x32])[0]
print(f"FV Header Length: 0x{fv_hdr_len:X}")

# Iterate FV files
file_start = fv_start + fv_hdr_len
print(f"\n=== FV Files ===")
file_count = 0
while file_start < fv_start + fv_length:
    # Align to 8 bytes
    file_start = (file_start + 7) & ~7
    if file_start + 24 >= len(abl):
        break

    # EFI_FFS_FILE_HEADER
    # 16 bytes: Name (GUID)
    # 1 byte: IntegrityCheck.Header
    # 1 byte: IntegrityCheck.File
    # 1 byte: Type
    # 1 byte: Attributes
    # 3 bytes: Size (24-bit LE)
    # 1 byte: State
    file_guid = abl[file_start:file_start+16]
    file_type = abl[file_start+18]
    file_attrs = abl[file_start+19]
    file_size_bytes = abl[file_start+20:file_start+23]
    file_size = file_size_bytes[0] | (file_size_bytes[1] << 8) | (file_size_bytes[2] << 16)
    file_state = abl[file_start+23]

    if file_size == 0 or file_size == 0xFFFFFF:
        break

    guid_str = f"{struct.unpack('<I', file_guid[:4])[0]:08X}-{struct.unpack('<H', file_guid[4:6])[0]:04X}-{struct.unpack('<H', file_guid[6:8])[0]:04X}-{file_guid[8:10].hex()}-{file_guid[10:16].hex()}"
    type_names = {1: "RAW", 2: "FREEFORM", 3: "SECURITY_CORE", 4: "PEI_CORE", 5: "DXE_CORE",
                  6: "PEIM", 7: "DRIVER", 8: "COMBINED_PEIM_DRIVER", 9: "APPLICATION", 0xB: "FV_IMAGE"}
    type_str = type_names.get(file_type, f"0x{file_type:02X}")

    print(f"\nFile #{file_count} at 0x{file_start:X}: GUID={guid_str}")
    print(f"  Type={type_str}, Size=0x{file_size:X} ({file_size} bytes), State=0x{file_state:02X}")

    # Parse sections within this file
    sec_start = file_start + 24  # Past FFS header
    while sec_start < file_start + file_size:
        if sec_start + 4 >= len(abl):
            break
        sec_size_bytes = abl[sec_start:sec_start+3]
        sec_size = sec_size_bytes[0] | (sec_size_bytes[1] << 8) | (sec_size_bytes[2] << 16)
        sec_type = abl[sec_start+3]

        if sec_size == 0 or sec_size == 0xFFFFFF:
            break

        sec_type_names = {
            0x01: "COMPRESSION", 0x02: "GUID_DEFINED", 0x10: "PE32",
            0x11: "PIC", 0x12: "TE", 0x13: "DXE_DEPEX", 0x14: "VERSION",
            0x15: "USER_INTERFACE", 0x16: "COMPATIBILITY16", 0x17: "FV_IMAGE",
            0x18: "FREEFORM_SUBTYPE_GUID", 0x19: "RAW", 0x1B: "PEI_DEPEX"
        }
        sec_type_str = sec_type_names.get(sec_type, f"0x{sec_type:02X}")

        sec_data_start = sec_start + 4
        sec_data = abl[sec_data_start:sec_start + sec_size]

        print(f"  Section at 0x{sec_start:X}: type={sec_type_str}, size=0x{sec_size:X}")

        if sec_type == 0x01:  # COMPRESSION
            comp_type = struct.unpack('<I', sec_data[4:8])[0] if len(sec_data) > 8 else -1
            uncomp_size = struct.unpack('<I', sec_data[:4])[0] if len(sec_data) > 4 else 0
            print(f"    Uncompressed size: 0x{uncomp_size:X}, CompType: {comp_type}")

            # Try LZMA decompression on data after the 8-byte compression header
            comp_data = sec_data[8:]
            try:
                decompressed = lzma.decompress(comp_data)
                print(f"    LZMA decompressed: {len(decompressed)} bytes")
                # Search decompressed data for our strings
                for s in [b'Encrypted block', b'get_param_by_index', b'OnePlus818',
                          b'000OnePlus', b'sw_proj_id', b'init_param',
                          b'AES', b'decrypt']:
                    idx = decompressed.find(s)
                    if idx >= 0:
                        # Get context
                        ctx_start = idx
                        while ctx_start > 0 and decompressed[ctx_start-1] != 0:
                            ctx_start -= 1
                        ctx_end = idx
                        while ctx_end < len(decompressed) and decompressed[ctx_end] != 0:
                            ctx_end += 1
                        txt = decompressed[ctx_start:ctx_end].decode('utf-8', errors='replace')
                        print(f"    FOUND '{s.decode()}' at dec+0x{idx:X}: '{txt[:100]}'")

                # Save decompressed data
                with open('/tmp/abl_decompressed.bin', 'wb') as f:
                    f.write(decompressed)
                print(f"    Saved to /tmp/abl_decompressed.bin")
            except Exception as e:
                print(f"    LZMA failed: {e}")
                # Try standard zlib/deflate
                import zlib
                try:
                    decompressed = zlib.decompress(comp_data)
                    print(f"    zlib decompressed: {len(decompressed)} bytes")
                except:
                    # Try EFI Standard Compression (Tiano)
                    print(f"    First 16 bytes of compressed: {hexlify(comp_data[:16]).decode()}")

        elif sec_type == 0x02:  # GUID_DEFINED
            # 16-byte GUID + 2 byte DataOffset + 2 byte Attributes
            if len(sec_data) >= 20:
                guid = sec_data[:16]
                data_offset = struct.unpack('<H', sec_data[16:18])[0]
                attrs = struct.unpack('<H', sec_data[18:20])[0]
                guid_str = f"{struct.unpack('<I', guid[:4])[0]:08X}-{struct.unpack('<H', guid[4:6])[0]:04X}"
                print(f"    GUID={guid_str}..., DataOffset={data_offset}, Attrs={attrs}")

                inner_data = sec_data[data_offset:]
                # Try LZMA
                if len(inner_data) > 8:
                    try:
                        decompressed = lzma.decompress(inner_data)
                        print(f"    GUID LZMA decompressed: {len(decompressed)} bytes")
                        for s in [b'Encrypted block', b'get_param_by_index', b'000OnePlus']:
                            idx = decompressed.find(s)
                            if idx >= 0:
                                print(f"    FOUND '{s.decode()}' at dec+0x{idx:X}")
                        with open('/tmp/abl_guid_decompressed.bin', 'wb') as f:
                            f.write(decompressed)
                        print(f"    Saved to /tmp/abl_guid_decompressed.bin")
                    except:
                        pass

        elif sec_type == 0x10:  # PE32
            # Check for MZ header
            if len(sec_data) > 2 and sec_data[:2] == b'MZ':
                print(f"    PE32 found, size={len(sec_data)}")
                for s in [b'Encrypted block', b'000OnePlus']:
                    idx = sec_data.find(s)
                    if idx >= 0:
                        print(f"    FOUND '{s.decode()}' in PE")

        # Move to next section (aligned to 4 bytes)
        sec_start = (sec_start + sec_size + 3) & ~3

    file_start += file_size
    file_count += 1
    if file_count > 50:
        break

print(f"\nTotal files found: {file_count}")
