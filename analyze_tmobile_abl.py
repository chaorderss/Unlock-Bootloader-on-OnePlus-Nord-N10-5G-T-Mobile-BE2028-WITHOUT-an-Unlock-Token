#!/usr/bin/env python3
"""Decompress and analyze T-Mobile ABL to find AVB/boot verification code."""
import struct, re, sys, os

ABL_PATH = '/Users/xmxx/pinganhuijia/edl_backup/abl_b.img'
OUT_PATH = '/Users/xmxx/pinganhuijia/tmobile_abl_decompressed.bin'

def parse_ffs_walk(data, fv_start):
    fv_hdr_len = struct.unpack_from('<H', data, fv_start + 0x30)[0]
    fv_len = struct.unpack_from('<Q', data, fv_start + 0x20)[0]
    pos = fv_start + ((fv_hdr_len + 7) & ~7)
    FFS_HDR = 24
    files = []
    while pos + FFS_HDR <= fv_start + fv_len and pos + FFS_HDR <= len(data):
        raw_guid = data[pos:pos+16]
        if all(b == 0xFF for b in raw_guid): break
        if all(b == 0x00 for b in raw_guid): pos += 8; continue
        sz_bytes = data[pos+20:pos+23]
        size = sz_bytes[0] | (sz_bytes[1]<<8) | (sz_bytes[2]<<16)
        if size < FFS_HDR or pos + size > len(data): break
        ftype = data[pos+18]
        files.append((pos, size, ftype, raw_guid.hex()))
        pos = (pos + size + 7) & ~7
    return files

def try_decompress_section(data, sec_start):
    """Try to decompress EFI section"""
    try:
        import lzma
        # Skip 4-byte size + 1-byte type header for EFI_SECTION_COMPRESSION
        # Compression type at offset 3 of section: 0=none, 1=EFI, 2=LZMA
        comp_type = data[sec_start + 4]
        orig_size = struct.unpack_from('<I', data, sec_start)[0] & 0xFFFFFF
        payload = data[sec_start + 4 + 1:]  # after compression type byte... actually
        # EFI_COMMON_SECTION_HEADER: size[3] + type[1]
        # EFI_COMPRESSION_SECTION: uncomp_size[4] + comp_type[1] + data
        uncomp_size = struct.unpack_from('<I', data, sec_start + 4)[0]
        comp_type2 = data[sec_start + 8]
        compressed_data = data[sec_start + 9:]
        if comp_type2 == 2:  # LZMA
            result = lzma.decompress(compressed_data)
            return result
    except Exception as e:
        pass
    return None

with open(ABL_PATH, 'rb') as f:
    abl = bytearray(f.read())

print(f'ABL size: {len(abl):#x}')
print(f'ELF magic: {abl[:4].hex()}')

# Find all _FVH
fvh_positions = [m.start() - 0x28 for m in re.finditer(b'_FVH', abl)]
print(f'_FVH at: {[hex(p) for p in fvh_positions]}')

# Walk first FV
fv_start = fvh_positions[0]
files = parse_ffs_walk(abl, fv_start)
print(f'\nFFS files found: {len(files)}')
for i, (pos, size, ftype, guid) in enumerate(files):
    print(f'  [{i}] pos={hex(pos)} size={hex(size)} type={hex(ftype)} guid={guid[:16]}...')

# Try to find the PE32+ / compressed section
# Look for MZ header within FFS files
print('\nSearching for MZ/PE32+ in FFS files...')
for pos, size, ftype, guid in files:
    file_data = abl[pos:pos+size]
    mz_hits = [m.start() for m in re.finditer(b'MZ', file_data)]
    pe_hits = [m.start() for m in re.finditer(b'PE\x00\x00', file_data)]
    if mz_hits or pe_hits:
        print(f'  MZ at {[hex(pos+h) for h in mz_hits]}, PE at {[hex(pos+h) for h in pe_hits]}')

# Search for EFI compression sections within each FFS file
print('\nLooking for EFI_SECTION_COMPRESSION (type 0x01)...')
for fi, (fpos, fsize, ftype, guid) in enumerate(files):
    # walk sections within file
    spos = fpos + 24  # skip FFS header
    while spos < fpos + fsize:
        sec_size = abl[spos] | (abl[spos+1]<<8) | (abl[spos+2]<<16)
        sec_type = abl[spos+3]
        if sec_size == 0 or spos + sec_size > fpos + fsize:
            break
        if sec_type == 0x01:  # EFI_SECTION_COMPRESSION
            comp_type = abl[spos+8]
            uncomp_size = struct.unpack_from('<I', abl, spos+4)[0]
            print(f'  File[{fi}] sec at {hex(spos)}: comp_type={comp_type} uncomp_size={hex(uncomp_size)}')
            if comp_type == 2:  # LZMA
                import lzma
                try:
                    raw = bytes(abl[spos+9:spos+sec_size])
                    decomp = lzma.decompress(raw)
                    print(f'  -> LZMA decompressed: {len(decomp):#x} bytes')
                    with open(OUT_PATH, 'wb') as f:
                        f.write(decomp)
                    print(f'  -> Written to {OUT_PATH}')
                    # Search for AVB strings in decompressed data
                    for pat in [b'avb_verify', b'AVB_IO_RESULT', b'VERIFIED_BOOT',
                                b'verified boot', b'boot state', b'orange', b'red',
                                b'corrupted', b'hash mismatch', b'verification disabled',
                                b'skip_verification', b'cmdline', b'androidboot.verifiedbootstate']:
                        hits = [m.start() for m in re.finditer(re.escape(pat), decomp, re.I)]
                        if hits:
                            print(f'  STR "{pat}": {len(hits)} hits at {[hex(h) for h in hits[:3]]}')
                except Exception as e:
                    print(f'  LZMA error: {e}')
        spos = (spos + sec_size + 3) & ~3

# If we couldn't decompress, search raw ABL for strings compressed in lzma stream
if not os.path.exists(OUT_PATH):
    print('\nTrying raw LZMA scan...')
    import lzma
    # LZMA streams often start with 5d 00 00 xx xx
    for i in range(0, len(abl)-6, 4):
        if abl[i] == 0x5d and abl[i+1] == 0x00 and abl[i+2] == 0x00:
            size_hint = struct.unpack_from('<I', abl, i-4)[0] if i >= 4 else 0
            if 0x50000 < size_hint < 0x300000:
                try:
                    decomp = lzma.decompress(bytes(abl[i:i+size_hint+100]))
                    if len(decomp) > 0x40000:
                        print(f'Found LZMA at {hex(i)}: {len(decomp):#x} bytes decompressed')
                        with open(OUT_PATH, 'wb') as f:
                            f.write(decomp)
                        break
                except:
                    pass
