#!/usr/bin/env python3
"""Parse T-Mobile ABL FFS sections and decompress the PE32+ code."""
import struct, re, sys, lzma

ABL_PATH = '/Users/xmxx/pinganhuijia/edl_backup/abl_b.img'
OUT_PATH = '/Users/xmxx/pinganhuijia/tmobile_abl_decompressed.bin'

with open(ABL_PATH, 'rb') as f:
    abl = bytearray(f.read())

# The single FFS file wraps an inner FV
ffs_pos = 0x3048
ffs_hdr = 24
spos = ffs_pos + ffs_hdr

# Walk sections in the FFS file
print('Sections in outer FFS:')
while spos < len(abl) - 4:
    sec_size = abl[spos] | (abl[spos+1]<<8) | (abl[spos+2]<<16)
    sec_type = abl[spos+3]
    if sec_size < 4:
        break
    type_names = {0x01:'COMPRESSION', 0x02:'GUID_DEFINED', 0x10:'PE32',
                  0x11:'PIC', 0x17:'FV_IMAGE', 0x19:'RAW', 0x15:'USER_INTERFACE'}
    print(f'  sec@{hex(spos)}: type=0x{sec_type:02x}({type_names.get(sec_type,"?")}) size={hex(sec_size)}')

    if sec_type == 0x17:  # EFI_SECTION_FIRMWARE_VOLUME_IMAGE - inner FV
        inner_fv_start = spos + 4
        inner_magic = abl[inner_fv_start+0x28:inner_fv_start+0x2C]
        print(f'    Inner FV magic: {inner_magic}')
        if inner_magic == b'_FVH':
            # Walk inner FV
            inner_hdr_len = struct.unpack_from('<H', abl, inner_fv_start + 0x30)[0]
            inner_fv_len = struct.unpack_from('<Q', abl, inner_fv_start + 0x20)[0]
            print(f'    Inner FV: hdrlen={inner_hdr_len} fvlen={hex(inner_fv_len)}')
            ipos = inner_fv_start + inner_hdr_len
            while ipos < inner_fv_start + inner_fv_len - 24 and ipos < len(abl) - 24:
                ig = abl[ipos:ipos+16]
                if all(b==0xFF for b in ig): break
                if all(b==0x00 for b in ig): ipos+=8; continue
                isz_b = abl[ipos+20:ipos+23]
                isz = isz_b[0]|(isz_b[1]<<8)|(isz_b[2]<<16)
                ift = abl[ipos+18]
                print(f'    FFS@{hex(ipos)}: type={hex(ift)} size={hex(isz)} guid={ig[:8].hex()}')
                if isz < 24: break
                # Walk sections in inner FFS file
                isecpos = ipos + 24
                while isecpos < ipos + isz - 4:
                    isec_sz = abl[isecpos]|(abl[isecpos+1]<<8)|(abl[isecpos+2]<<16)
                    isec_type = abl[isecpos+3]
                    if isec_sz < 4: break
                    print(f'      sec@{hex(isecpos)}: type=0x{isec_type:02x} size={hex(isec_sz)}')
                    if isec_type == 0x02:  # GUID_DEFINED
                        guid = abl[isecpos+4:isecpos+20].hex()
                        print(f'        GUID={guid}')
                        # LZMA GUID: ee4e5898-3914-4259-9d6e-dc7bd79403cf
                        if guid.startswith('98584eee'):
                            data_off = struct.unpack_from('<H', abl, isecpos+20)[0]
                            payload = bytes(abl[isecpos+data_off:isecpos+isec_sz])
                            print(f'        Trying LZMA decompress, payload={len(payload):#x} bytes')
                            try:
                                decomp = lzma.decompress(payload)
                                print(f'        SUCCESS: {len(decomp):#x} bytes decompressed')
                                with open(OUT_PATH, 'wb') as fw:
                                    fw.write(decomp)
                                print(f'        Written to {OUT_PATH}')
                            except Exception as e:
                                print(f'        LZMA failed: {e}')
                    if isec_type == 0x01:  # COMPRESSION
                        comp_type = abl[isecpos+8]
                        uncomp_size = struct.unpack_from('<I', abl, isecpos+4)[0]
                        print(f'        comp_type={comp_type} uncomp_size={hex(uncomp_size)}')
                        if comp_type == 2:
                            payload = bytes(abl[isecpos+9:isecpos+isec_sz])
                            try:
                                decomp = lzma.decompress(payload)
                                print(f'        SUCCESS LZMA: {len(decomp):#x} bytes')
                                with open(OUT_PATH, 'wb') as fw:
                                    fw.write(decomp)
                            except Exception as e:
                                print(f'        LZMA failed: {e}')
                    if isec_type == 0x10:  # PE32 directly
                        print(f'        PE32 directly at {hex(isecpos+4)}')
                        pe_data = abl[isecpos+4:isecpos+isec_sz]
                        with open(OUT_PATH, 'wb') as fw:
                            fw.write(pe_data)
                    isecpos = (isecpos + isec_sz + 3) & ~3
                ipos = (ipos + isz + 7) & ~7

    spos = (spos + sec_size + 3) & ~3

# If still not found, try: the MZ headers in raw ABL might be PE32+ directly
if not __import__('os').path.exists(OUT_PATH):
    print('\nTrying direct PE32+ extraction from raw ABL...')
    # Find largest MZ
    mz_hits = [(m.start(), ) for m in re.finditer(b'MZ', abl)]
    for (off,) in mz_hits:
        if off + 0x40 >= len(abl): continue
        pe_off_rel = struct.unpack_from('<I', abl, off+0x3C)[0]
        pe_abs = off + pe_off_rel
        if pe_abs + 4 >= len(abl): continue
        if abl[pe_abs:pe_abs+4] == b'PE\x00\x00':
            machine = struct.unpack_from('<H', abl, pe_abs+4)[0]
            num_sec = struct.unpack_from('<H', abl, pe_abs+6)[0]
            if machine == 0xAA64 and 1 <= num_sec <= 20:
                print(f'  ARM64 PE32+ at {hex(off)}, {num_sec} sections')
