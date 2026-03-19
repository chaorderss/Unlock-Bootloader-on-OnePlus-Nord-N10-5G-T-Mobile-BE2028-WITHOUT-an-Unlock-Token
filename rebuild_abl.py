#!/usr/bin/env python3
"""
Patch Global ABL to bypass unlock token check, then rebuild the full ABL image.

Patch: Change B.EQ (54000080) at decompressed offset 0x3bc7c to NOP (D503201F)

Structure of ABL image:
  ELF header -> program headers -> UEFI Firmware Volume payload
  FV -> FFS file -> GuidDefinedSection (LZMA compressed) -> inner FV -> PE32+

We need to:
1. Parse the ELF to find the FV payload
2. Parse the FV to find the FFS file
3. Parse the FFS to find the GuidDefinedSection
4. Decompress the LZMA data
5. Apply our patch to the decompressed data
6. Recompress with LZMA
7. Rebuild all headers with correct sizes and checksums
8. Write the patched ABL image
"""

import struct
import lzma
import os
import sys

RAW_ABL = '/Users/xmxx/pinganhuijia/global_abl.img'
OUTPUT_ABL = '/Users/xmxx/pinganhuijia/global_abl_patched.img'
OUTPUT_PADDED = '/Users/xmxx/pinganhuijia/global_abl_patched_padded.img'

# The patch: at decompressed offset 0x3bc7c, change B.EQ to NOP
PATCH_OFFSET = 0x3bc7c
PATCH_OLD = struct.pack('<I', 0x54000080)  # B.EQ
PATCH_NEW = struct.pack('<I', 0xd503201f)  # NOP

def read_file(path):
    with open(path, 'rb') as f:
        return bytearray(f.read())

def write_file(path, data):
    with open(path, 'wb') as f:
        f.write(data)
    print('Written ' + str(len(data)) + ' bytes to ' + path)

def checksum8(data):
    """Calculate 8-bit checksum (sum of all bytes mod 256 = 0)"""
    return (-sum(data)) & 0xFF

def fv_checksum16(data):
    """Calculate 16-bit FV header checksum"""
    s = 0
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            s += struct.unpack_from('<H', data, i)[0]
        else:
            s += data[i]
    return (-s) & 0xFFFF

def parse_elf(data):
    """Parse ELF header, return list of (offset, size) for LOAD segments"""
    magic = data[:4]
    assert magic == b'\x7fELF', 'Not an ELF file'

    ei_class = data[4]  # 1=32bit, 2=64bit
    print('ELF class: ' + ('64-bit' if ei_class == 2 else '32-bit'))

    if ei_class == 2:
        e_phoff = struct.unpack_from('<Q', data, 32)[0]
        e_phentsize = struct.unpack_from('<H', data, 54)[0]
        e_phnum = struct.unpack_from('<H', data, 56)[0]
    else:
        e_phoff = struct.unpack_from('<I', data, 28)[0]
        e_phentsize = struct.unpack_from('<H', data, 42)[0]
        e_phnum = struct.unpack_from('<H', data, 44)[0]

    print('  phoff=' + hex(e_phoff) + ' phentsize=' + str(e_phentsize) + ' phnum=' + str(e_phnum))

    segments = []
    for i in range(e_phnum):
        ph_off = e_phoff + i * e_phentsize
        if ei_class == 2:
            p_type = struct.unpack_from('<I', data, ph_off)[0]
            p_offset = struct.unpack_from('<Q', data, ph_off + 8)[0]
            p_filesz = struct.unpack_from('<Q', data, ph_off + 32)[0]
            p_memsz = struct.unpack_from('<Q', data, ph_off + 40)[0]
        else:
            p_type = struct.unpack_from('<I', data, ph_off)[0]
            p_offset = struct.unpack_from('<I', data, ph_off + 4)[0]
            p_filesz = struct.unpack_from('<I', data, ph_off + 16)[0]
            p_memsz = struct.unpack_from('<I', data, ph_off + 20)[0]

        print('  Segment ' + str(i) + ': type=' + hex(p_type) + ' offset=' + hex(p_offset) +
              ' filesz=' + hex(p_filesz) + ' memsz=' + hex(p_memsz))
        segments.append((p_type, p_offset, p_filesz, p_memsz, ph_off))

    return ei_class, segments

def find_fv(data, start, size):
    """Find UEFI Firmware Volume at the given offset"""
    # FV signature _FVH at offset +0x28
    sig_off = start + 0x28
    sig = data[sig_off:sig_off+4]
    if sig != b'_FVH':
        # Search for it
        idx = data.find(b'_FVH', start, start + size)
        if idx < 0:
            print('ERROR: _FVH signature not found')
            return None
        start = idx - 0x28
        print('  Found _FVH at adjusted start ' + hex(start))

    fv_len = struct.unpack_from('<Q', data, start + 0x20)[0]
    hdr_len = struct.unpack_from('<H', data, start + 0x30)[0]

    print('  FV at ' + hex(start) + ': length=' + hex(fv_len) + ' hdr_len=' + hex(hdr_len))
    return start, fv_len, hdr_len

def find_ffs_and_section(data, fv_start, fv_hdr_len, fv_len):
    """Find first FFS file and its GuidDefinedSection with compressed data"""

    off = fv_start + fv_hdr_len
    fv_end = fv_start + fv_len

    while off < fv_end - 24:
        # FFS file header: 16 bytes GUID + 2 bytes integrity + 1 byte type + 1 byte attrs + 3 bytes size + 1 byte state
        ffs_guid = data[off:off+16]
        ffs_type = data[off + 18]
        ffs_attrs = data[off + 19]
        ffs_size = struct.unpack_from('<I', data, off + 20)[0] & 0xFFFFFF  # 3 bytes
        ffs_state = data[off + 23]

        if ffs_type == 0xFF or ffs_size == 0 or ffs_size == 0xFFFFFF:
            break

        print('  FFS at ' + hex(off) + ': type=' + hex(ffs_type) + ' size=' + hex(ffs_size) + ' state=' + hex(ffs_state))
        print('   GUID: ' + ffs_guid.hex())

        # Parse sections within FFS
        ffs_hdr_size = 24
        sec_off = off + ffs_hdr_size
        ffs_end = off + ffs_size

        while sec_off < ffs_end - 4:
            sec_size = struct.unpack_from('<I', data, sec_off)[0] & 0xFFFFFF
            sec_type = data[sec_off + 3]

            if sec_size == 0 or sec_size > ffs_end - sec_off:
                break

            print('    Section at ' + hex(sec_off) + ': type=' + hex(sec_type) + ' size=' + hex(sec_size))

            # Type 0x02 = GUID_DEFINED section (compressed)
            if sec_type == 0x02:
                # GuidDefined header: 4 bytes common + 16 bytes GUID + 2 bytes data_offset + 2 bytes attrs
                guid = data[sec_off+4:sec_off+20]
                data_offset = struct.unpack_from('<H', data, sec_off + 20)[0]
                attrs = struct.unpack_from('<H', data, sec_off + 22)[0]
                print('      GuidDefined GUID: ' + guid.hex())
                print('      Data offset: ' + hex(data_offset) + ' Attrs: ' + hex(attrs))

                compressed_start = sec_off + data_offset
                compressed_size = sec_size - data_offset
                print('      Compressed data: ' + hex(compressed_start) + ' size=' + hex(compressed_size))

                return {
                    'ffs_off': off,
                    'ffs_size': ffs_size,
                    'ffs_hdr_size': ffs_hdr_size,
                    'sec_off': sec_off,
                    'sec_size': sec_size,
                    'sec_type': sec_type,
                    'guid_data_offset': data_offset,
                    'compressed_start': compressed_start,
                    'compressed_size': compressed_size,
                    'guid': guid,
                }

            # Type 0x19 = RAW section
            if sec_type == 0x19:
                print('    (RAW section, skipping)')

            # Align to 4 bytes
            sec_off += (sec_size + 3) & ~3

        # Move to next FFS file (4-byte aligned)
        off += (ffs_size + 7) & ~7  # FFS files are 8-byte aligned in FV

    return None

def try_decompress(data):
    """Try to decompress LZMA data with various methods"""

    # Method 1: Standard LZMA
    try:
        result = lzma.decompress(data)
        print('  Decompressed with standard LZMA: ' + str(len(result)) + ' bytes')
        return result
    except Exception as e:
        print('  Standard LZMA failed: ' + str(e))

    # Method 2: LZMA with raw decoder (UEFI typically uses raw LZMA stream)
    # UEFI LZMA format: 5 bytes props + 8 bytes uncompressed size + compressed data
    if len(data) >= 13:
        props = data[0]
        dict_size = struct.unpack_from('<I', data, 1)[0]
        uncomp_size = struct.unpack_from('<Q', data, 5)[0]
        print('  LZMA props: ' + hex(props) + ' dict_size=' + hex(dict_size) + ' uncomp_size=' + hex(uncomp_size))

        try:
            # Create LZMA decompressor with the properties from the stream
            lc = props % 9
            rest = props // 9
            lp = rest % 5
            pb = rest // 5

            filters = [{'id': lzma.FILTER_LZMA1, 'dict_size': dict_size, 'lc': lc, 'lp': lp, 'pb': pb}]
            dec = lzma.decompress(data[13:], format=lzma.FORMAT_RAW, filters=filters)
            print('  Decompressed with raw LZMA1: ' + str(len(dec)) + ' bytes')
            if len(dec) != uncomp_size:
                print('  WARNING: size mismatch! expected ' + hex(uncomp_size) + ' got ' + hex(len(dec)))
            return dec
        except Exception as e:
            print('  Raw LZMA1 failed: ' + str(e))

        # Method 3: Try with full header (5+8 bytes)
        try:
            filters = [{'id': lzma.FILTER_LZMA1, 'dict_size': dict_size, 'lc': lc, 'lp': lp, 'pb': pb}]
            dec = lzma.decompress(data[5:], format=lzma.FORMAT_RAW, filters=filters)
            print('  Decompressed with raw LZMA1 (skip 5): ' + str(len(dec)) + ' bytes')
            return dec
        except Exception as e:
            print('  Raw LZMA1 (skip 5) failed: ' + str(e))

    # Method 4: Try as LZMA_ALONE format
    try:
        dec = lzma.decompress(data, format=lzma.FORMAT_ALONE)
        print('  Decompressed with LZMA_ALONE: ' + str(len(dec)) + ' bytes')
        return dec
    except Exception as e:
        print('  LZMA_ALONE failed: ' + str(e))

    # Method 5: Skip potential extra headers
    for skip in [0, 4, 8, 12, 16, 20, 24]:
        try:
            dec = lzma.decompress(data[skip:], format=lzma.FORMAT_ALONE)
            print('  Decompressed with LZMA_ALONE skip=' + str(skip) + ': ' + str(len(dec)) + ' bytes')
            return dec
        except:
            pass

    return None

def compress_lzma_uefi(data, orig_props, orig_dict_size):
    """Compress data in UEFI LZMA format (5 bytes props + 8 bytes size + stream)"""
    lc = orig_props % 9
    rest = orig_props // 9
    lp = rest % 5
    pb = rest // 5

    filters = [{'id': lzma.FILTER_LZMA1, 'dict_size': orig_dict_size, 'lc': lc, 'lp': lp, 'pb': pb}]
    compressed = lzma.compress(data, format=lzma.FORMAT_RAW, filters=filters)

    # Build UEFI LZMA header: 5 bytes props + 8 bytes uncompressed size
    header = bytes([orig_props]) + struct.pack('<I', orig_dict_size) + struct.pack('<Q', len(data))
    return header + compressed

def main():
    print('=== ABL Patch & Rebuild Tool ===\n')

    data = read_file(RAW_ABL)
    print('Loaded raw ABL: ' + str(len(data)) + ' bytes\n')

    # Step 1: Parse ELF
    print('--- Step 1: Parse ELF ---')
    ei_class, segments = parse_elf(data)

    # Find the LOAD segment with the FV payload (usually the largest or second segment)
    fv_segment = None
    for seg in segments:
        if seg[0] == 1 and seg[2] > 0:  # PT_LOAD with nonzero file size
            if fv_segment is None or seg[2] > fv_segment[2]:
                fv_segment = seg

    if not fv_segment:
        print('ERROR: No LOAD segment found')
        return

    print('\nUsing segment at offset ' + hex(fv_segment[1]) + ' size ' + hex(fv_segment[2]))

    # Step 2: Find FV
    print('\n--- Step 2: Find Firmware Volume ---')
    fv_info = find_fv(data, fv_segment[1], fv_segment[2])
    if not fv_info:
        return
    fv_start, fv_len, fv_hdr_len = fv_info

    # Step 3: Find FFS and compressed section
    print('\n--- Step 3: Find FFS + GuidDefinedSection ---')
    sec_info = find_ffs_and_section(data, fv_start, fv_hdr_len, fv_len)
    if not sec_info:
        print('ERROR: Could not find compressed section')
        return

    # Step 4: Decompress
    print('\n--- Step 4: Decompress ---')
    comp_data = bytes(data[sec_info['compressed_start']:sec_info['compressed_start'] + sec_info['compressed_size']])
    print('Compressed data starts with: ' + comp_data[:20].hex())

    # Save LZMA properties for recompression
    lzma_props = comp_data[0]
    lzma_dict_size = struct.unpack_from('<I', comp_data, 1)[0]

    decompressed = try_decompress(comp_data)
    if decompressed is None:
        print('ERROR: All decompression methods failed')
        return

    decompressed = bytearray(decompressed)

    # Verify this is the data we expect by checking for the patch target
    verify_seq = struct.pack('<I', 0xd65f03c0) + struct.pack('<I', 0x97fff219) + struct.pack('<I', 0x72001c1f) + struct.pack('<I', 0x54000080)
    verify_idx = decompressed.find(verify_seq)
    if verify_idx < 0:
        print('ERROR: Could not find target instruction sequence in decompressed data')
        # Try to find it with just the B.EQ + surrounding
        short_seq = struct.pack('<I', 0x72001c1f) + struct.pack('<I', 0x54000080) + struct.pack('<I', 0x320003e0)
        verify_idx2 = decompressed.find(short_seq)
        if verify_idx2 >= 0:
            print('  Found shorter sequence at ' + hex(verify_idx2) + ', patch offset would be ' + hex(verify_idx2 + 4))
            PATCH_OFFSET_ACTUAL = verify_idx2 + 4
        else:
            print('  Short sequence also not found. Cannot patch.')
            return
    else:
        PATCH_OFFSET_ACTUAL = verify_idx + 12  # 3 instructions in
        print('Found target sequence at ' + hex(verify_idx) + ', B.EQ at ' + hex(PATCH_OFFSET_ACTUAL))

    # Step 5: Apply patch
    print('\n--- Step 5: Apply Patch ---')
    old_insn = decompressed[PATCH_OFFSET_ACTUAL:PATCH_OFFSET_ACTUAL+4]
    print('Old instruction at ' + hex(PATCH_OFFSET_ACTUAL) + ': ' + old_insn.hex() + ' (' + hex(struct.unpack('<I', old_insn)[0]) + ')')
    assert old_insn == PATCH_OLD, 'Unexpected instruction at patch offset!'

    decompressed[PATCH_OFFSET_ACTUAL:PATCH_OFFSET_ACTUAL+4] = PATCH_NEW
    new_insn = decompressed[PATCH_OFFSET_ACTUAL:PATCH_OFFSET_ACTUAL+4]
    print('New instruction: ' + new_insn.hex() + ' (' + hex(struct.unpack('<I', new_insn)[0]) + ') = NOP')

    # Step 6: Recompress
    print('\n--- Step 6: Recompress ---')
    new_compressed = compress_lzma_uefi(bytes(decompressed), lzma_props, lzma_dict_size)
    print('New compressed size: ' + hex(len(new_compressed)) + ' (was ' + hex(sec_info['compressed_size']) + ')')

    size_diff = len(new_compressed) - sec_info['compressed_size']
    print('Size difference: ' + str(size_diff) + ' bytes')

    # Step 7: Rebuild
    print('\n--- Step 7: Rebuild ABL image ---')

    output = bytearray(data)

    # Replace compressed data
    old_comp_start = sec_info['compressed_start']
    old_comp_end = old_comp_start + sec_info['compressed_size']

    # Build new image: before_compressed + new_compressed + after_compressed
    before = data[:old_comp_start]
    after = data[old_comp_end:]
    output = bytearray(before) + bytearray(new_compressed) + bytearray(after)

    # Update section size
    new_sec_size = sec_info['guid_data_offset'] + len(new_compressed)
    sec_off = sec_info['sec_off']
    # Section header: 3 bytes size (LE) + 1 byte type
    # Adjust sec_off in new output (same position since before_compressed preserves offsets)
    output[sec_off] = new_sec_size & 0xFF
    output[sec_off + 1] = (new_sec_size >> 8) & 0xFF
    output[sec_off + 2] = (new_sec_size >> 16) & 0xFF
    print('  Updated section size: ' + hex(new_sec_size))

    # Update FFS file size
    ffs_off = sec_info['ffs_off']
    new_ffs_size = sec_info['ffs_hdr_size'] + ((new_sec_size + 3) & ~3)  # pad section to 4-byte align
    output[ffs_off + 20] = new_ffs_size & 0xFF
    output[ffs_off + 21] = (new_ffs_size >> 8) & 0xFF
    output[ffs_off + 22] = (new_ffs_size >> 16) & 0xFF
    print('  Updated FFS size: ' + hex(new_ffs_size))

    # Recalculate FFS header checksum (byte at offset 16 in FFS header)
    # FFS integrity check: checksum of header bytes (offset 0-22, skipping byte 16 [IntegrityCheck.File] and byte 23 [State])
    ffs_hdr_for_check = bytearray(output[ffs_off:ffs_off+24])
    ffs_hdr_for_check[16] = 0  # zero out file checksum field for calculation
    ffs_hdr_for_check[17] = 0  # zero out data checksum field
    ffs_hdr_for_check[23] = 0  # zero out state
    output[ffs_off + 16] = checksum8(ffs_hdr_for_check)
    output[ffs_off + 17] = 0xAA  # FFS_FIXED_CHECKSUM (typical for UEFI)
    print('  Updated FFS header checksum: ' + hex(output[ffs_off + 16]))

    # Update FV length
    fv_start_in_output = fv_start  # same position
    old_fv_len = fv_len
    new_fv_len = old_fv_len + size_diff
    struct.pack_into('<Q', output, fv_start_in_output + 0x20, new_fv_len)
    print('  Updated FV length: ' + hex(new_fv_len) + ' (was ' + hex(old_fv_len) + ')')

    # Recalculate FV header checksum
    fv_hdr = bytearray(output[fv_start_in_output:fv_start_in_output + fv_hdr_len])
    # Zero out the checksum field at offset 0x32 (2 bytes) before recalculating
    fv_hdr[0x32] = 0
    fv_hdr[0x33] = 0
    fv_cksum = fv_checksum16(fv_hdr)
    struct.pack_into('<H', output, fv_start_in_output + 0x32, fv_cksum)
    print('  Updated FV header checksum: ' + hex(fv_cksum))

    # Update ELF program header file size
    for seg in segments:
        if seg[0] == 1 and seg[2] > 0:
            ph_off = seg[4]
            if ei_class == 2:
                # p_filesz at ph_off+32, p_memsz at ph_off+40
                old_filesz = struct.unpack_from('<Q', output, ph_off + 32)[0]
                new_filesz = old_filesz + size_diff
                struct.pack_into('<Q', output, ph_off + 32, new_filesz)
                old_memsz = struct.unpack_from('<Q', output, ph_off + 40)[0]
                new_memsz = old_memsz + size_diff
                struct.pack_into('<Q', output, ph_off + 40, new_memsz)
                print('  Updated ELF segment filesz: ' + hex(new_filesz) + ' memsz: ' + hex(new_memsz))
            else:
                old_filesz = struct.unpack_from('<I', output, ph_off + 16)[0]
                new_filesz = old_filesz + size_diff
                struct.pack_into('<I', output, ph_off + 16, new_filesz)
                old_memsz = struct.unpack_from('<I', output, ph_off + 20)[0]
                new_memsz = old_memsz + size_diff
                struct.pack_into('<I', output, ph_off + 20, new_memsz)
                print('  Updated ELF segment filesz: ' + hex(new_filesz) + ' memsz: ' + hex(new_memsz))
            break

    # Step 8: Write output
    print('\n--- Step 8: Write Output ---')
    write_file(OUTPUT_ABL, output)

    # Also create padded version (8MB for EDL flash)
    target_size = 8 * 1024 * 1024
    if len(output) < target_size:
        padded = output + bytearray(target_size - len(output))
    else:
        padded = output
    write_file(OUTPUT_PADDED, padded)

    # Verify: decompress the new image and check the patch
    print('\n--- Verification ---')
    new_comp_data = bytes(output[old_comp_start:old_comp_start + len(new_compressed)])
    verify_decomp = try_decompress(new_comp_data)
    if verify_decomp:
        nop_check = verify_decomp[PATCH_OFFSET_ACTUAL:PATCH_OFFSET_ACTUAL+4]
        nop_val = struct.unpack('<I', nop_check)[0]
        if nop_val == 0xd503201f:
            print('VERIFICATION PASSED: NOP instruction at patch offset!')
        else:
            print('VERIFICATION FAILED: Expected NOP but got ' + hex(nop_val))
    else:
        print('WARNING: Could not verify (decompression of rebuilt image failed)')

    print('\n=== DONE ===')
    print('Patched ABL: ' + OUTPUT_ABL)
    print('Padded ABL (for EDL): ' + OUTPUT_PADDED)

if __name__ == '__main__':
    main()
