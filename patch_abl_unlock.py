#!/usr/bin/env python3
"""
Analyze and patch the Global ABL to bypass the unlock token check.

The string "Please flash unlock token first." is at offset 0x62ef3 in the
decompressed ABL blob. The PE32+ (LinuxLoader) starts at offset 0xB8.

Strategy:
1. Parse PE32+ to get section layout and image base
2. Calculate the virtual address of the target string
3. Scan .text section for ADRP+ADD pairs referencing that VA
4. Find the conditional branch (CBZ/CBNZ/B.cond) near the reference
5. Patch it to skip the token check
"""

import struct
import sys
import os

DECOMP_PATH = '/Users/xmxx/pinganhuijia/global_abl_decompressed.bin'

def read_file(path):
    with open(path, 'rb') as f:
        return bytearray(f.read())

def parse_pe32(data, pe_offset):
    """Parse PE32+ header and return sections + image base"""
    # Check MZ
    assert data[pe_offset:pe_offset+2] == b'MZ', "Not MZ at pe_offset"

    # PE header offset is at MZ+0x3C
    pe_sig_off = pe_offset + struct.unpack_from('<I', data, pe_offset + 0x3C)[0]
    assert data[pe_sig_off:pe_sig_off+4] == b'PE\x00\x00', f"No PE sig at {pe_sig_off:#x}"

    coff_off = pe_sig_off + 4
    machine = struct.unpack_from('<H', data, coff_off)[0]
    num_sections = struct.unpack_from('<H', data, coff_off + 2)[0]
    opt_hdr_size = struct.unpack_from('<H', data, coff_off + 16)[0]

    print(f"  Machine: {machine:#06x} ({'ARM64' if machine == 0xAA64 else 'other'})")
    print(f"  Number of sections: {num_sections}")
    print(f"  Optional header size: {opt_hdr_size}")

    opt_off = coff_off + 20
    magic = struct.unpack_from('<H', data, opt_off)[0]
    print(f"  Optional header magic: {magic:#06x} ({'PE32+' if magic == 0x20B else 'PE32' if magic == 0x10B else '?'})")

    if magic == 0x20B:  # PE32+
        image_base = struct.unpack_from('<Q', data, opt_off + 24)[0]
        section_alignment = struct.unpack_from('<I', data, opt_off + 32)[0]
        file_alignment = struct.unpack_from('<I', data, opt_off + 36)[0]
        size_of_image = struct.unpack_from('<I', data, opt_off + 56)[0]
        size_of_headers = struct.unpack_from('<I', data, opt_off + 60)[0]
    else:  # PE32
        image_base = struct.unpack_from('<I', data, opt_off + 28)[0]
        section_alignment = struct.unpack_from('<I', data, opt_off + 32)[0]
        file_alignment = struct.unpack_from('<I', data, opt_off + 36)[0]
        size_of_image = struct.unpack_from('<I', data, opt_off + 56)[0]
        size_of_headers = struct.unpack_from('<I', data, opt_off + 60)[0]

    print(f"  Image base: {image_base:#x}")
    print(f"  Section alignment: {section_alignment:#x}")
    print(f"  File alignment: {file_alignment:#x}")
    print(f"  Size of image: {size_of_image:#x}")

    # Parse sections
    section_off = opt_off + opt_hdr_size
    sections = []
    for i in range(num_sections):
        s_off = section_off + i * 40
        name_raw = data[s_off:s_off+8]
        name = name_raw.split(b'\x00')[0].decode('ascii', errors='replace')
        vsize = struct.unpack_from('<I', data, s_off + 8)[0]
        va = struct.unpack_from('<I', data, s_off + 12)[0]
        raw_size = struct.unpack_from('<I', data, s_off + 16)[0]
        raw_ptr = struct.unpack_from('<I', data, s_off + 20)[0]
        chars = struct.unpack_from('<I', data, s_off + 36)[0]

        sections.append({
            'name': name, 'va': va, 'vsize': vsize,
            'raw_ptr': raw_ptr, 'raw_size': raw_size,
            'characteristics': chars
        })

        is_code = bool(chars & 0x20)
        is_data = bool(chars & 0x40)
        exec_flag = bool(chars & 0x20000000)
        print(f"  Section {i}: '{name}' VA={va:#x} VSize={vsize:#x} RawPtr={raw_ptr:#x} RawSize={raw_size:#x} {'CODE' if is_code else ''} {'EXEC' if exec_flag else ''} {'DATA' if is_data else ''}")

    return image_base, sections

def decode_adrp(insn):
    """Decode ARM64 ADRP instruction, return (rd, imm_pages) or None"""
    if (insn & 0x9F000000) != 0x90000000:
        return None
    rd = insn & 0x1F
    immlo = (insn >> 29) & 0x3
    immhi = (insn >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    # Sign extend 21-bit
    if imm & (1 << 20):
        imm -= (1 << 21)
    return (rd, imm << 12)

def decode_add_imm(insn):
    """Decode ARM64 ADD Xd, Xn, #imm instruction, return (rd, rn, imm) or None"""
    # ADD (immediate): sf=1, op=0, S=0, 100010, sh, imm12, Rn, Rd
    if (insn & 0xFF800000) == 0x91000000:  # 64-bit ADD
        rd = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = (insn >> 10) & 0xFFF
        sh = (insn >> 22) & 1
        if sh:
            imm12 <<= 12
        return (rd, rn, imm12)
    return None

def decode_branch(insn, pc):
    """Decode ARM64 conditional branch instructions.
    Returns (type, target_addr, condition) or None.
    Types: 'b.cond', 'cbz', 'cbnz', 'tbz', 'tbnz', 'b', 'bl'
    """
    # B.cond: 0101010 0 imm19 0 cond
    if (insn & 0xFF000010) == 0x54000000:
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1 << 18):
            imm19 -= (1 << 19)
        cond = insn & 0xF
        target = pc + (imm19 << 2)
        cond_names = ['eq','ne','cs','cc','mi','pl','vs','vc','hi','ls','ge','lt','gt','le','al','nv']
        return ('b.' + cond_names[cond], target, cond)

    # CBZ/CBNZ: sf 011010 op imm19 Rt
    if (insn & 0x7E000000) == 0x34000000:
        op = (insn >> 24) & 1
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1 << 18):
            imm19 -= (1 << 19)
        rt = insn & 0x1F
        sf = (insn >> 31) & 1
        target = pc + (imm19 << 2)
        return ('cbnz' if op else 'cbz', target, rt)

    # TBZ/TBNZ: b5 011011 op b40 imm14 Rt
    if (insn & 0x7E000000) == 0x36000000:
        op = (insn >> 24) & 1
        imm14 = (insn >> 5) & 0x3FFF
        if imm14 & (1 << 13):
            imm14 -= (1 << 14)
        rt = insn & 0x1F
        target = pc + (imm14 << 2)
        return ('tbnz' if op else 'tbz', target, rt)

    # B: 000101 imm26
    if (insn & 0xFC000000) == 0x14000000:
        imm26 = insn & 0x3FFFFFF
        if imm26 & (1 << 25):
            imm26 -= (1 << 26)
        target = pc + (imm26 << 2)
        return ('b', target, None)

    # BL: 100101 imm26
    if (insn & 0xFC000000) == 0x94000000:
        imm26 = insn & 0x3FFFFFF
        if imm26 & (1 << 25):
            imm26 -= (1 << 26)
        target = pc + (imm26 << 2)
        return ('bl', target, None)

    return None

def find_string_references(data, pe_offset, image_base, sections, target_str_file_offset):
    """Find ADRP+ADD pairs that reference the target string's virtual address"""

    # Calculate the string's VA
    # The string is at file offset target_str_file_offset in the decompressed blob
    # PE starts at pe_offset in the blob
    # Need to find which section contains this offset and compute its VA

    str_offset_in_pe = target_str_file_offset - pe_offset
    print(f"\n  String offset relative to PE base: {str_offset_in_pe:#x}")

    # Find which section contains this offset
    str_va = None
    for sec in sections:
        if sec['raw_ptr'] <= str_offset_in_pe < sec['raw_ptr'] + sec['raw_size']:
            str_va = image_base + sec['va'] + (str_offset_in_pe - sec['raw_ptr'])
            print(f"  String is in section '{sec['name']}' at VA {str_va:#x}")
            break

    if str_va is None:
        # Try treating the offset directly as RVA
        str_va = image_base + str_offset_in_pe
        print(f"  String not in any section raw range, using direct: VA {str_va:#x}")

    str_page = str_va & ~0xFFF
    str_page_off = str_va & 0xFFF
    print(f"  String VA: {str_va:#x}, page: {str_page:#x}, page_off: {str_page_off:#x}")

    # Find code section(s)
    code_sections = [s for s in sections if s['characteristics'] & 0x20000000]  # IMAGE_SCN_MEM_EXECUTE
    if not code_sections:
        code_sections = [s for s in sections if s['characteristics'] & 0x20]  # IMAGE_SCN_CNT_CODE
    if not code_sections:
        code_sections = [sections[0]]  # fallback to first section

    print(f"\n  Scanning {len(code_sections)} code section(s) for references...")

    references = []

    for sec in code_sections:
        sec_file_start = pe_offset + sec['raw_ptr']
        sec_va_start = image_base + sec['va']

        # Scan for ADRP instructions
        for i in range(0, sec['raw_size'] - 4, 4):
            file_off = sec_file_start + i
            if file_off + 4 > len(data):
                break

            insn = struct.unpack_from('<I', data, file_off)[0]
            adrp = decode_adrp(insn)
            if adrp is None:
                continue

            rd, imm_pages = adrp
            pc = sec_va_start + i
            adrp_result = (pc & ~0xFFF) + imm_pages

            # Check if this ADRP points to the string's page
            if adrp_result != str_page:
                continue

            # Check next instruction for ADD with matching page offset
            if file_off + 8 > len(data):
                continue

            insn2 = struct.unpack_from('<I', data, file_off + 4)[0]
            add = decode_add_imm(insn2)
            if add and add[1] == rd and add[2] == str_page_off:
                ref_pc = pc
                ref_file_off = file_off
                print(f"\n  *** FOUND reference at file offset {ref_file_off:#x} (VA {ref_pc:#x})")
                print(f"      ADRP X{rd}, #{imm_pages:#x}  ; -> page {adrp_result:#x}")
                print(f"      ADD  X{add[0]}, X{add[1]}, #{add[2]:#x}  ; -> {str_va:#x}")
                references.append((ref_file_off, ref_pc, rd, add[0]))

    return references, str_va

def analyze_context(data, pe_offset, image_base, sections, ref_file_off, ref_pc):
    """Analyze instructions around a string reference to find the conditional branch"""

    # Find the code section this reference is in
    code_sec = None
    for sec in sections:
        sec_start = pe_offset + sec['raw_ptr']
        sec_end = sec_start + sec['raw_size']
        if sec_start <= ref_file_off < sec_end:
            code_sec = sec
            break

    if code_sec is None:
        print("  ERROR: Reference not in any section")
        return None

    sec_file_start = pe_offset + code_sec['raw_ptr']
    sec_va_start = image_base + code_sec['va']

    # Show -40 to +20 instructions around the reference
    print(f"\n  === Context around reference at {ref_file_off:#x} (VA {ref_pc:#x}) ===")

    branches_before = []

    start_off = max(sec_file_start, ref_file_off - 40*4)
    end_off = min(sec_file_start + code_sec['raw_size'], ref_file_off + 20*4)

    for off in range(start_off, end_off, 4):
        insn = struct.unpack_from('<I', data, off)[0]
        pc = sec_va_start + (off - sec_file_start)

        marker = " >>>" if off == ref_file_off or off == ref_file_off + 4 else "    "

        # Try to decode
        desc = f"{insn:#010x}"

        adrp = decode_adrp(insn)
        if adrp:
            rd, imm = adrp
            page = (pc & ~0xFFF) + imm
            desc = f"ADRP X{rd}, {page:#x}"

        add = decode_add_imm(insn)
        if add:
            desc = f"ADD  X{add[0]}, X{add[1]}, #{add[2]:#x}"

        br = decode_branch(insn, pc)
        if br:
            desc = f"{br[0].upper()} {br[1]:#x}"
            if br[0] not in ('b', 'bl') and br[2] is not None:
                if br[0].startswith('b.'):
                    desc = f"{br[0].upper()} {br[1]:#x}"
                else:
                    desc = f"{br[0].upper()} X{br[2]}, {br[1]:#x}"

            if off < ref_file_off:
                branches_before.append((off, pc, insn, br))

        # RET
        if insn == 0xD65F03C0:
            desc = "RET"

        # MOV (from BL results, etc)
        # STP/LDP (stack)
        if (insn & 0xFFE00000) == 0xA9800000 or (insn & 0xFFE00000) == 0xA9C00000:
            desc = f"STP/LDP (stack)"

        # BL
        if br and br[0] == 'bl':
            desc = f"BL {br[1]:#x}"

        print(f"  {marker} {off:#010x} (VA {pc:#010x}): {insn:08x}  {desc}")

    return branches_before

def main():
    print("=== ABL Unlock Token Patch Tool ===\n")

    data = read_file(DECOMP_PATH)
    print(f"Loaded {len(data)} bytes from {DECOMP_PATH}")

    # Find the target string
    target = b'Please flash unlock token first.'
    target_utf16 = 'Please flash unlock token first.'.encode('utf-16-le')

    # Search for both ASCII and UTF-16
    positions_ascii = []
    positions_utf16 = []

    pos = 0
    while True:
        idx = data.find(target, pos)
        if idx == -1:
            break
        positions_ascii.append(idx)
        pos = idx + 1

    pos = 0
    while True:
        idx = data.find(target_utf16, pos)
        if idx == -1:
            break
        positions_utf16.append(idx)
        pos = idx + 1

    print(f"\nASCII matches: {[hex(p) for p in positions_ascii]}")
    print(f"UTF-16LE matches: {[hex(p) for p in positions_utf16]}")

    all_positions = [(p, 'ascii') for p in positions_ascii] + [(p, 'utf16') for p in positions_utf16]

    if not all_positions:
        print("ERROR: Target string not found!")
        return

    # PE32+ starts at 0xB8
    pe_offset = 0xB8
    print(f"\nPE32+ offset: {pe_offset:#x}")

    print("\n--- Parsing PE32+ headers ---")
    image_base, sections = parse_pe32(data, pe_offset)

    # For each string occurrence, find code references
    all_refs = []
    for str_off, encoding in all_positions:
        print(f"\n--- Searching for references to string at {str_off:#x} ({encoding}) ---")
        refs, str_va = find_string_references(data, pe_offset, image_base, sections, str_off)
        for ref in refs:
            all_refs.append((ref, str_va, str_off, encoding))

    if not all_refs:
        print("\nERROR: No code references found to the target string!")
        print("\nTrying alternative: search for the string VA directly in code...")

        # Maybe the string is referenced differently - search more broadly
        # Try with all possible VAs (treating file offset as various RVAs)
        for str_off, encoding in all_positions:
            str_off_in_pe = str_off - pe_offset
            # Try various VA calculations
            for sec in sections:
                # What if the string's file offset maps to this section?
                candidate_va = image_base + str_off_in_pe
                print(f"  Trying VA {candidate_va:#x} (direct offset as RVA)")

                str_page = candidate_va & ~0xFFF
                str_page_off = candidate_va & 0xFFF

                code_sections = [s for s in sections if s['characteristics'] & 0x20000000 or s['characteristics'] & 0x20]
                if not code_sections:
                    code_sections = sections[:1]

                for csec in code_sections:
                    sec_file_start = pe_offset + csec['raw_ptr']
                    sec_va_start = image_base + csec['va']

                    for i in range(0, min(csec['raw_size'], len(data) - sec_file_start - 4), 4):
                        file_off = sec_file_start + i
                        insn = struct.unpack_from('<I', data, file_off)[0]
                        adrp = decode_adrp(insn)
                        if adrp is None:
                            continue
                        rd, imm_pages = adrp
                        pc = sec_va_start + i
                        adrp_result = (pc & ~0xFFF) + imm_pages
                        if adrp_result != str_page:
                            continue

                        if file_off + 8 > len(data):
                            continue
                        insn2 = struct.unpack_from('<I', data, file_off + 4)[0]
                        add_result = decode_add_imm(insn2)
                        if add_result and add_result[1] == rd and add_result[2] == str_page_off:
                            ref_pc = pc
                            print(f"  *** FOUND at file {file_off:#x} VA {ref_pc:#x}")
                            all_refs.append(((file_off, ref_pc, rd, add_result[0]), candidate_va, str_off, encoding))

                if all_refs:
                    break
            if all_refs:
                break

    if not all_refs:
        print("\nFATAL: Could not find any code reference to the unlock token string!")
        return

    # Analyze context around each reference
    print(f"\n{'='*60}")
    print(f"Found {len(all_refs)} reference(s). Analyzing context...")

    for ref_info, str_va, str_off, encoding in all_refs:
        ref_file_off, ref_pc, _, _ = ref_info
        branches = analyze_context(data, pe_offset, image_base, sections, ref_file_off, ref_pc)

        if branches:
            print(f"\n  Conditional branches BEFORE the string reference:")
            for boff, bpc, binsn, bdec in branches:
                print(f"    {boff:#010x} (VA {bpc:#010x}): {binsn:08x}  {bdec[0]} -> {bdec[1]:#x}")

if __name__ == '__main__':
    main()
