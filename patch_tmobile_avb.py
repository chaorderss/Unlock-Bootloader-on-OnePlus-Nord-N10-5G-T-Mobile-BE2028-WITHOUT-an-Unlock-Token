#!/usr/bin/env python3
"""
Analyze T-Mobile ABL AVB verification code and generate a patch
to make it boot Magisk-patched images regardless of verification result.

Key findings:
 0x592ba: "Unlocked, AvbSlotVerify returned %a, continue boot"
 0x59383: "ERROR: Device State %a,AvbSlotVerify"
 0x591b2: "verifiedbootstate=green.orange.yellow"
 0x5a7b9: "VERIFICATION_DISABLED bit is set"

Strategy: Find the code that checks device lock state before AvbSlotVerify,
patch it so the LOCKED path behaves like UNLOCKED (continue on failure).
"""
import struct, re, sys

DECOMP = '/Users/xmxx/pinganhuijia/tmobile_abl_decompressed.bin'
ABL_IN = '/Users/xmxx/pinganhuijia/edl_backup/abl_b.img'
ABL_OUT = '/Users/xmxx/pinganhuijia/tmobile_abl_patched.img'

with open(DECOMP, 'rb') as f:
    code = bytearray(f.read())

# -----------------------------------------------------------------------
# Decode AArch64 instructions around the key string references
# -----------------------------------------------------------------------
# The decompressed blob is an inner FV containing a PE32+ image.
# PE32+ typically starts with MZ header, then sections.
# We need the image base to compute virtual addresses from file offsets.

def find_pe32_info(data):
    """Return (pe_file_offset, image_base, sections)"""
    for m in re.finditer(b'MZ', data):
        off = m.start()
        if off + 0x40 > len(data): continue
        pe_rel = struct.unpack_from('<I', data, off+0x3C)[0]
        pe_abs = off + pe_rel
        if pe_abs + 24 > len(data): continue
        if data[pe_abs:pe_abs+4] != b'PE\x00\x00': continue
        machine = struct.unpack_from('<H', data, pe_abs+4)[0]
        if machine != 0xAA64: continue  # must be ARM64
        num_sections = struct.unpack_from('<H', data, pe_abs+6)[0]
        opt_hdr_sz = struct.unpack_from('<H', data, pe_abs+16)[0]
        opt_off = pe_abs + 24
        magic = struct.unpack_from('<H', data, opt_off)[0]
        if magic != 0x20B: continue  # PE32+
        image_base = struct.unpack_from('<Q', data, opt_off+24)[0]
        sec_tbl_off = opt_off + opt_hdr_sz
        sections = []
        for i in range(num_sections):
            s = sec_tbl_off + i*40
            name = data[s:s+8].rstrip(b'\x00')
            vsize = struct.unpack_from('<I', data, s+8)[0]
            vaddr = struct.unpack_from('<I', data, s+12)[0]
            raw_size = struct.unpack_from('<I', data, s+16)[0]
            raw_off = struct.unpack_from('<I', data, s+20)[0]
            sections.append({'name':name, 'vaddr':vaddr, 'vsize':vsize,
                             'raw_off':raw_off+off, 'raw_size':raw_size})
        print(f"PE32+ found at file offset {hex(off)}, image_base={hex(image_base)}")
        print(f"  Sections: {[(s['name'].decode(),hex(s['vaddr']),hex(s['raw_off'])) for s in sections]}")
        return off, image_base, sections
    return None, None, None

pe_off, image_base, sections = find_pe32_info(code)
if pe_off is None:
    print("No ARM64 PE32+ found in decompressed data!")
    # Show what MZ hits exist
    for m in re.finditer(b'MZ', code):
        print(f"  MZ at {hex(m.start())}")
    sys.exit(1)

def va_to_file_offset(va, image_base, sections, pe_file_start):
    rva = va - image_base
    for s in sections:
        if s['vaddr'] <= rva < s['vaddr'] + s['vsize']:
            return s['raw_off'] + (rva - s['vaddr'])
    # If not in any section, try raw offset from PE start
    return pe_file_start + rva

def file_offset_to_va(file_off, image_base, sections, pe_file_start):
    for s in sections:
        if s['raw_off'] <= file_off < s['raw_off'] + s['raw_size']:
            return image_base + s['vaddr'] + (file_off - s['raw_off'])
    return image_base + (file_off - pe_file_start)

# -----------------------------------------------------------------------
# Find the string reference to the "ERROR: Device State" message
# and also "Unlocked, AvbSlotVerify returned"
# -----------------------------------------------------------------------
STR_UNLOCKED = b'Unlocked, AvbSlotVerify returned'
STR_LOCKED_ERR = b'ERROR: Device State'
STR_VERIF_DISABLED = b'VERIFICATION_DISABLED bit is set'

str_unlocked_off = code.find(STR_UNLOCKED)
str_locked_err_off = code.find(STR_LOCKED_ERR)
str_verif_disabled_off = code.find(STR_VERIF_DISABLED)

print(f"\nKey string offsets in decompressed blob:")
print(f"  'Unlocked...AvbSlotVerify' at {hex(str_unlocked_off)}")
print(f"  'ERROR: Device State' at {hex(str_locked_err_off)}")
print(f"  'VERIFICATION_DISABLED' at {hex(str_verif_disabled_off)}")

# Compute virtual addresses
str_unlocked_va = file_offset_to_va(str_unlocked_off, image_base, sections, pe_off)
str_locked_err_va = file_offset_to_va(str_locked_err_off, image_base, sections, pe_off)
print(f"\nVirtual addresses:")
print(f"  'Unlocked...' VA = {hex(str_unlocked_va)}")
print(f"  'ERROR: Device State' VA = {hex(str_locked_err_va)}")

# -----------------------------------------------------------------------
# Find ADRP+ADD pairs referencing these strings in the code sections
# -----------------------------------------------------------------------
def decode_adrp(insn):
    if (insn & 0x9F000000) != 0x90000000: return None
    immlo = (insn >> 29) & 0x3
    immhi = (insn >> 5) & 0x7FFFF
    imm = ((immhi << 2) | immlo) << 12
    if imm & (1 << 32): imm -= (1 << 33)
    rd = insn & 0x1F
    return rd, imm

def decode_add_imm(insn):
    if (insn >> 24) & 0xFF not in (0x91,): return None
    if (insn >> 22) & 0x3 != 0: return None
    imm12 = (insn >> 10) & 0xFFF
    rn = (insn >> 5) & 0x1F
    rd = insn & 0x1F
    return rd, rn, imm12

# Find code section
text_section = None
for s in sections:
    if b'.text' in s['name'] or b'text' in s['name'].lower():
        text_section = s
        break
if text_section is None and sections:
    # Use first executable section (usually index 0 or named .text)
    text_section = sections[0]

print(f"\nSearching in section: {text_section['name']} raw_off={hex(text_section['raw_off'])} size={hex(text_section['raw_size'])}")

def find_refs_to_va(target_va, code, text_section, image_base, sections, pe_off):
    refs = []
    tstart = text_section['raw_off']
    tend = tstart + text_section['raw_size']
    for i in range(tstart, min(tend, len(code)-4), 4):
        pc = file_offset_to_va(i, image_base, sections, pe_off)
        insn = struct.unpack_from('<I', code, i)[0]
        r = decode_adrp(insn)
        if r is None: continue
        rd, imm = r
        page_va = (pc & ~0xFFF) + imm
        if abs(page_va - (target_va & ~0xFFF)) < 0x1000:
            # Check next instruction for ADD
            if i+4 < len(code):
                insn2 = struct.unpack_from('<I', code, i+4)[0]
                r2 = decode_add_imm(insn2)
                if r2 and r2[1] == rd:
                    rd2, rn2, imm12 = r2
                    final_va = page_va + imm12
                    if final_va == target_va:
                        refs.append(i)
    return refs

print(f"\nFinding code references to 'ERROR: Device State' string...")
locked_refs = find_refs_to_va(str_locked_err_va, code, text_section, image_base, sections, pe_off)
print(f"  Found {len(locked_refs)} refs: {[hex(r) for r in locked_refs]}")

print(f"\nFinding code references to 'Unlocked, AvbSlotVerify' string...")
unlocked_refs = find_refs_to_va(str_unlocked_va, code, text_section, image_base, sections, pe_off)
print(f"  Found {len(unlocked_refs)} refs: {[hex(r) for r in unlocked_refs]}")

# -----------------------------------------------------------------------
# Analyze context around the locked error reference to find the branch
# -----------------------------------------------------------------------
def disasm_context(code, file_off, count=20, image_base=0, sections=[], pe_off=0):
    """Print ARM64 instructions around an offset"""
    start = max(0, file_off - count*4)
    print(f"  Context around {hex(file_off)} (showing {hex(start)} to {hex(file_off+count*4)}):")
    for i in range(start, file_off + count*4, 4):
        if i+4 > len(code): break
        insn = struct.unpack_from('<I', code, i)[0]
        va = file_offset_to_va(i, image_base, sections, pe_off)
        marker = " <-- TARGET" if i == file_off else ""
        # Decode branch instructions
        branch_info = ""
        # B/BL
        if (insn >> 26) == 0x05:
            imm26 = insn & 0x3FFFFFF
            if imm26 & (1<<25): imm26 -= (1<<26)
            target = va + imm26*4
            branch_info = f"  B {hex(target)}"
        elif (insn >> 26) == 0x25:
            imm26 = insn & 0x3FFFFFF
            if imm26 & (1<<25): imm26 -= (1<<26)
            target = va + imm26*4
            branch_info = f"  BL {hex(target)}"
        # B.cond
        elif (insn >> 24) == 0x54:
            imm19 = (insn >> 5) & 0x7FFFF
            if imm19 & (1<<18): imm19 -= (1<<19)
            target = va + imm19*4
            cond = insn & 0xF
            cond_names = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
            branch_info = f"  B.{cond_names[cond]} {hex(target)}"
        # CBZ/CBNZ
        elif (insn >> 24) & 0x7F == 0x34:
            imm19 = (insn >> 5) & 0x7FFFF
            if imm19 & (1<<18): imm19 -= (1<<19)
            target = va + imm19*4
            rn = insn & 0x1F
            op = "CBNZ" if (insn>>24)&1 else "CBZ"
            branch_info = f"  {op} x{rn}, {hex(target)}"
        # TBZ/TBNZ
        elif (insn >> 24) & 0x7E == 0x36:
            imm14 = (insn >> 5) & 0x3FFF
            if imm14 & (1<<13): imm14 -= (1<<14)
            target = va + imm14*4
            bit = ((insn>>31)<<5) | ((insn>>19)&0x1F)
            rn = insn & 0x1F
            op = "TBNZ" if (insn>>24)&1 else "TBZ"
            branch_info = f"  {op} x{rn}, #{bit}, {hex(target)}"
        print(f"  {hex(va):16s}  {insn:08x}{branch_info}{marker}")

if locked_refs:
    print("\n=== Context around 'ERROR: Device State' reference ===")
    disasm_context(code, locked_refs[0], count=30, image_base=image_base, sections=sections, pe_off=pe_off)

if unlocked_refs:
    print("\n=== Context around 'Unlocked, AvbSlotVerify' reference ===")
    disasm_context(code, unlocked_refs[0], count=20, image_base=image_base, sections=sections, pe_off=pe_off)
