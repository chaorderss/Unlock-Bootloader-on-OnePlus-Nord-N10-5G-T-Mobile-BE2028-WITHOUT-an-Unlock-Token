#!/usr/bin/env python3
"""
Patch T-Mobile ABL to bypass AVB boot verification.
Since image_base=0 and VAs equal file offsets, we can work directly with
file offsets to find ADRP+ADD pairs referencing the target strings and
identify the conditional branch to patch.
"""
import struct, re, sys, lzma, os

ABL_IN  = '/Users/xmxx/pinganhuijia/edl_backup/abl_b.img'
DECOMP  = '/Users/xmxx/pinganhuijia/tmobile_abl_decompressed.bin'
ABL_OUT = '/Users/xmxx/pinganhuijia/tmobile_abl_avb_patched.img'

with open(DECOMP, 'rb') as f:
    code = bytearray(f.read())

CODE_SIZE = len(code)
print(f"Decompressed ABL size: {hex(CODE_SIZE)}")

# Since image_base=0 in this UEFI PI image, VA == file_offset
# The code is spread throughout the decompressed blob

STR_UNLOCKED_OFF = code.find(b'Unlocked, AvbSlotVerify')
STR_LOCKED_ERR_OFF = code.find(b'ERROR: Device State')
STR_VERIF_DIS_OFF = code.find(b'VERIFICATION_DISABLED bit is set')

print(f"String offsets (= VAs since base=0):")
print(f"  'Unlocked...':  {hex(STR_UNLOCKED_OFF)}")
print(f"  'ERROR: Device State': {hex(STR_LOCKED_ERR_OFF)}")
print(f"  'VERIFICATION_DISABLED': {hex(STR_VERIF_DIS_OFF)}")

def decode_adrp(insn, pc):
    if (insn & 0x9F000000) != 0x90000000: return None
    immlo = (insn >> 29) & 0x3
    immhi = (insn >> 5) & 0x7FFFF
    imm = ((immhi << 2) | immlo) << 12
    if imm & (1 << 32): imm -= (1 << 33)
    rd = insn & 0x1F
    page = (pc & ~0xFFF) + imm
    return rd, page

def decode_add(insn):
    # ADD (immediate): 0x91xxxxxx, shift=0
    if (insn >> 22) != 0x244: return None
    imm12 = (insn >> 10) & 0xFFF
    rn = (insn >> 5) & 0x1F
    rd = insn & 0x1F
    return rd, rn, imm12

def find_adrp_add_refs(target_va, code, search_start=0x1000, search_end=None):
    """Find all ADRP+ADD pairs that load target_va into a register"""
    if search_end is None:
        search_end = len(code) - 8
    refs = []
    target_page = target_va & ~0xFFF
    target_off  = target_va & 0xFFF
    for i in range(search_start, search_end, 4):
        pc = i  # VA == file offset
        insn1 = struct.unpack_from('<I', code, i)[0]
        r = decode_adrp(insn1, pc)
        if r is None: continue
        rd, page = r
        if page != target_page: continue
        # Check next instruction
        insn2 = struct.unpack_from('<I', code, i+4)[0]
        r2 = decode_add(insn2)
        if r2 and r2[1] == rd and r2[2] == target_off:
            refs.append(i)
    return refs

print(f"\nSearching ADRP+ADD refs for ERROR string (searching ~1.5M bytes)...")
err_refs = find_adrp_add_refs(STR_LOCKED_ERR_OFF, code)
print(f"  Found {len(err_refs)}: {[hex(r) for r in err_refs]}")

print(f"\nSearching ADRP+ADD refs for Unlocked string...")
ok_refs = find_adrp_add_refs(STR_UNLOCKED_OFF, code)
print(f"  Found {len(ok_refs)}: {[hex(r) for r in ok_refs]}")

def branch_info(insn, pc):
    """Decode branch instruction, return (mnemonic, target) or None"""
    # B.cond
    if (insn >> 24) == 0x54 and (insn & 0x10000000) == 0:
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1<<18): imm19 -= (1<<19)
        target = pc + imm19*4
        cond = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV'][insn&0xF]
        return f'B.{cond}', target
    # CBZ
    if (insn>>24)&0xBF == 0x34:
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1<<18): imm19 -= (1<<19)
        target = pc + imm19*4
        rn = insn & 0x1F
        op = 'CBNZ' if (insn>>24)&1 else 'CBZ'
        return f'{op} x{rn}', target
    # TBZ/TBNZ
    if (insn>>24)&0xBE == 0x36:
        imm14 = (insn >> 5) & 0x3FFF
        if imm14 & (1<<13): imm14 -= (1<<14)
        target = pc + imm14*4
        bit = ((insn>>31)<<5)|((insn>>19)&0x1F)
        rn = insn & 0x1F
        op = 'TBNZ' if (insn>>24)&1 else 'TBZ'
        return f'{op} x{rn}#{bit}', target
    # B unconditional
    if (insn>>26) == 0x05:
        imm26 = insn & 0x3FFFFFF
        if imm26 & (1<<25): imm26 -= (1<<26)
        return 'B', pc + imm26*4
    # BL
    if (insn>>26) == 0x25:
        imm26 = insn & 0x3FFFFFF
        if imm26 & (1<<25): imm26 -= (1<<26)
        return 'BL', pc + imm26*4
    return None

def show_context(code, file_off, before=20, after=20):
    start = max(0, file_off - before*4)
    for i in range(start, min(len(code)-3, file_off + after*4), 4):
        insn = struct.unpack_from('<I', code, i)[0]
        bi = branch_info(insn, i)
        bstr = f'  -> {bi[0]} {hex(bi[1])}' if bi else ''
        marker = ' <<<' if i == file_off else ''
        print(f'  {hex(i):8s}  {insn:08x}{bstr}{marker}')

# Show context around each ERROR reference
for ref_off in err_refs[:3]:
    print(f"\n=== Context around ERROR ref at {hex(ref_off)} ===")
    show_context(code, ref_off, before=25, after=10)

# Show context around each Unlocked reference
for ref_off in ok_refs[:3]:
    print(f"\n=== Context around Unlocked ref at {hex(ref_off)} ===")
    show_context(code, ref_off, before=15, after=10)

# -----------------------------------------------------------------------
# Now look for the branch that decides LOCKED vs UNLOCKED path
# The AVB check function should have a structure like:
#   if (is_unlocked) {
#       AvbSlotVerify(...); // ignore result or continue
#       print("Unlocked, AvbSlotVerify returned...")
#   } else {
#       rc = AvbSlotVerify(...)
#       if (rc != 0) {
#           print("ERROR: Device State...")
#           halt/loop
#       }
#   }
# We want to find the branch between these paths and NOP or invert it.
# -----------------------------------------------------------------------
print("\n=== Searching for conditional branches within 200 insns before ERROR ref ===")
for ref_off in err_refs[:2]:
    print(f"\nSearching before ERROR ref at {hex(ref_off)}:")
    cond_branches = []
    for i in range(max(0,ref_off-200*4), ref_off, 4):
        insn = struct.unpack_from('<I', code, i)[0]
        bi = branch_info(insn, i)
        if bi and bi[0] not in ('B','BL'):  # conditional only
            cond_branches.append((i, bi))
            print(f"  {hex(i)}: {insn:08x}  {bi[0]} -> {hex(bi[1])}")
