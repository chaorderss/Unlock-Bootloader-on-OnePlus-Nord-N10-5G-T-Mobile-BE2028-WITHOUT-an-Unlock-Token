#!/usr/bin/env python3
"""
Patch T-Mobile ABL to bypass AVB verification.
Strategy:
1. Decompress ABL LZMA payload from edl_backup/abl_b.img
2. Use capstone to find ADRP+ADD pairs targeting the AVB error strings
3. Locate the conditional branch that gates the error path
4. Patch: NOP the branch or force it to always take the "continue" path
5. Recompress and reconstruct the full ABL image
6. Pad to original size

Layout (confirmed):
  abl_b.img: ELF -> FV at 0x3000 -> FFS at 0x3048 -> GUID_DEFINED at 0x3060
  LZMA payload starts at 0x3078 (after 24-byte section header)
  Decompressed: PE32+ ARM64, image_base=0, DELTA=0xb8 (VA = file_off - 0xb8)
  .text: vaddr=0x1000, raw_off=0x10b8, raw_sz=0x73000
  .data: vaddr=0x74000, raw_off=0x740b8
  String "ERROR: Device State": file_off=0x592e4, VA=0x5922c
  String "Unlocked, AvbSlotVerify": file_off=0x592b0, VA=0x591f8
"""
import struct, sys, lzma, os
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import *

ABL_IMG    = '/Users/xmxx/pinganhuijia/edl_backup/abl_b.img'
DECOMP_BIN = '/Users/xmxx/pinganhuijia/tmobile_abl_decompressed.bin'
OUT_IMG    = '/Users/xmxx/pinganhuijia/tmobile_abl_avb_patched.img'

DELTA          = 0xb8
TEXT_RAW_START = 0x10b8
TEXT_RAW_END   = 0x740b8

# String positions (file offsets in decompressed blob)
STR_ERROR_FILE    = 0x592e4   # "ERROR: Device State %a,AvbSlotVerify returned %a"
STR_UNLOCKED_FILE = 0x592b0   # "State: Unlocked, AvbSlotVerify returned %a, continue boot"

STR_ERROR_VA    = STR_ERROR_FILE    - DELTA   # 0x5922c
STR_UNLOCKED_VA = STR_UNLOCKED_FILE - DELTA   # 0x591f8

# ============================================================
# 1. Load decompressed ABL
# ============================================================
print("Loading decompressed ABL...")
with open(DECOMP_BIN, 'rb') as f:
    d = bytearray(f.read())
print(f"  Size: {hex(len(d))}")

# ============================================================
# 2. Capstone: find all ADRP instructions in .text that target
#    page 0x59000 (where both strings live)
# ============================================================
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

code_bytes = bytes(d[TEXT_RAW_START:TEXT_RAW_END])
BASE_VA    = TEXT_RAW_START - DELTA  # 0x1000

TARGET_PAGE_ERROR    = STR_ERROR_VA    & ~0xFFF   # 0x59000
TARGET_PAGE_UNLOCKED = STR_UNLOCKED_VA & ~0xFFF   # 0x59000  (same page!)
TARGET_PAGES = {TARGET_PAGE_ERROR, TARGET_PAGE_UNLOCKED}

print(f"Scanning .text for ADRP targeting pages: {[hex(p) for p in TARGET_PAGES]}")

# Collect (va, file_off, rd) for each matching ADRP
adrp_hits = []
for insn in md.disasm(code_bytes, BASE_VA):
    if insn.mnemonic.lower() != 'adrp':
        continue
    if not insn.operands:
        continue
    target_page = insn.operands[1].imm
    if target_page in TARGET_PAGES:
        va      = insn.address
        file_off = va + DELTA
        rd      = insn.operands[0].reg
        adrp_hits.append((va, file_off, rd, target_page))

print(f"  Found {len(adrp_hits)} ADRP hits")

# ============================================================
# 3. For each ADRP hit, check next instruction (ADD xN, xN, #offset)
#    to find exact refs to our two strings
# ============================================================
def get_insn_at(va):
    """Disassemble single instruction at VA"""
    fo = va + DELTA
    chunk = bytes(d[fo:fo+4])
    insns = list(md.disasm(chunk, va))
    return insns[0] if insns else None

error_refs    = []
unlocked_refs = []

for (va, fo, rd, tpage) in adrp_hits:
    next_insn = get_insn_at(va + 4)
    if next_insn is None:
        continue
    if next_insn.mnemonic.lower() != 'add':
        continue
    if len(next_insn.operands) < 3:
        continue
    # ADD xN, xRd, #imm  -- verify rn == rd
    rn  = next_insn.operands[1].reg
    imm = next_insn.operands[2].imm
    if rn != rd:
        continue
    # Full VA = target_page + imm
    target_va = tpage + imm
    if target_va == STR_ERROR_VA:
        error_refs.append((va, fo))
    elif target_va == STR_UNLOCKED_VA:
        unlocked_refs.append((va, fo))

print(f"\n  ERROR string refs:    {len(error_refs)}: {[hex(x[0]) for x in error_refs]}")
print(f"  UNLOCKED string refs: {len(unlocked_refs)}: {[hex(x[0]) for x in unlocked_refs]}")

# ============================================================
# 4. Disassemble context around each ref to find the branch to patch
# ============================================================
def disasm_range(start_va, end_va):
    """Return list of (va, mnemonic, op_str, insn) for range"""
    fo_s = start_va + DELTA
    fo_e = end_va   + DELTA
    chunk = bytes(d[fo_s:fo_e])
    return list(md.disasm(chunk, start_va))

BRANCH_MNEMONICS = {'b', 'bl', 'b.eq','b.ne','b.lt','b.le','b.gt','b.ge',
                    'b.hi','b.lo','b.hs','b.ls','b.mi','b.pl','b.vs','b.vc',
                    'cbz','cbnz','tbz','tbnz'}

def find_nearest_branch_before(ref_va, window=0x80):
    """Look backward from ref_va for a conditional branch"""
    insns = disasm_range(ref_va - window, ref_va + 4)
    branches = []
    for ins in insns:
        if ins.mnemonic.lower().startswith('b') or ins.mnemonic.lower() in ('cbz','cbnz','tbz','tbnz'):
            branches.append(ins)
    return branches

print("\n" + "="*60)
print("CONTEXT AROUND ERROR STRING REFS")
print("="*60)

patch_candidates = []

for (ref_va, ref_fo) in error_refs:
    print(f"\nRef at VA {hex(ref_va)} (file {hex(ref_fo)}):")
    # Show 20 instructions before and 8 after
    start = ref_va - 0x50
    end   = ref_va + 0x30
    insns = disasm_range(start, end)
    for ins in insns:
        marker = " <<< ADRP ERROR STRING" if ins.address == ref_va else ""
        branch_mark = " *** BRANCH" if ins.mnemonic.lower() in BRANCH_MNEMONICS or ins.mnemonic.lower().startswith('b.') else ""
        fo = ins.address + DELTA
        print(f"  {hex(ins.address)} (file {hex(fo)}): {ins.mnemonic:8} {ins.op_str}{marker}{branch_mark}")

print("\n" + "="*60)
print("CONTEXT AROUND UNLOCKED STRING REFS")
print("="*60)
for (ref_va, ref_fo) in unlocked_refs:
    print(f"\nRef at VA {hex(ref_va)} (file {hex(ref_fo)}):")
    start = ref_va - 0x50
    end   = ref_va + 0x30
    insns = disasm_range(start, end)
    for ins in insns:
        marker = " <<< ADRP UNLOCKED STRING" if ins.address == ref_va else ""
        branch_mark = " *** BRANCH" if ins.mnemonic.lower() in BRANCH_MNEMONICS or ins.mnemonic.lower().startswith('b.') else ""
        fo = ins.address + DELTA
        print(f"  {hex(ins.address)} (file {hex(fo)}): {ins.mnemonic:8} {ins.op_str}{marker}{branch_mark}")

# ============================================================
# 5. Interactive: ask user which branch to patch
#    (or auto-detect if pattern is clear)
# ============================================================
print("\n" + "="*60)
print("AUTO-DETECT PATCH TARGET")
print("="*60)

# The pattern we expect:
#   ...
#   BL  AvbSlotVerify           ; returns error code in x0
#   CBZ/CBNZ x0, <continue>     ; if result == 0 (success), continue
#   <error path>:
#   ADRP x?, #error_string_page
#   ADD  x?, x?, #error_string_off
#   BL   print_error
#   ...
#   <continue path>:
#   ADRP x?, #unlocked_string_page
#   ADD  x?, x?, #unlocked_string_off

# Find branches between the UNLOCKED and ERROR refs
# (they should be close together in the same function)
if error_refs and unlocked_refs:
    # Sort by VA
    all_refs = sorted([(va, 'ERROR') for va,_ in error_refs] +
                      [(va, 'UNLOCKED') for va,_ in unlocked_refs])
    print(f"All refs sorted by VA: {[(hex(v), t) for v,t in all_refs]}")

    # Look for the branch that selects between error and unlocked paths
    # It should be BEFORE both, or between the two
    for i in range(len(all_refs)-1):
        va1, t1 = all_refs[i]
        va2, t2 = all_refs[i+1]
        if t1 != t2:  # consecutive refs of different types
            diff = va2 - va1
            print(f"\nConsecutive {t1}@{hex(va1)} -> {t2}@{hex(va2)}, gap={hex(diff)}")
            if diff < 0x200:  # close together, likely same function
                # The branch should be just before the ERROR path
                # Look in range va1-0x80 to va1
                earlier = min(va1, va2)
                insns = disasm_range(earlier - 0x80, earlier + 4)
                print("Branches in the 128 bytes before earlier ref:")
                for ins in insns:
                    if ins.mnemonic.lower().startswith('b') or ins.mnemonic.lower() in ('cbz','cbnz','tbz','tbnz'):
                        fo = ins.address + DELTA
                        # Decode branch target
                        tgt = None
                        if ins.operands:
                            last_op = ins.operands[-1]
                            if last_op.type == ARM64_OP_IMM:
                                tgt = last_op.imm
                        tgt_s = f" -> {hex(tgt)}" if tgt else ""
                        print(f"  Branch: {hex(ins.address)} (file {hex(fo)}): {ins.mnemonic} {ins.op_str}{tgt_s}")
                        patch_candidates.append((ins.address, fo, ins.mnemonic, ins.op_str, tgt))

print(f"\nPatch candidates: {len(patch_candidates)}")
for pc_va, pc_fo, mnem, ops, tgt in patch_candidates:
    print(f"  {hex(pc_va)} (file {hex(pc_fo)}): {mnem} {ops}  target={hex(tgt) if tgt else '?'}")
