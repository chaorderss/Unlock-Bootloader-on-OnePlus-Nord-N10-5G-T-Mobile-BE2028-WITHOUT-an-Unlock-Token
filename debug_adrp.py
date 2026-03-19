#!/usr/bin/env python3
"""Debug: show what follows ADRP targeting page 0x59000"""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64_const import ARM64_OP_IMM, ARM64_OP_REG, ARM64_REG_X0

with open('/Users/xmxx/pinganhuijia/tmobile_abl_decompressed.bin','rb') as f:
    d = bytearray(f.read())

DELTA          = 0xb8
TEXT_RAW_START = 0x10b8
TEXT_RAW_END   = 0x740b8
BASE_VA        = TEXT_RAW_START - DELTA  # 0x1000

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

code_bytes = bytes(d[TEXT_RAW_START:TEXT_RAW_END])

TARGET_PAGE     = 0x59000
STR_ERROR_VA    = 0x592e4 - DELTA  # 0x5922c  (ERROR: Device State)
STR_UNLOCKED_VA = 0x592b0 - DELTA  # 0x591f8  (State: Unlocked)

print(f"ERROR string VA:    {hex(STR_ERROR_VA)}")
print(f"UNLOCKED string VA: {hex(STR_UNLOCKED_VA)}")
print(f"Both on page:       {hex(TARGET_PAGE)}")
print(f"ERROR offset in page:    {hex(STR_ERROR_VA & 0xFFF)}")   # 0x22c
print(f"UNLOCKED offset in page: {hex(STR_UNLOCKED_VA & 0xFFF)}") # 0x1f8
print()

# Build a map: file_offset -> (mnemonic, op_str, insn)
insn_map = {}
for insn in md.disasm(code_bytes, BASE_VA):
    fo = insn.address + DELTA
    insn_map[fo] = insn

# Now scan for ADRP hitting page 0x59000 and show next insn
count = 0
hits_error = []
hits_unlocked = []

for insn in md.disasm(code_bytes, BASE_VA):
    if insn.mnemonic.lower() != 'adrp':
        continue
    if not insn.operands:
        continue
    tpage = insn.operands[1].imm
    if tpage != TARGET_PAGE:
        continue

    fo       = insn.address + DELTA
    fo_next  = fo + 4
    ni       = insn_map.get(fo_next)

    count += 1
    if count <= 40:
        ni_str = f"{ni.mnemonic} {ni.op_str}" if ni else "???"
        print(f"  {hex(insn.address)} (file {hex(fo)}): "
              f"adrp {insn.op_str} | next: {ni_str}")

    if ni and ni.mnemonic.lower() == 'add' and len(ni.operands) >= 3:
        imm = ni.operands[2].imm
        result_va = tpage + imm
        if result_va == STR_ERROR_VA:
            hits_error.append(insn.address)
            print(f"  *** ERROR ref at VA {hex(insn.address)}")
        elif result_va == STR_UNLOCKED_VA:
            hits_unlocked.append(insn.address)
            print(f"  *** UNLOCKED ref at VA {hex(insn.address)}")

print(f"\nTotal ADRP hits: {count}")
print(f"ERROR refs:    {[hex(v) for v in hits_error]}")
print(f"UNLOCKED refs: {[hex(v) for v in hits_unlocked]}")

# Check if offset is correct: what's at exactly file 0x592e4 - DELTA?
# Verify by checking a raw ADD instruction near a known-good ADRP hit
for insn in md.disasm(code_bytes, BASE_VA):
    if insn.address < 0x1540 or insn.address > 0x1560:
        continue
    fo = insn.address + DELTA
    print(f"  Sanity {hex(insn.address)} (file {hex(fo)}): {insn.mnemonic} {insn.op_str}")
