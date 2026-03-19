#!/usr/bin/env python3
"""
Strategy change: instead of ADRP+ADD adjacent search,
find all ADD instructions with imm==0x1f8 (Unlocked) or imm==0x22c (ERROR)
then look backward for the ADRP that loaded the page.
Also shows surrounding code context.
"""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64_const import ARM64_OP_IMM, ARM64_OP_REG

with open('/Users/xmxx/pinganhuijia/tmobile_abl_decompressed.bin','rb') as f:
    d = bytearray(f.read())

DELTA          = 0xb8
TEXT_RAW_START = 0x10b8
TEXT_RAW_END   = 0x740b8
BASE_VA        = TEXT_RAW_START - DELTA  # 0x1000

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

code_bytes = bytes(d[TEXT_RAW_START:TEXT_RAW_END])

STR_ERROR_VA    = 0x592e4 - DELTA  # 0x5922c
STR_UNLOCKED_VA = 0x592b0 - DELTA  # 0x591f8

TARGET_PAGE     = 0x59000
TARGET_OFF_ERR  = STR_ERROR_VA    & 0xFFF   # 0x22c
TARGET_OFF_UNL  = STR_UNLOCKED_VA & 0xFFF   # 0x1f8

print(f"Searching for ADD with imm=#{hex(TARGET_OFF_ERR)} (ERROR) or #{hex(TARGET_OFF_UNL)} (UNLOCKED)")
print(f"Both should be preceded (possibly distantly) by ADRP x?, #{hex(TARGET_PAGE)}")
print()

# Build full instruction list with index for fast backward lookup
insn_list = list(md.disasm(code_bytes, BASE_VA))
insn_by_va = {ins.address: (i, ins) for i, ins in enumerate(insn_list)}

def show_ctx(center_va, before=12, after=8, marks=None):
    if marks is None:
        marks = {}
    start_va = center_va - before*4
    end_va   = center_va + after*4
    for ins in insn_list:
        if ins.address < start_va or ins.address > end_va:
            continue
        fo = ins.address + DELTA
        mk = marks.get(ins.address, "")
        # Highlight branches
        br = ""
        m = ins.mnemonic.lower()
        if m.startswith('b') or m in ('cbz','cbnz','tbz','tbnz'):
            if ins.operands and ins.operands[-1].type == ARM64_OP_IMM:
                tgt = ins.operands[-1].imm
                br = f"  --> {hex(tgt)} (file {hex(tgt+DELTA)})"
        print(f"  {hex(ins.address)} (file {hex(fo)}):  {ins.mnemonic:8} {ins.op_str}{mk}{br}")

print("=" * 70)
print("ADD instructions with imm matching string offsets")
print("=" * 70)

for idx, ins in enumerate(insn_list):
    m = ins.mnemonic.lower()
    if m != 'add':
        continue
    if len(ins.operands) < 3:
        continue
    imm_op = ins.operands[2]
    if imm_op.type != ARM64_OP_IMM:
        continue
    imm = imm_op.imm
    if imm not in (TARGET_OFF_ERR, TARGET_OFF_UNL):
        continue

    label = "UNLOCKED" if imm == TARGET_OFF_UNL else "ERROR"
    fa = ins.address + DELTA
    print(f"\n>>> {label} ADD at VA {hex(ins.address)} (file {hex(fa)}):  {ins.mnemonic} {ins.op_str}")

    # Look backward up to 80 instructions for the ADRP that loaded page 0x59000
    adrp_va = None
    dest_reg = ins.operands[0].reg  # The destination of ADD
    src_reg  = ins.operands[1].reg  # The source of ADD (should be same as ADRP dest)
    print(f"    ADD src register: {ins.operands[1].reg} (ARM64_REG_X? offset from X0)")
    for back in range(1, 80):
        i2 = idx - back
        if i2 < 0:
            break
        prev = insn_list[i2]
        if prev.mnemonic.lower() == 'adrp' and prev.operands:
            rd = prev.operands[0].reg
            pg = prev.operands[1].imm
            if pg == TARGET_PAGE:
                adrp_va = prev.address
                print(f"    ADRP found {back} insns back at VA {hex(adrp_va)} (rd={rd}): {prev.mnemonic} {prev.op_str}")
                break

    print(f"  Context (showing conditional branches):")
    marks = {ins.address: f"  <<< {label} string ADD"}
    if adrp_va:
        marks[adrp_va] = "  <<< ADRP"
    show_ctx(ins.address, before=20, after=10, marks=marks)
