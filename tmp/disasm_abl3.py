#!/usr/bin/env python3
"""Find ADRP+ADD pairs with wider search window."""
import struct
from capstone import *

with open('/tmp/abl_dec.bin', 'rb') as f:
    data = f.read()

MZ = 0xB8

str_rvas = {
    0x06139D: 'init_param_sw_prj_id',
    0x0613B1: 'Failed to read sw prj id proc flag',
    0x0613E4: 'sw_proj_id_proc: %u (fmt)',
    0x0613F9: 'Process: start backup to RPMB',
    0x06142B: 'Store SPI to RPMB success',
    0x061453: 'RPMB enalbed. Clean backup proc flag',
    0x061481: 'Failed to set sw proj procedure flag',
    0x0614B2: 'Failed to store SPI to RPMB',
    0x0614DB: 'Process: check and restore from RPMB',
    0x061514: 'Not equal. Restore.',
    0x061534: 'Failed to set sw prj id',
    0x06155A: 'Set Sw proj support flag',
    0x061578: 'Failed to set support flag',
    0x0615A4: 'Software ID equals!',
    0x06074F: 'GetParamSoftwareProjectIDProcState',
    0x060772: 'GetParamSoftwareProjectIDProcState %d',
    0x060666: 'GetParamSoftwareProjectID',
    0x060690: 'GetParamSoftwareProjectID %d',
    0x05F9D5: 'rpmb_enable=%a',
}

# Group by page
page_offsets = {}
for rva, name in str_rvas.items():
    page = rva & ~0xFFF
    off12 = rva & 0xFFF
    if page not in page_offsets:
        page_offsets[page] = {}
    page_offsets[page][off12] = name

# For each ADRP targeting a page of interest, search next 20 instructions for matching ADD
TEXT_START = 0x10B8
TEXT_END = 0x6A0B8
SEARCH_WINDOW = 20  # instructions

refs = []

for adrp_off in range(TEXT_START, TEXT_END - 4, 4):
    insn = struct.unpack_from('<I', data, adrp_off)[0]
    if (insn >> 24) & 0x9F != 0x90:
        continue

    pc_rva = adrp_off - MZ
    pc_page = pc_rva & ~0xFFF
    immlo = (insn >> 29) & 3
    immhi = (insn >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & 0x100000:
        imm -= 0x200000
    adrp_target = pc_page + (imm << 12)
    rd = insn & 0x1F

    if adrp_target not in page_offsets:
        continue

    # Search following instructions for ADD to same register
    for i in range(1, SEARCH_WINDOW + 1):
        next_off = adrp_off + i * 4
        if next_off >= TEXT_END:
            break
        ni = struct.unpack_from('<I', data, next_off)[0]

        # Check for ADD Xd, Xn, #imm12 (64-bit, no shift)
        if (ni >> 22) & 0x3FF == 0x244:
            add_rn = (ni >> 5) & 0x1F
            add_imm = (ni >> 10) & 0xFFF
            add_rd = ni & 0x1F
            if add_rn == rd and add_imm in page_offsets[adrp_target]:
                name = page_offsets[adrp_target][add_imm]
                refs.append((pc_rva, name, rd, add_rd, i))
                break

        # Check if another ADRP to same register invalidates our search
        if (ni >> 24) & 0x9F == 0x90 and (ni & 0x1F) == rd:
            break  # rd was overwritten
        # Also check for MOV to rd
        # MOVZ: [31]=1 [30:29]=10 [28:23]=100101 -> top byte: 110100101
        # Actually just check for any instruction that writes to rd
        # This is complex, let's just check a few common patterns

print(f"=== Found {len(refs)} references ===")
for (rva, name, adrp_rd, add_rd, dist) in sorted(refs, key=lambda x: x[0]):
    print(f"  0x{rva:06X}: X{adrp_rd}->X{add_rd} (+{dist}) '{name}'")

# Now let's find the init_param_sw_prj_id function
print("\n=== init_param_sw_prj_id function context ===")
func_refs = [r for r in refs if 'init_param_sw_prj_id' == r[1]]
if func_refs:
    # Find the first ref that loads the function name
    name_ref_rva = func_refs[0][0]
    print(f"Function name loaded at RVA 0x{name_ref_rva:06X}")

    # The function should start before this. Look for prologue.
    foff = name_ref_rva + MZ
    prologue = None
    for off in range(foff, max(TEXT_START, foff - 0x400), -4):
        insn_val = struct.unpack_from('<I', data, off)[0]
        # STP pre-index or signed offset
        if (insn_val >> 22) & 0x3FF in (0x2A6, 0x2A4):
            rt1 = insn_val & 0x1F
            rt2 = (insn_val >> 10) & 0x1F
            rn = (insn_val >> 5) & 0x1F
            if rn == 31 and rt1 == 29 and rt2 == 30:
                prologue = off
                break

    if prologue:
        # Check for SUB SP before STP
        prev = struct.unpack_from('<I', data, prologue - 4)[0]
        if (prev >> 22) & 0x3FF == 0x344 and (prev & 0x1F) == 31:
            prologue -= 4

        start_rva = prologue - MZ
        print(f"Prologue at RVA 0x{start_rva:06X}")

        # Disassemble the full function
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        code = data[prologue:prologue + 0x800]

        # Build annotation map
        ann = {}
        for (r_rva, r_name, _, _, _) in refs:
            ann[r_rva] = f" ; >>> {r_name}"

        ret_count = 0
        for ins in md.disasm(code, start_rva):
            a = ann.get(ins.address, "")
            if ins.mnemonic == 'ret':
                ret_count += 1
                a = " ; <<< RETURN"
            elif ins.mnemonic == 'bl':
                a = f" ; call"
            print(f"  0x{ins.address:06X}: {ins.mnemonic:8s} {ins.op_str:40s}{a}")
            if ret_count >= 2:
                break

# Now find and disassemble GetParamSoftwareProjectIDProcState
print("\n=== GetParamSoftwareProjectIDProcState ===")
proc_refs = [r for r in refs if 'GetParamSoftwareProjectIDProcState' == r[1] and '%d' not in r[1]]
if proc_refs:
    name_ref_rva = proc_refs[0][0]
    foff = name_ref_rva + MZ
    prologue = None
    for off in range(foff, max(TEXT_START, foff - 0x200), -4):
        insn_val = struct.unpack_from('<I', data, off)[0]
        if (insn_val >> 22) & 0x3FF in (0x2A6, 0x2A4):
            rt1 = insn_val & 0x1F
            rt2 = (insn_val >> 10) & 0x1F
            rn = (insn_val >> 5) & 0x1F
            if rn == 31 and rt1 == 29 and rt2 == 30:
                prologue = off
                break

    if prologue:
        prev = struct.unpack_from('<I', data, prologue - 4)[0]
        if (prev >> 22) & 0x3FF == 0x344 and (prev & 0x1F) == 31:
            prologue -= 4

        start_rva = prologue - MZ
        print(f"Prologue at RVA 0x{start_rva:06X}")

        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        code = data[prologue:prologue + 0x400]

        ann2 = {}
        for (r_rva, r_name, _, _, _) in refs:
            ann2[r_rva] = f" ; >>> {r_name}"

        for ins in md.disasm(code, start_rva):
            a = ann2.get(ins.address, "")
            if ins.mnemonic == 'ret':
                a = " ; <<< RETURN"
            print(f"  0x{ins.address:06X}: {ins.mnemonic:8s} {ins.op_str:40s}{a}")
            if ins.mnemonic == 'ret':
                break
