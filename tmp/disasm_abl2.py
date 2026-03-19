#!/usr/bin/env python3
"""Find exact ADRP+ADD references to key strings and disassemble the functions."""
import struct
from capstone import *

with open('/tmp/abl_dec.bin', 'rb') as f:
    data = f.read()

MZ = 0xB8
TEXT_START = 0x10B8
TEXT_END = 0x6A0B8

def file_to_rva(foff):
    return foff - MZ

def rva_to_file(rva):
    return rva + MZ

# String RVA -> name mapping (low 12 bits matter for ADD)
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

# Build page -> [(rva, name)] mapping
page_targets = {}
for rva, name in str_rvas.items():
    page = rva & ~0xFFF
    offset = rva & 0xFFF
    if page not in page_targets:
        page_targets[page] = {}
    page_targets[page][offset] = (rva, name)

# Scan for ADRP+ADD pairs
print("=== ADRP+ADD references to key strings ===")
refs = []  # (code_rva, string_name, register)

for off in range(TEXT_START, TEXT_END - 8, 4):
    insn = struct.unpack_from('<I', data, off)[0]
    if (insn >> 24) & 0x9F != 0x90:
        continue

    pc_rva = file_to_rva(off)
    pc_page = pc_rva & ~0xFFF
    immlo = (insn >> 29) & 3
    immhi = (insn >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & 0x100000:
        imm -= 0x200000
    adrp_target = pc_page + (imm << 12)
    rd = insn & 0x1F

    if adrp_target not in page_targets:
        continue

    # Check ADD following
    next_insn = struct.unpack_from('<I', data, off + 4)[0]
    # ADD Xd, Xn, #imm12 (sf=1, op=0, S=0, shift=00): 1001000100xxxxxxxxxxxxxxxxxxxxxx
    if (next_insn >> 22) & 0x3FF == 0x244:
        add_rn = (next_insn >> 5) & 0x1F
        add_imm = (next_insn >> 10) & 0xFFF
        if add_rn == rd and add_imm in page_targets[adrp_target]:
            target_rva, target_name = page_targets[adrp_target][add_imm]
            add_rd = next_insn & 0x1F
            refs.append((pc_rva, target_name, add_rd))
            print(f"  RVA 0x{pc_rva:06X}: ADRP+ADD X{add_rd} -> '{target_name}'")

# Group references by code region
print(f"\nTotal references found: {len(refs)}")

# Now disassemble the init_param_sw_prj_id function
# Find the first reference to 'init_param_sw_prj_id' string (function name)
func_name_refs = [r for r in refs if 'init_param_sw_prj_id' in r[1] and 'fmt' not in r[1]]
if func_name_refs:
    first_ref_rva = func_name_refs[0][0]
    print(f"\n=== init_param_sw_prj_id function, first name ref at RVA 0x{first_ref_rva:06X} ===")

    # Find function prologue
    func_start_file = rva_to_file(first_ref_rva)
    prologue_file = None
    for off in range(func_start_file, max(TEXT_START, func_start_file - 0x400), -4):
        insn = struct.unpack_from('<I', data, off)[0]
        # STP X29, X30, [SP, #imm]!  (pre-index) or STP X29, X30, [SP, #imm]
        if (insn >> 22) & 0x3FF in (0x2A6, 0x2A4):
            rt1 = insn & 0x1F
            rt2 = (insn >> 10) & 0x1F
            rn = (insn >> 5) & 0x1F
            if rn == 31 and rt1 == 29 and rt2 == 30:
                prologue_file = off
                break

    if prologue_file:
        func_start_rva = file_to_rva(prologue_file)
        print(f"  Prologue at RVA 0x{func_start_rva:06X}")

        # Also check for SUB SP before the STP
        prev_insn = struct.unpack_from('<I', data, prologue_file - 4)[0]
        if (prev_insn >> 22) & 0x3FF == 0x344:  # SUB X immediate with sf=1
            sub_rd = prev_insn & 0x1F
            if sub_rd == 31:  # SUB SP, SP, #imm
                prologue_file -= 4
                func_start_rva = file_to_rva(prologue_file)
                print(f"  SUB SP before STP at RVA 0x{func_start_rva:06X}")
    else:
        func_start_rva = first_ref_rva - 0x100
        prologue_file = rva_to_file(func_start_rva)
        print(f"  No prologue found, starting from RVA 0x{func_start_rva:06X}")

    # Disassemble the function
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    code_size = 0x1000  # disassemble up to 4KB
    code = data[prologue_file:prologue_file + code_size]

    # Build annotation map from refs
    ann_map = {}
    for (r_rva, r_name, r_rd) in refs:
        ann_map[r_rva] = f"; >>> str: {r_name}"

    print(f"\n--- Disassembly ---")
    ret_count = 0
    for ins in md.disasm(code, func_start_rva):
        ann = ann_map.get(ins.address, "")

        if ins.mnemonic == 'bl':
            # Check if target is a known function
            target_addr = int(ins.op_str.lstrip('#'), 16) if ins.op_str.startswith('#') else 0
            ann = f"; call 0x{target_addr:X}" if target_addr else ""
        elif ins.mnemonic in ('b', 'b.eq', 'b.ne', 'b.lt', 'b.gt', 'b.le', 'b.ge',
                               'b.hi', 'b.lo', 'b.hs', 'b.ls', 'b.mi', 'b.pl',
                               'cbz', 'cbnz', 'tbz', 'tbnz'):
            ann = f"; branch"
        elif ins.mnemonic == 'ret':
            ret_count += 1
            ann = "; <<< RETURN"

        line = f"  0x{ins.address:06X}: {ins.bytes.hex():16s} {ins.mnemonic:8s} {ins.op_str:40s} {ann}"
        print(line)

        if ret_count >= 3:
            break
else:
    print("\nNo references to init_param_sw_prj_id found!")

# Also find and disassemble GetParamSoftwareProjectIDProcState
print("\n\n=== GetParamSoftwareProjectIDProcState function ===")
proc_state_refs = [r for r in refs if 'ProcState' in r[1] and '%d' not in r[1]]
if proc_state_refs:
    first_ref_rva = proc_state_refs[0][0]
    func_start_file = rva_to_file(first_ref_rva)

    prologue_file = None
    for off in range(func_start_file, max(TEXT_START, func_start_file - 0x200), -4):
        insn = struct.unpack_from('<I', data, off)[0]
        if (insn >> 22) & 0x3FF in (0x2A6, 0x2A4):
            rt1 = insn & 0x1F
            rt2 = (insn >> 10) & 0x1F
            rn = (insn >> 5) & 0x1F
            if rn == 31 and rt1 == 29 and rt2 == 30:
                prologue_file = off
                break

    if prologue_file:
        func_start_rva = file_to_rva(prologue_file)
        print(f"  Prologue at RVA 0x{func_start_rva:06X}")

        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        code = data[prologue_file:prologue_file + 0x200]

        for ins in md.disasm(code, func_start_rva):
            ann = ann_map.get(ins.address, "")
            if ins.mnemonic == 'ret':
                ann = "; <<< RETURN"
            print(f"  0x{ins.address:06X}: {ins.bytes.hex():16s} {ins.mnemonic:8s} {ins.op_str:40s} {ann}")
            if ins.mnemonic == 'ret':
                break
