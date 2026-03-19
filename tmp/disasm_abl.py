#!/usr/bin/env python3
"""Disassemble init_param_sw_prj_id and related functions in ABL binary."""
from capstone import *
import struct

with open('/tmp/abl_dec.bin', 'rb') as f:
    data = f.read()

MZ_OFFSET = 0xB8
PE_BASE = 0  # imageBase = 0

# .text: file 0x10B8 - 0x6A0B8, RVA 0x1000-0x6A000
TEXT_FILE_START = 0x10B8
TEXT_FILE_END = 0x6A0B8
TEXT_RVA_START = 0x1000

def file_to_rva(foff):
    return foff - MZ_OFFSET  # Since sections have raw_ptr == virt_addr effectively

def rva_to_file(rva):
    return rva + MZ_OFFSET

# Key string file offsets -> RVAs
STRING_RVAS = {
    'init_param_sw_prj_id': 0x06139D,
    'Failed to read sw prj id proc flag': 0x0613B1,
    'sw_proj_id_proc: %u': 0x0613E4,
    'Process: start backup': 0x0613F9,
    'Store SPI to RPMB success': 0x06142B,
    'RPMB enalbed. Clean backup proc flag': 0x061453,
    'Failed to set sw proj procedure flag': 0x061481,
    'Failed to store SPI to RPMB': 0x0614B2,
    'Process: check and restore from RPMB': 0x0614DB,
    'Not equal. Restore.': 0x061514,
    'Failed to set sw prj id': 0x061534,
    'Set Sw proj support flag': 0x06155A,
    'Failed to set support flag': 0x061578,
    'Software ID equals!': 0x0615A4,
    'GetParamSoftwareProjectIDProcState': 0x06074F,
    'GetParamSoftwareProjectIDProcState %d': 0x060772,
    'GetParamSoftwareProjectID': 0x060666,
    'rpmb_enable=%a': 0x05F9D5,
}

# Search for ADRP instructions targeting key string pages
print("=== Finding ADRP references to key strings ===")

# Pre-compute target pages
target_pages = {}
for name, rva in STRING_RVAS.items():
    page = rva & ~0xFFF
    if page not in target_pages:
        target_pages[page] = []
    target_pages[page].append((name, rva))

# Scan all ADRP instructions
adrp_refs = {}  # file_offset -> (target_page, rd)
for off in range(TEXT_FILE_START, TEXT_FILE_END - 4, 4):
    insn = struct.unpack_from('<I', data, off)[0]
    # ADRP: bit[31]=1, bit[28:24]=10000
    if (insn >> 24) & 0x9F != 0x90:
        continue

    pc_rva = file_to_rva(off)
    pc_page = pc_rva & ~0xFFF
    immlo = (insn >> 29) & 3
    immhi = (insn >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & 0x100000:
        imm |= ~0x1FFFFF  # sign extend
        imm &= 0xFFFFFFFF
        imm = imm - 0x100000000 if imm > 0x7FFFFFFF else imm
    adrp_target = (pc_page + (imm << 12)) & 0xFFFFFFFF
    rd = insn & 0x1F

    if adrp_target in target_pages:
        # Check ADD following
        if off + 4 < TEXT_FILE_END:
            next_insn = struct.unpack_from('<I', data, off + 4)[0]
            # ADD Xd, Xn, #imm12
            if (next_insn >> 22) & 0x3FF == 0x244:  # 64-bit ADD immediate
                add_rd = next_insn & 0x1F
                add_rn = (next_insn >> 5) & 0x1F
                add_imm = (next_insn >> 10) & 0xFFF
                if add_rn == rd:
                    full_rva = adrp_target + add_imm
                    for (name, str_rva) in target_pages[adrp_target]:
                        if full_rva == str_rva:
                            if name not in adrp_refs:
                                adrp_refs[name] = []
                            adrp_refs[name].append((off, pc_rva, add_rd))

for name, refs in sorted(adrp_refs.items(), key=lambda x: x[1][0][1] if x[1] else 0):
    for (foff, rva, rd) in refs:
        print(f"  0x{rva:06X}: ref to '{name}' (X{rd})")

# Now, find the function boundary for init_param_sw_prj_id
# It's referenced at some call sites. Let's find the function that references
# the log strings.
print("\n=== Disassembling around init_param_sw_prj_id references ===")

# Find the reference to 'sw_proj_id_proc: %u' which is the first log message
# in the function
proc_refs = adrp_refs.get('sw_proj_id_proc: %u', [])
if not proc_refs:
    proc_refs = adrp_refs.get('Failed to read sw prj id proc flag', [])

if proc_refs:
    # Get the first reference
    first_ref_file, first_ref_rva, _ = proc_refs[0]

    # Find function start by looking backwards for function prologue
    # STP X29, X30, [SP, #-xxx]!  (push frame pointer and return address)
    func_start = None
    for off in range(first_ref_file, max(TEXT_FILE_START, first_ref_file - 0x2000), -4):
        insn = struct.unpack_from('<I', data, off)[0]
        # STP with pre-index writeback to SP
        # Pattern: STP Xt1, Xt2, [SP, #imm]!
        # Encoding: x010100110 for STP pre-index
        if (insn >> 22) & 0x3FF == 0x2A6:  # STP X pre-index
            rn = (insn >> 5) & 0x1F
            rt1 = insn & 0x1F
            rt2 = (insn >> 10) & 0x1F
            if rn == 31 and rt1 == 29 and rt2 == 30:  # SP, X29, X30
                func_start = off
                break

    if func_start is None:
        # Try finding SUB SP, SP pattern
        for off in range(first_ref_file, max(TEXT_FILE_START, first_ref_file - 0x2000), -4):
            insn = struct.unpack_from('<I', data, off)[0]
            # STP with signed offset to SP (not pre-index)
            if (insn >> 22) & 0x3FF == 0x2A4:  # STP X signed
                rn = (insn >> 5) & 0x1F
                rt1 = insn & 0x1F
                rt2 = (insn >> 10) & 0x1F
                if rn == 31 and rt1 == 29 and rt2 == 30:
                    func_start = off
                    break

    if func_start is None:
        func_start = first_ref_file - 0x200  # fallback
        print(f"  Could not find function prologue, using offset 0x{func_start:X}")
    else:
        print(f"  Function prologue at file 0x{func_start:X} (RVA 0x{file_to_rva(func_start):X})")

    # Disassemble using capstone
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    # Find function end - look for RET or next function prologue
    func_end = min(func_start + 0x800, TEXT_FILE_END)

    code = data[func_start:func_end]
    base_rva = file_to_rva(func_start)

    # Create a map of RVAs to string names for annotation
    rva_to_string = {}
    for name, refs in adrp_refs.items():
        for (foff, rva, rd) in refs:
            rva_to_string[rva] = name

    print(f"\n--- Disassembly from RVA 0x{base_rva:X} ---")
    ret_count = 0
    for insn in md.disasm(code, base_rva):
        annotation = ""
        if insn.address in rva_to_string:
            annotation = f"  ; >>> {rva_to_string[insn.address]}"

        # Also annotate BL targets
        if insn.mnemonic == 'bl':
            # Get target from operand
            target = insn.op_str
            annotation = f"  ; call {target}"
        elif insn.mnemonic == 'ret':
            ret_count += 1
            annotation = "  ; <<< RETURN"

        print(f"  0x{insn.address:06X}: {insn.mnemonic:8s} {insn.op_str:40s}{annotation}")

        # Stop after second RET (likely end of function)
        if ret_count >= 2:
            break

# Also disassemble GetParamSoftwareProjectIDProcState
print("\n=== Disassembling GetParamSoftwareProjectIDProcState ===")
proc_state_refs = adrp_refs.get('GetParamSoftwareProjectIDProcState', [])
if proc_state_refs:
    first_ref_file, first_ref_rva, _ = proc_state_refs[0]

    func_start = None
    for off in range(first_ref_file, max(TEXT_FILE_START, first_ref_file - 0x200), -4):
        insn_val = struct.unpack_from('<I', data, off)[0]
        if (insn_val >> 22) & 0x3FF in (0x2A6, 0x2A4):
            rn = (insn_val >> 5) & 0x1F
            rt1 = insn_val & 0x1F
            rt2 = (insn_val >> 10) & 0x1F
            if rn == 31 and rt1 == 29 and rt2 == 30:
                func_start = off
                break

    if func_start:
        print(f"  Function at RVA 0x{file_to_rva(func_start):X}")
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        code = data[func_start:func_start + 0x300]
        base_rva = file_to_rva(func_start)

        for insn in md.disasm(code, base_rva):
            ann = ""
            if insn.address in rva_to_string:
                ann = f"  ; >>> {rva_to_string[insn.address]}"
            if insn.mnemonic == 'ret':
                ann = "  ; <<< RETURN"
            print(f"  0x{insn.address:06X}: {insn.mnemonic:8s} {insn.op_str}{ann}")
            if insn.mnemonic == 'ret':
                break

# Also disassemble GetParamSoftwareProjectID
print("\n=== Disassembling GetParamSoftwareProjectID ===")
get_swid_refs = adrp_refs.get('GetParamSoftwareProjectID', [])
if get_swid_refs:
    first_ref_file, first_ref_rva, _ = get_swid_refs[0]

    func_start = None
    for off in range(first_ref_file, max(TEXT_FILE_START, first_ref_file - 0x200), -4):
        insn_val = struct.unpack_from('<I', data, off)[0]
        if (insn_val >> 22) & 0x3FF in (0x2A6, 0x2A4):
            rn = (insn_val >> 5) & 0x1F
            rt1 = insn_val & 0x1F
            rt2 = (insn_val >> 10) & 0x1F
            if rn == 31 and rt1 == 29 and rt2 == 30:
                func_start = off
                break

    if func_start:
        print(f"  Function at RVA 0x{file_to_rva(func_start):X}")
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        code = data[func_start:func_start + 0x300]
        base_rva = file_to_rva(func_start)

        for insn in md.disasm(code, base_rva):
            ann = ""
            if insn.address in rva_to_string:
                ann = f"  ; >>> {rva_to_string[insn.address]}"
            if insn.mnemonic == 'ret':
                ann = "  ; <<< RETURN"
            print(f"  0x{insn.address:06X}: {insn.mnemonic:8s} {insn.op_str}{ann}")
            if insn.mnemonic == 'ret':
                break
