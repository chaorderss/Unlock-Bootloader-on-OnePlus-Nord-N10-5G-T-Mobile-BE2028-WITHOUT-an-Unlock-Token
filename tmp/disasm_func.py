#!/usr/bin/env python3
"""Disassemble init_param_sw_prj_id function at ~RVA 0x35900."""
import struct
from capstone import *

with open('/tmp/abl_dec.bin', 'rb') as f:
    data = f.read()

MZ = 0xB8
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

# String RVAs for annotations
str_rvas = {
    0x06139D: 'init_param_sw_prj_id',
    0x0613B1: 'Failed to read sw prj id proc flag',
    0x0613E4: 'sw_proj_id_proc: %u',
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

def resolve_adrp_add(pc_rva, insn, data, foff):
    """Try to resolve ADRP at pc_rva and find matching ADD in next 20 insns."""
    if (insn >> 24) & 0x9F != 0x90:
        return None
    pc_page = pc_rva & ~0xFFF
    immlo = (insn >> 29) & 3
    immhi = (insn >> 5) & 0x7FFFF
    imm21 = (immhi << 2) | immlo
    if imm21 & 0x100000:
        imm21 -= 0x200000
    adrp_target = pc_page + (imm21 << 12)
    rd = insn & 0x1F

    for i in range(1, 20):
        noff = foff + i * 4
        if noff >= len(data) - 4:
            break
        ni = struct.unpack_from('<I', data, noff)[0]
        if (ni >> 22) & 0x3FF == 0x244:
            add_rn = (ni >> 5) & 0x1F
            add_imm = (ni >> 10) & 0xFFF
            if add_rn == rd:
                full_addr = adrp_target + add_imm
                return full_addr
        if (ni >> 24) & 0x9F == 0x90 and (ni & 0x1F) == rd:
            break
    return None

# Find function prologue - scan backwards from RVA 0x35924
target = 0x35924
start_rva = target
# Scan backwards for STP X29, X30
for rva in range(target, target - 0x400, -4):
    foff = rva + MZ
    insn = struct.unpack_from('<I', data, foff)[0]
    if (insn >> 22) & 0x3FF in (0x2A6, 0x2A4):
        rt1 = insn & 0x1F
        rt2 = (insn >> 10) & 0x1F
        rn = (insn >> 5) & 0x1F
        if rn == 31 and rt1 == 29 and rt2 == 30:
            start_rva = rva
            break

# Check for SUB SP before
prev = struct.unpack_from('<I', data, start_rva + MZ - 4)[0]
if (prev >> 22) & 0x3FF == 0x344 and (prev & 0x1F) == 31:
    start_rva -= 4

print(f"=== init_param_sw_prj_id: prologue at RVA 0x{start_rva:06X} ===")
print(f"    Disassembling to RVA 0x{start_rva + 0x800:06X}\n")

foff = start_rva + MZ
code = data[foff:foff + 0x800]

ret_count = 0
for ins in md.disasm(code, start_rva):
    # Try to resolve string references
    ann = ""
    if ins.mnemonic == 'adrp':
        insn_val = struct.unpack_from('<I', data, ins.address + MZ)[0]
        resolved = resolve_adrp_add(ins.address, insn_val, data, ins.address + MZ)
        if resolved and resolved in str_rvas:
            ann = f" ; -> {str_rvas[resolved]}"
    elif ins.mnemonic == 'bl':
        ann = " ; CALL"
    elif ins.mnemonic == 'ret':
        ann = " ; RETURN"
        ret_count += 1
    elif ins.mnemonic in ('b', 'b.eq', 'b.ne', 'b.lt', 'b.gt', 'b.le', 'b.ge',
                          'b.hi', 'b.lo', 'b.hs', 'b.ls', 'b.mi', 'b.pl',
                          'cbz', 'cbnz', 'tbz', 'tbnz'):
        ann = " ; BRANCH"

    print(f"  {ins.address:06X}: {ins.mnemonic:8s} {ins.op_str:45s}{ann}")

    if ret_count >= 3:
        break

# Also find and disassemble the GetParamSoftwareProjectIDProcState function
# This is likely called by init_param_sw_prj_id
# Search the entire code for references to this string
print("\n\n=== Searching for GetParamSoftwareProjectIDProcState references ===")
# Page 0x60000, offset 0x74F
# Search for ADRP targeting 0x60000
for off in range(0x10B8, 0x6A0B8 - 4, 4):
    insn = struct.unpack_from('<I', data, off)[0]
    if (insn >> 24) & 0x9F != 0x90:
        continue
    pc_rva = off - MZ
    pc_page = pc_rva & ~0xFFF
    immlo = (insn >> 29) & 3
    immhi = (insn >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & 0x100000:
        imm -= 0x200000
    adrp_target = pc_page + (imm << 12)
    if adrp_target == 0x60000:
        rd = insn & 0x1F
        # Check for ADD with offset 0x74F or 0x666 or 0x772
        for i in range(1, 20):
            noff = off + i * 4
            if noff >= 0x6A0B8:
                break
            ni = struct.unpack_from('<I', data, noff)[0]
            if (ni >> 22) & 0x3FF == 0x244:
                add_rn = (ni >> 5) & 0x1F
                add_imm = (ni >> 10) & 0xFFF
                if add_rn == rd:
                    target_rva = 0x60000 + add_imm
                    if target_rva in str_rvas:
                        print(f"  RVA 0x{pc_rva:06X}: X{rd} -> {str_rvas[target_rva]}")
                    break
            if (ni >> 24) & 0x9F == 0x90 and (ni & 0x1F) == rd:
                break

# Also search for BL targets within init_param_sw_prj_id
print("\n=== BL call targets within init_param_sw_prj_id ===")
foff = start_rva + MZ
code = data[foff:foff + 0x800]
for ins in md.disasm(code, start_rva):
    if ins.mnemonic == 'bl':
        target_addr = int(ins.op_str.lstrip('#'), 16) if ins.op_str.startswith('#') else 0
        print(f"  0x{ins.address:06X}: BL 0x{target_addr:X}")
    if ins.mnemonic == 'ret':
        break
