#!/usr/bin/env python3
"""Disassemble SetDeviceUnlocked area in detail."""

from capstone import *

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

with open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb') as f:
    data = f.read()

# Disassemble from 0x22C00 to 0x23100
start = 0x22C00
end = 0x23100
code = data[start:end]

print(f"=== SetDeviceUnlocked area: 0x{start:X} - 0x{end:X} ===")
for insn in md.disasm(code, start):
    extra = ''
    if insn.mnemonic == 'bl':
        target = insn.operands[0].imm
        extra = f'  ; call 0x{target:X}'
    elif insn.mnemonic in ('b', 'b.eq', 'b.ne', 'b.gt', 'b.lt', 'b.ge', 'b.le',
                           'b.hi', 'b.lo', 'b.hs', 'b.ls', 'cbz', 'cbnz', 'tbz', 'tbnz'):
        for op in insn.operands:
            if op.type == 2:  # IMM
                extra = f'  ; -> 0x{op.imm:X}'
    elif insn.mnemonic == 'adrp':
        extra = f'  ; page=0x{insn.operands[1].imm:X}'
    elif insn.mnemonic in ('strb', 'str', 'strh', 'stur', 'sturb'):
        extra = '  ; *** STORE ***'
    elif insn.mnemonic in ('ldrb', 'ldr', 'ldrh', 'ldur', 'ldurb'):
        extra = '  ; LOAD'
    print(f"  0x{insn.address:05X}: {insn.mnemonic:<8s} {insn.op_str}{extra}")
