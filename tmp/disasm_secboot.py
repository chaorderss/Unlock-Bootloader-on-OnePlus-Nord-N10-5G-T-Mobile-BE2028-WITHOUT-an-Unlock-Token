#!/usr/bin/env python3
"""Disassemble the SecureBoot check and alternative unlock paths."""

from capstone import *

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

with open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb') as f:
    data = f.read()

def disasm_range(start, end, title):
    code = data[start:end]
    print(f"=== {title} (0x{start:X} - 0x{end:X}) ===")
    for insn in md.disasm(code, start):
        extra = ''
        if insn.mnemonic == 'bl':
            extra = f'  ; call 0x{insn.operands[0].imm:X}'
        elif insn.mnemonic == 'adrp':
            extra = f'  ; page=0x{insn.operands[1].imm:X}'
        elif insn.mnemonic in ('b', 'b.eq', 'b.ne', 'b.gt', 'b.lt', 'b.ge', 'b.le',
                               'b.hi', 'b.lo', 'b.hs', 'b.ls', 'cbz', 'cbnz', 'tbz', 'tbnz'):
            for op in insn.operands:
                if op.type == 2:
                    extra = f'  ; -> 0x{op.imm:X}'
        elif 'str' in insn.mnemonic:
            extra = '  ; *** STORE ***'
        elif 'ldr' in insn.mnemonic:
            extra = '  ; LOAD'
        print(f"  0x{insn.address:05X}: {insn.mnemonic:<8s} {insn.op_str}{extra}")
    print()

# IsSecureBootEnabled at 0x189E0
disasm_range(0x189D0, 0x18A30, "IsSecureBootEnabled area (0x189E0)")

# Function 0x189E8 - called at 0x22EDC
disasm_range(0x189E8, 0x18A30, "Func_0x189E8 (SecureBoot check?)")

# Path at 0x22F50 - taken when 0x189E8 returns 0 (no SecureBoot)
disasm_range(0x22F50, 0x22FF0, "Path 0x22F50 (0x189E8 returned 0)")

# Check strings at 0x5BEEA area
print("=== Strings near 0x5B000 ===")
for addr in [0x5BE51, 0x5BE5A, 0x5BE64, 0x5BE88, 0x5BEA4]:
    s = data[addr:addr+80]
    end_idx = s.find(0)
    if end_idx > 0:
        s = s[:end_idx]
    try:
        print(f"  0x{addr:05X}: {s.decode('ascii', errors='replace')}")
    except:
        pass

# Check strings at 0x5C0F8 and 0x5C119 and 0x5C144
for addr in [0x5C0F8, 0x5C119, 0x5C144]:
    s = data[addr:addr+80]
    end_idx = s.find(0)
    if end_idx > 0:
        s = s[:end_idx]
    try:
        print(f"  0x{addr:05X}: {s.decode('ascii', errors='replace')}")
    except:
        pass
