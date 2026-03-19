#!/usr/bin/env python3
"""Disassemble Func_0x189E8 fully, and functions it calls."""

from capstone import *

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

with open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb') as f:
    data = f.read()

def disasm_func(start, max_len=400, title=""):
    code = data[start:start+max_len]
    print(f"=== {title} @ 0x{start:X} ===")
    ret_count = 0
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
        if insn.mnemonic == 'ret':
            ret_count += 1
            if ret_count >= 2:
                break
        if insn.mnemonic == 'udf':
            break
    print()

# Full 0x189E8
disasm_func(0x189E8, 200, "Func_0x189E8 (full)")

# 0x1DAC - called from 0x189E8
disasm_func(0x1DAC, 100, "Func_0x1DAC (first check)")

# 0x1DA4 - called from 0x189E8
disasm_func(0x1DA4, 100, "Func_0x1DA4 (second check)")

# Check 0x38800 (where IsSecureBootEnabled at 0x189E0 jumps to)
disasm_func(0x38800, 200, "IsSecureBootEnabled_body at 0x38800")

# Check the strings used in the unlock function
print("=== Key strings ===")
for addr in [0x5BEA4, 0x5BE64, 0x5C0F8, 0x5C119, 0x5C144]:
    s = data[addr:addr+100]
    end_idx = s.find(0)
    if end_idx > 0:
        s = s[:end_idx]
    try:
        print(f"  0x{addr:05X}: '{s.decode('ascii', errors='replace')}'")
    except:
        pass

# Now let's check what 0x22EDC calls - in full context
print("\n=== Full flow from 0x22EDC to 0x23010 ===")
print("0x22EDC: bl 0x189E8 → returns x0")
print("0x22EE0: cbz x0, 0x22F50 → if x0=0, skip inverse write")
print("0x22EE4: tst w23, #0xff → test unlock value")
print("0x22EF0: cset w8, eq → w8 = INVERSE of w23")
print("0x22EF8: cbz w22, 0x22FEC → device_unlock path")
print("0x22FEC: strb w8, [x1, #0xd] → WRITE INVERSE to is_unlocked")
print()
print("Conclusion:")
print("  If 0x189E8 returns NON-ZERO (likely SecureBoot=true),")
print("  then is_unlocked is OVERWRITTEN with INVERSE value.")
print("  If 0x189E8 returns ZERO (no SecureBoot),")
print("  then 0x22F50 path is taken (different unlock flow).")
