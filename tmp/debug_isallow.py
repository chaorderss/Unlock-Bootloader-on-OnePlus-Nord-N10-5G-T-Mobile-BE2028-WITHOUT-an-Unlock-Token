#!/usr/bin/env python3
"""
Debug: verify ADRP at 0x48530 and search for IsAllowUnlock writes more robustly.
"""

from capstone import *
import struct

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

with open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb') as f:
    data = f.read()

# 1. Directly verify instruction at 0x48530
print("=== Direct decode at 0x48530 ===")
inst_bytes = data[0x48530:0x48534]
print(f"Raw bytes: {inst_bytes.hex()}")
for insn in md.disasm(inst_bytes, 0x48530):
    print(f"  {insn.mnemonic} {insn.op_str}")
    if insn.mnemonic == 'adrp' and len(insn.operands) >= 2:
        print(f"  Operand[1].imm = 0x{insn.operands[1].imm:X}")

# 2. Search for ADRP to 0x1C0000 using raw binary encoding
# ADRP: [1] [immlo:2] [10000] [immhi:19] [Rd:5]
# The page is PC_page + (immhi:immlo << 12)
# We need to find all ADRP instructions where PC_page + offset = 0x1C0000
print("\n=== Binary search for ADRP targeting 0x1C0000 ===")
target_page = 0x1C0000

for off in range(0x1000, 0x69000, 4):
    word = struct.unpack_from('<I', data, off)[0]
    # Check if it's an ADRP
    if (word & 0x9F000000) == 0x90000000:
        # Decode the immediate
        immlo = (word >> 29) & 0x3
        immhi = (word >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000:  # sign extend
            imm |= ~0x1FFFFF
            imm &= 0xFFFFFFFF
            imm = imm if imm < 0x80000000 else imm - 0x100000000
        page_base = off & ~0xFFF
        result_page = (page_base + (imm << 12)) & 0xFFFFFFFF

        if result_page == target_page:
            rd = word & 0x1F
            print(f"  0x{off:05X}: adrp x{rd}, #0x{target_page:X}")

# 3. Also check what 0x1C0000+0x10 corresponds to
# 0x1C0010 is in the .data section (VA 0x6A000, size 0x15E000, so data up to 0x1C8000)
# But in the file, this corresponds to file offset 0x1C0010 (since VA == file offset)
print(f"\n=== Address 0x1C0010 in PE ===")
print(f"File offset 0x1C0010, section .data")
val = struct.unpack_from('<I', data, 0x1C0010)[0]
print(f"Value: 0x{val:08X}")

# Check the entire 0x1C0000-0x1C0100 range
print(f"\nDump of 0x1C0000-0x1C0030:")
for base in range(0x1C0000, 0x1C0030, 16):
    hex_str = data[base:base+16].hex()
    print(f"  0x{base:05X}: {hex_str}")

# 4. More importantly: search for ANY write to the 0x10 offset from
# an address in the 0x1C0000 page area
# This includes patterns like:
#   adrp xN, some_base → compute address → str wM, [xN, #0x10]
# But also:
#   ldr xN, [some_ptr] → str wM, [xN, #0x10]
# The value might be written through a pointer rather than ADRP

# 5. Let's instead search for who calls 0x3BBF0 (called just before IsAllowUnlock print)
# and the function containing 0x48534 to understand the full flow
print("\n=== Full IsAllowUnlock context function ===")
# Going back further to find the proper function start
for scan in range(0x48400, 0x48000, -4):
    word = struct.unpack_from('<I', data, scan)[0]
    if word == 0xD65F03C0:  # RET
        start = scan + 4
        print(f"Function starts at 0x{start:05X}")
        break

# Now disasm from 0x48400 for full context
code = data[0x48400:0x48560]
for insn in md.disasm(code, 0x48400):
    extra = ''
    if insn.mnemonic == 'bl':
        extra = f'  ; CALL 0x{insn.operands[0].imm:X}'
    elif insn.mnemonic == 'blr':
        extra = '  ; INDIRECT'
    elif insn.mnemonic == 'adrp':
        extra = f'  ; page=0x{insn.operands[1].imm:X}'
    elif insn.mnemonic in ('b', 'b.eq', 'b.ne', 'cbz', 'cbnz', 'tbz', 'tbnz',
                           'b.hi', 'b.hs', 'b.lo', 'b.ls', 'b.ge', 'b.le', 'b.gt', 'b.lt'):
        for op in insn.operands:
            if op.type == 2:
                extra = f'  ; -> 0x{op.imm:X}'
    elif 'str' in insn.mnemonic:
        extra = '  ; STORE'
    print(f"  0x{insn.address:05X}: {insn.mnemonic:<8s} {insn.op_str}{extra}")

# 6. what's at 0x3BBF0? It's called before the IsAllowUnlock print
print("\n=== Func 0x3BBF0 (called before IsAllowUnlock) ===")
code = data[0x3BBF0:0x3BC40]
for insn in md.disasm(code, 0x3BBF0):
    extra = ''
    if insn.mnemonic == 'bl':
        extra = f'  ; CALL 0x{insn.operands[0].imm:X}'
    elif insn.mnemonic == 'adrp':
        extra = f'  ; page=0x{insn.operands[1].imm:X}'
    elif insn.mnemonic in ('b', 'b.eq', 'b.ne', 'cbz', 'cbnz'):
        for op in insn.operands:
            if op.type == 2:
                extra = f'  ; -> 0x{op.imm:X}'
    print(f"  0x{insn.address:05X}: {insn.mnemonic:<8s} {insn.op_str}{extra}")
    if insn.mnemonic == 'ret':
        break

# 7. Check string at 0x66DBA for context
s = data[0x66DBA:0x66DBA+24]
end = s.find(0)
if end > 0: s = s[:end]
print(f"\nString at 0x66DBA: '{s.decode('ascii', errors='replace')}'")
