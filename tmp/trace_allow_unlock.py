#!/usr/bin/env python3
"""
Trace IsAllowUnlock at 0x48534 and other callers of 0x189E8.
"""

from capstone import *
import struct

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

with open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb') as f:
    data = f.read()

def disasm_range(start, end, title=""):
    code = data[start:end]
    print(f"\n=== {title} (0x{start:X}-0x{end:X}) ===")
    for insn in md.disasm(code, start):
        extra = ''
        if insn.mnemonic == 'bl':
            extra = f'  ; CALL 0x{insn.operands[0].imm:X}'
        elif insn.mnemonic == 'blr':
            extra = '  ; INDIRECT CALL'
        elif insn.mnemonic == 'adrp':
            extra = f'  ; page=0x{insn.operands[1].imm:X}'
        elif insn.mnemonic in ('b', 'b.eq', 'b.ne', 'b.gt', 'b.lt', 'b.ge', 'b.le',
                               'b.hi', 'b.lo', 'b.hs', 'b.ls', 'cbz', 'cbnz', 'tbz', 'tbnz'):
            for op in insn.operands:
                if op.type == 2:
                    extra = f'  ; -> 0x{op.imm:X}'
        elif 'str' in insn.mnemonic:
            extra = '  ; *** STORE ***'
        print(f"  0x{insn.address:05X}: {insn.mnemonic:<8s} {insn.op_str}{extra}")

# 1. Context around IsAllowUnlock reference at 0x48534
print("=== IsAllowUnlock context at 0x48534 ===")
# Find function start
func_start = 0x48534
for scan in range(0x48534 - 4, 0x48000, -4):
    word = struct.unpack_from('<I', data, scan)[0]
    if word == 0xD65F03C0 or (word & 0xFFFF0000) == 0x00000000:
        func_start = scan + 4
        break

disasm_range(func_start, 0x48600, f"IsAllowUnlock function (from 0x{func_start:X})")

# 2. Caller at 0x0184C (early boot)
print("\n\n")
# Find function containing 0x0184C
func_start2 = 0x0184C
for scan in range(0x0184C - 4, 0x01000, -4):
    word = struct.unpack_from('<I', data, scan)[0]
    if word == 0xD65F03C0 or (word & 0xFFFF0000) == 0x00000000:
        func_start2 = scan + 4
        break

disasm_range(max(func_start2, 0x01800), 0x01900, f"Early boot caller at 0x0184C (from ~0x{func_start2:X})")

# 3. Caller at 0x46BCC
func_start3 = 0x46BCC
for scan in range(0x46BCC - 4, 0x46000, -4):
    word = struct.unpack_from('<I', data, scan)[0]
    if word == 0xD65F03C0 or (word & 0xFFFF0000) == 0x00000000:
        func_start3 = scan + 4
        break

disasm_range(max(func_start3, 0x46B00), 0x46C80, f"Third caller at 0x46BCC (from ~0x{func_start3:X})")

# 4. What function is at 0x48534? Check strings nearby
print("\n=== Strings near 0x48534's function ===")
# The string is used with ADRP x1, #0x66000 + ADD x1, x1, #0xDD2
# This is likely a debug print: Print("IsAllowUnlock is %d\n", value)
# What's the value? Let's check what's loaded into x2 (the %d parameter) before the print

# Let's search for the "IsAllowUnlock" check function itself
# Look for functions named or related to IsAllowUnlock
# Check the string at 0x63090 "oem unlock" more context
s = data[0x63080:0x630C0]
print(f"Strings near 0x63090:")
for off in range(0, len(s)):
    if s[off] == 0 and off + 1 < len(s) and 0x20 <= s[off+1] < 0x7f:
        end = s.find(0, off+1)
        if end > off+1:
            try:
                print(f"  0x{0x63080+off+1:05X}: '{s[off+1:end].decode('ascii')}'")
            except:
                pass

# 5. Find what function gets registered for "oem unlock" command
# The fastboot command table typically has pairs of (string, handler_function)
# Search for pointer to "oem unlock" string
oem_unlock_addr = 0x63090
# In the data section, search for a pointer to this address
print(f"\n=== Searching for pointers to 'oem unlock' at 0x{oem_unlock_addr:X} ===")
for off in range(0x6A000, len(data) - 8, 8):
    val = struct.unpack_from('<Q', data, off)[0]
    if val == oem_unlock_addr:
        # Found! Check nearby for handler pointer
        print(f"  Pointer at 0x{off:05X} → 0x{oem_unlock_addr:X}")
        # Check surrounding qwords for function pointers
        for delta in range(-32, 40, 8):
            ptr = struct.unpack_from('<Q', data, off+delta)[0]
            if 0x1000 <= ptr < 0x69000:
                print(f"    [{delta:+d}] 0x{ptr:05X} (code ptr)")
            elif ptr < 0x200000:
                print(f"    [{delta:+d}] 0x{ptr:X}")
