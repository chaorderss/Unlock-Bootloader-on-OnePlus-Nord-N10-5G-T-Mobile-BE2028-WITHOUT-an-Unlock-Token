#!/usr/bin/env python3
"""
Find code that references IsAllowUnlock and the VB protocol method_0x30.
Also trace the other GUID reference at 0x027CC more fully.
"""

from capstone import *
import struct

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

with open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb') as f:
    data = f.read()

# 1. Search for ALL references to address 0x66DD2 by any method
# The string could be loaded via:
# a) ADRP xN, page + ADD xN, xN, #offset
# b) ADRP xN, page + LDR xN, [xN, #offset]  (if it's a pointer)
# c) ADR xN, addr (small offset)

str_addr = 0x66DD2
str_page = str_addr & ~0xFFF  # 0x66000
str_off = str_addr & 0xFFF    # 0xDD2

print(f"=== Method 1: ADRP references to page 0x{str_page:X} ===")
code = data[0x1000:0x69000]
adrp_refs = []
idx = 0
for insn in md.disasm(code, 0x1000):
    if insn.mnemonic == 'adrp' and len(insn.operands) >= 2:
        if insn.operands[1].imm == str_page:
            adrp_refs.append((insn.address, insn.operands[0].reg))

print(f"Found {len(adrp_refs)} ADRP to page 0x{str_page:X}")
for addr, reg in adrp_refs[:30]:
    # Check next few instructions for ADD/LDR with offset 0xDD2
    for delta in range(4, 20, 4):
        next_code = data[addr+delta:addr+delta+4]
        for ni in md.disasm(next_code, addr+delta):
            if f'0x{str_off:x}' in ni.op_str or f'#{str_off}' in ni.op_str:
                print(f"  MATCH: 0x{addr:05X}: adrp + 0x{addr+delta:05X}: {ni.mnemonic} {ni.op_str}")

# 2. Also try: search for the string bytes as an immediate in ADR instruction
# ADR has ±1MB range
print(f"\n=== Method 2: Search raw for IsAllowUnlock address via binary pattern ===")
# The ADD immediate for 0xDD2 would be encoded in the instruction
# ADD Xd, Xn, #imm12 : bits [21:10] = imm12
# 0xDD2 = 3538 = 0b1101_1101_0010
# In ADD encoding: 1001_0001_00 | imm12 | Rn | Rd
add_imm = 0xDD2
# ADD X_,X_,#0xDD2 encoding:
# 10010001_00_IIIIIIIIIIII_NNNNN_DDDDD
# where I = 0xDD2 = 0b110111010010
imm12_bits = (add_imm & 0xFFF) << 10
add_base = 0x91000000 | imm12_bits
add_mask = 0xFFC00000 | (0xFFF << 10)

count = 0
for off in range(0x1000, 0x69000, 4):
    word = struct.unpack_from('<I', data, off)[0]
    if (word & add_mask) == (add_base & add_mask):
        # This is an ADD with imm=0xDD2
        for insn2 in md.disasm(data[off:off+4], off):
            if '0xdd2' in insn2.op_str.lower():
                # Check preceding ADRP
                for back in range(4, 20, 4):
                    prev = data[off-back:off-back+4]
                    for pi in md.disasm(prev, off-back):
                        if pi.mnemonic == 'adrp' and '0x66000' in hex(pi.operands[1].imm if len(pi.operands)>=2 else 0):
                            print(f"  FOUND via binary: 0x{off-back:05X}: {pi.mnemonic} {pi.op_str} + 0x{off:05X}: {insn2.mnemonic} {insn2.op_str}")
                            count += 1
                count2 = 0
                if count == 0:
                    print(f"  ADD #0xDD2 at 0x{off:05X}: {insn2.mnemonic} {insn2.op_str}")
                    count2 += 1
                    if count2 > 20:
                        break

# 3. Broader approach: disassemble the full function near 0x027CC (other VB proto user)
print("\n=== Function at ~0x027CC (other VB protocol user) ===")
# Find the function start
func_start = 0x027CC
for scan in range(0x027CC - 4, 0x01000, -4):
    word = struct.unpack_from('<I', data, scan)[0]
    if word == 0xD65F03C0:  # RET
        func_start = scan + 4
        break
    if word == 0x00000000:  # UDF #0
        func_start = scan + 4
        break

print(f"  Function start estimate: 0x{func_start:05X}")
dis_code = data[func_start:func_start+600]
for insn in md.disasm(dis_code, func_start):
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
    if insn.mnemonic == 'ret' and insn.address > 0x02900:
        break

# 4. Search for ALL protocol->method_0x30 callers
# Pattern: ldr x8, [x0, #0x30] followed by blr x8
print("\n=== All protocol->method_0x30 callers ===")
# LDR X8, [X0, #0x30] encoding: 0xF9401808
# More general: LDR Xt, [Xn, #0x30]
for off in range(0x1000, 0x69000, 4):
    word = struct.unpack_from('<I', data, off)[0]
    # LDR Xt, [Xn, #0x30] : 1111100101 offset Rn Rt
    # offset = 0x30/8 = 6, so bits [21:10] = 6 = 0b000000000110
    if (word & 0xFFC003E0) == 0xF9401800:  # LDR X?, [X0, #0x30]
        rt = word & 0x1F
        # Check if next instruction is BLR Xt
        next_word = struct.unpack_from('<I', data, off+4)[0]
        expected_blr = 0xD63F0000 | (rt << 5)
        if next_word == expected_blr:
            print(f"  0x{off:05X}: ldr x{rt}, [x0, #0x30]; blr x{rt}")

# 5. Let's also check: what calls 0x189E8?
print("\n=== All callers of 0x189E8 ===")
target = 0x189E8
for off in range(0x1000, 0x69000, 4):
    word = struct.unpack_from('<I', data, off)[0]
    if (word & 0xFC000000) == 0x94000000:  # BL
        imm26 = word & 0x3FFFFFF
        if imm26 & 0x2000000:
            imm26 |= ~0x3FFFFFF
        dest = off + (imm26 << 2)
        if dest == target:
            print(f"  0x{off:05X}: bl 0x{target:05X}")
