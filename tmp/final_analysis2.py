#!/usr/bin/env python3
"""
Final analysis: VB protocol installation and config.bin offset check.
"""
import struct
from capstone import *

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

with open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb') as f:
    pe = f.read()

# 1. Check config.bin critical offsets
config = open('/Users/xmxx/pinganhuijia/edl_backup/lun0/config.bin', 'rb').read()
print(f"config.bin[0x7FFF] = 0x{config[0x7FFF]:02X}  (generic.py oem_unlock target)")
print(f"config.bin[0x7FFFF] = 0x{config[0x7FFFF]:02X}  (actual last byte)")
print(f"config.bin first 40 bytes: {config[:40].hex()}")

# 2. Search for data section pointers to GUID addr 0x69BE0
guid_addr = 0x69BE0
print(f"\n=== Pointers to 0x{guid_addr:X} in data section ===")
for off in range(0x6A000, len(pe) - 8, 8):
    val = struct.unpack_from('<Q', pe, off)[0]
    if val == guid_addr:
        print(f"  Found at 0x{off:05X}")
        for delta in range(-32, 40, 8):
            v = struct.unpack_from('<Q', pe, off+delta)[0]
            label = ''
            if 0x1000 <= v < 0x69000: label = ' (code)'
            elif v == guid_addr: label = ' *** GUID ***'
            print(f"    [{delta:+d}] 0x{v:016X}{label}")

# 3. Function 0x40D0 (called near GUID ref at 0x2274)
print(f"\n=== Function 0x40D0 ===")
for insn in md.disasm(pe[0x40D0:0x40D0+120], 0x40D0):
    extra = ''
    if insn.mnemonic == 'bl': extra = f'  ; CALL 0x{insn.operands[0].imm:X}'
    elif insn.mnemonic == 'adrp': extra = f'  ; page=0x{insn.operands[1].imm:X}'
    elif insn.mnemonic == 'blr': extra = '  ; INDIRECT'
    print(f"  0x{insn.address:05X}: {insn.mnemonic:<8s} {insn.op_str}{extra}")
    if insn.mnemonic == 'ret': break

# 4. First VB protocol caller at 0x027CC
print(f"\n=== First VB protocol caller (0x027CC-0x02860) ===")
for insn in md.disasm(pe[0x027CC:0x02860], 0x027CC):
    extra = ''
    if insn.mnemonic == 'bl': extra = f'  ; CALL 0x{insn.operands[0].imm:X}'
    elif insn.mnemonic == 'blr': extra = '  ; INDIRECT'
    elif insn.mnemonic == 'adrp': extra = f'  ; page=0x{insn.operands[1].imm:X}'
    elif insn.mnemonic in ('b','b.eq','b.ne','cbz','cbnz','tbz','tbnz',
                           'b.hi','b.hs','b.lo','b.ls','b.ge','b.le','b.gt','b.lt'):
        for op in insn.operands:
            if op.type == 2: extra = f'  ; -> 0x{op.imm:X}'
    elif 'str' in insn.mnemonic: extra = '  ; STORE'
    print(f"  0x{insn.address:05X}: {insn.mnemonic:<8s} {insn.op_str}{extra}")
