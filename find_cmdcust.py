#!/usr/bin/env python3
import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin','rb').read()

# CRITICAL: disasm_addr = file_offset - 0x1000
# So disasm 0x35fb8 = file 0x36fb8 (CmdCustUnlockFlash)
# And disasm 0x361c0 = file 0x371c0 (oem get_unlock_code display)

DISASM_TO_FILE = 0x1000

print('=== Looking for callers of CmdCustUnlockFlash ===')
print(f'CmdCustUnlockFlash: disasm 0x35fb8, file 0x{0x35fb8 + DISASM_TO_FILE:x}')
target_file = 0x35fb8 + DISASM_TO_FILE  # = 0x36fb8

for off in range(0x1000, 0x6a000, 4):
    insn = struct.unpack_from('<I', data, off)[0]
    if (insn & 0xfc000000) == 0x94000000:  # BL
        imm = (insn & 0x3ffffff)
        if imm & (1<<25): imm -= (1<<26)
        target = (off + imm*4) & 0xffffffff
        if target == target_file:
            print(f'  BL at file 0x{off:x} (disasm 0x{off-DISASM_TO_FILE:x}): bl 0x{target:x} (disasm 0x{target-DISASM_TO_FILE:x})')
    elif (insn & 0xfc000000) == 0x14000000:  # B (tail call)
        imm = (insn & 0x3ffffff)
        if imm & (1<<25): imm -= (1<<26)
        target = (off + imm*4) & 0xffffffff
        if target == target_file:
            print(f'  B  at file 0x{off:x} (disasm 0x{off-DISASM_TO_FILE:x}): b 0x{target:x}')

print()
print('=== Table dispatch: look for func ptr == 0x36fb8 ===')
# In dispatch table, look for entry whose function pointer = 0x36fb8 = CmdCustUnlockFlash file addr
for addr in range(0x633b8, 0x636c0, 16):
    str_ptr = struct.unpack_from('<Q', data, addr)[0]
    func_ptr = struct.unpack_from('<Q', data, addr+8)[0]
    if func_ptr == target_file:
        s = b''
        j = str_ptr
        while j < str_ptr+60 and data[j] and data[j] < 0x80:
            s += bytes([data[j]])
            j += 1
        print(f'  dispatch[0x{addr:x}]: str={repr(s[:40])}, func=0x{func_ptr:x}')
    if func_ptr == 0x371c0:  # oem get_unlock_code
        s = b''
        j = str_ptr
        while j < str_ptr+60 and data[j] and data[j] < 0x80:
            s += bytes([data[j]])
            j += 1
        print(f'  dispatch[0x{addr:x}]: str={repr(s[:40])}, func=0x371c0 (get_unlock_code)')

print()
print('=== Get_unlock_code function callers ===')
target2 = 0x371c0  # file addr
for off in range(0x1000, 0x6a000, 4):
    insn = struct.unpack_from('<I', data, off)[0]
    if (insn & 0xfc000000) == 0x94000000:
        imm = (insn & 0x3ffffff)
        if imm & (1<<25): imm -= (1<<26)
        target = (off + imm*4) & 0xffffffff
        if target == target2:
            print(f'  BL at file 0x{off:x} (disasm 0x{off-DISASM_TO_FILE:x})')

print()
print('=== Read disasm context around 0x390f8 (handler for lsnsnfwydjhwtk cmd) ===')
print('This is handler file=0x3a0f8, disasm=0x390f8')
# Looking for what 0x390f8 calls
for off in range(0x39000+DISASM_TO_FILE, 0x3a000+DISASM_TO_FILE, 4):  # file range
    insn = struct.unpack_from('<I', data, off)[0]
    if (insn & 0xfc000000) == 0x94000000:
        imm = (insn & 0x3ffffff)
        if imm & (1<<25): imm -= (1<<26)
        target = (off + imm*4) & 0xffffffff
        print(f'  BL at file 0x{off:x} (disasm 0x{off-DISASM_TO_FILE:x}): -> file 0x{target:x} (disasm 0x{target-DISASM_TO_FILE:x})')
