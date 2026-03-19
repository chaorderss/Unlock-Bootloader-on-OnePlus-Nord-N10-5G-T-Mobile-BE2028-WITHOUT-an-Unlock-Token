#!/usr/bin/env python3
import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin','rb').read()

# Find callers of the flash-token handler at disasm 0x48bf8 (file 0x49bf8)
target_file = 0x49bf8
results = []
for i in range(0, len(data)-4, 4):
    instr = int.from_bytes(data[i:i+4], 'little')
    op = instr >> 26
    if op in (0b100101, 0b000101):  # BL or B
        imm26 = instr & 0x3FFFFFF
        if imm26 & 0x2000000:
            imm26 |= ~0x3FFFFFF
        offset = imm26 << 2
        tgt = i + offset
        if tgt == target_file:
            op_name = 'BL' if op == 0b100101 else 'B'
            print(f'{op_name} at file 0x{i:x} (disasm 0x{i-0x1000:x}) -> 0x{tgt:x}')
            results.append(i)
print(f'Total callers: {len(results)}')

# Also check if 0x49bf8 appears as a function pointer in data sections
print("\n=== Searching for function pointer references ===")
for addr, name in [(0x49bf8, 'flash_token_handler'), (0x48bf8, 'flash_token_disasm')]:
    # 8-byte pointers
    for i in range(0x6a000, min(len(data)-8, 0x200000), 8):
        ptr = struct.unpack_from('<Q', data, i)[0]
        if ptr == addr:
            print(f'PTR8 at file 0x{i:x}: 0x{ptr:x} ({name})')
    # 4-byte pointers
    for i in range(0x6a000, min(len(data)-4, 0x200000), 4):
        ptr = struct.unpack_from('<I', data, i)[0]
        if ptr == addr:
            print(f'PTR4 at file 0x{i:x}: 0x{ptr:x} ({name})')

# Also look at the strings referenced around disasm 0x48c34 and 0x65e08/0x65e19
# (those were the "token too large" and "no token" error strings)
print("\n=== Strings at 0x65e08, 0x65e19, 0x67000+0x1fa, 0x67000+0x218 ===")
for offset_disasm, desc in [
    (0x65e08, 'error_str_1'),
    (0x65e19, 'error_str_2'),
    (0x671fa, 'partition_related_1'),
    (0x67218, 'partition_related_2'),
]:
    file_off = offset_disasm + 0x1000
    s = data[file_off:file_off+64]
    null_pos = s.find(b'\x00')
    if null_pos >= 0:
        s = s[:null_pos]
    print(f'  0x{offset_disasm:x} (file 0x{file_off:x}) [{desc}]: {s}')
