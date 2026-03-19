#!/usr/bin/env python3
import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin','rb').read()

# Read around 0x5f500 to understand model number usage
print('=== Strings at 0x5f4e0 - 0x5fb70 ===')
i = 0x5f4e0
while i < 0x5fb70:
    s = b''
    start = i
    while i < 0x5fb70 and data[i]:
        s += bytes([data[i]])
        i += 1
    if s and len(s) >= 2:
        printable = ''.join(chr(b) if 32 <= b < 127 else f'\\x{b:02x}' for b in s)
        print(f'  0x{start:x} [{len(s)}]: {repr(printable[:80])}')
    i += 1

# Now look at callers of 0x35fb8 to find the wrapper function
print()
print('=== BL calls in 0x35b50-0x35c80 ===')
for line_addr in range(0x35b50, 0x35c80, 4):
    insn = struct.unpack_from('<I', data, line_addr)[0]
    if (insn & 0xfc000000) == 0x94000000:  # BL
        imm = (insn & 0x3ffffff)
        if imm & (1<<25): imm -= (1<<26)
        target = (line_addr + imm*4) & 0xffffffff
        print(f'  0x{line_addr:x}: bl 0x{target:x}')
    elif insn == 0xd65f03c0:
        print(f'  0x{line_addr:x}: ret')

# Find what calls the wrapper at 0x35b64 area
print()
print('=== What calls functions in 0x35b00-0x35c80? ===')
for off in range(0x1000, 0x69000, 4):
    insn = struct.unpack_from('<I', data, off)[0]
    if (insn & 0xfc000000) == 0x94000000:
        imm = (insn & 0x3ffffff)
        if imm & (1<<25): imm -= (1<<26)
        target = (off + imm*4) & 0xffffffff
        if 0x35b00 <= target <= 0x35c80:
            print(f'  0x{off:x}: bl 0x{target:x}')

print()
print('=== Dispatch table entries with funcs in 0x35xxx range ===')
for addr in range(0x633b8, 0x63600, 16):
    str_ptr = struct.unpack_from('<Q', data, addr)[0]
    func_ptr = struct.unpack_from('<Q', data, addr+8)[0]
    if 0x35000 <= func_ptr <= 0x36fff:
        s = b''
        if 0x60000 <= str_ptr < 0x70000:
            j = str_ptr
            while j < str_ptr+60 and data[j]:
                s += bytes([data[j]])
                j += 1
        printable = ''.join(chr(b) if 32<=b<127 else '.' for b in s)
        print(f'  0x{addr:x}: str=0x{str_ptr:x} "{printable[:40]}", func=0x{func_ptr:x}')
