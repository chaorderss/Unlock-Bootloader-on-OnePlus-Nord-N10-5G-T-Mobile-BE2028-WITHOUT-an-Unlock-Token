#!/usr/bin/env python3
import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin','rb').read()

# The function pointer table entry for the flash-token handler is at file 0x68458
# In .text section: disasm addr = file - 0x1000 = 0x67458
# VAddr at runtime = file offset (since delta=0)
# Function pointers stored = runtime VAddr

# Look at the area around file 0x68458
print("=== Area around file 0x68458 (flash token handler ptr) ===")
start = 0x68380
end = 0x684f0
for off in range(start, end, 8):
    v = struct.unpack_from('<Q', data, off)[0]
    marker = ' <<< FLASH_TOKEN_HANDLER PTR' if off == 0x68458 else ''
    # If v looks like string ptr in .text range, show string too
    strval = ''
    if 0x1000 <= v < 0x6a000:
        # Check if it's a printable string
        s = data[v:v+40]
        null_pos = s.find(b'\x00')
        if null_pos >= 0:
            s = s[:null_pos]
        if all(0x20 <= b < 0x7f for b in s) and len(s) > 0:
            strval = f' -> "{s.decode()}"'
        else:
            strval = f' -> (code at disasm 0x{v-0x1000:x})'
    elif v == 0:
        pass
    print(f'  file 0x{off:x}: 0x{v:x}{strval}{marker}')
