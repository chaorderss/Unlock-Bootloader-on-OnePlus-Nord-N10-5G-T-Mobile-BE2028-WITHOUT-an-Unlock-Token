#!/usr/bin/env python3
import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin','rb').read()

# Find ADRP instructions that reference page 0x63000 (command table page)
page_target = 0x63000
results = []
for off in range(0x1000, 0x69000, 4):
    insn = struct.unpack_from('<I', data, off)[0]
    if (insn & 0x9f000000) == 0x90000000:  # ADRP
        rd = insn & 0x1f
        imm_lo = (insn >> 29) & 3
        imm_hi = (insn >> 5) & 0x7ffff
        imm = ((imm_hi << 2) | imm_lo) << 12
        if imm & (1 << 32):
            imm -= (1 << 33)
        pc_page = off & ~0xfff
        target_page = (pc_page + imm) & 0xffffffffffff
        if target_page == page_target:
            results.append((off, rd))

print(f'Found {len(results)} ADRP refs to 0x63000 page:')
for off, rd in results:
    print(f'  ADRP x{rd} at 0x{off:x}')
    # Look at next instruction for ADD offset
    if off + 4 < len(data):
        next_insn = struct.unpack_from('<I', data, off+4)[0]
        print(f'    next: 0x{next_insn:08x}')

# Also find where the command table loop is by looking for pattern:
# LDP x?, x? from command table
# or checking functions that iterate through the table
print()
print('=== Looking for the dispatcher/decode function ===')
# Search for the function that calls handlers after matching commands
# The dispatch table pairs are (encoded_str_ptr, handler_ptr)
# Look for: load ptr, decode/compare, call handler
# Find code near the start of the EFI image that calls dispatch
# The handler at e.g. 0x3bcc0 should be called from somewhere after command dispatch

# Let's look at 0x3bcc0 (handler for first encoded command)
print('Handler at 0x3bcc0:')
for i in range(20):
    off = 0x3bcc0 + i*4
    insn = struct.unpack_from('<I', data, off)[0]
    # Decode BL target
    if (insn & 0xfc000000) == 0x94000000:
        imm = (insn & 0x3ffffff)
        if imm & (1<<25): imm -= (1<<26)
        target = (off + imm*4) & 0xffffffff
        print(f'  0x{off:x}: bl 0x{target:x}')
    elif insn == 0xd65f03c0:
        print(f'  0x{off:x}: ret')
        break
    elif insn == 0x00000000:
        break
    else:
        print(f'  0x{off:x}: 0x{insn:08x}')
